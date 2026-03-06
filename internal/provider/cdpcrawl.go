package provider

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/badchars/recon0/internal/cdp"
	"github.com/badchars/recon0/internal/config"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/network"
)

type CDPCrawl struct{}

func (c *CDPCrawl) Name() string       { return "cdpcrawl" }
func (c *CDPCrawl) Stage() string      { return "crawl" }
func (c *CDPCrawl) OutputType() string { return "urls" }
func (c *CDPCrawl) Check() error       { return nil } // built-in

func (c *CDPCrawl) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config
	harDir := filepath.Join(opts.WorkDir, "har")
	jsDir := filepath.Join(opts.WorkDir, "js")
	os.MkdirAll(harDir, 0755)
	os.MkdirAll(jsDir, 0755)

	// Read live hosts
	hosts := readLines(opts.Input)
	if len(hosts) == 0 {
		return &Result{Count: 0, OutputFile: opts.Output}, nil
	}

	// Config
	headless := config.GetBool(extra, "headless", true)
	timeoutPerPage := config.GetDuration(extra, "timeout_per_page", 30*time.Second)
	clickDepth := config.GetInt(extra, "click_depth", 2)
	maxConcurrent := config.GetInt(extra, "max_concurrent_tabs", opts.Res.ThreadsCDP)
	userAgent := config.GetString(extra, "user_agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	viewportW := config.GetInt(extra, "viewport_width", 1920)
	viewportH := config.GetInt(extra, "viewport_height", 1080)

	if maxConcurrent <= 0 {
		maxConcurrent = 5
	}

	// Launch browser pool
	pool, err := cdp.NewBrowserPool(ctx, cdp.BrowserOpts{
		Headless:       headless,
		MaxConcurrency: maxConcurrent,
		UserAgent:      userAgent,
		ViewportWidth:  viewportW,
		ViewportHeight: viewportH,
	})
	if err != nil {
		return nil, fmt.Errorf("cdpcrawl: failed to start Chrome: %w", err)
	}
	defer pool.Close()

	// Output file for discovered URLs (written incrementally for progress monitor)
	os.MkdirAll(filepath.Dir(opts.Output), 0755)
	outFile, err := os.Create(opts.Output)
	if err != nil {
		return nil, fmt.Errorf("cdpcrawl: create output: %w", err)
	}
	defer outFile.Close()
	outWriter := bufio.NewWriter(outFile)

	var (
		mu          sync.Mutex
		totalURLs   int
		totalHARs   int
		totalJS     int
		seenJSHash  = make(map[string]bool)
		jsManifest  = make(map[string]string) // filename → original URL
	)

	// Process hosts concurrently
	var wg sync.WaitGroup
	for _, hostURL := range hosts {
		if ctx.Err() != nil {
			break
		}

		hostURL = strings.TrimSpace(hostURL)
		if hostURL == "" {
			continue
		}

		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			// Acquire browser context (blocks if at capacity)
			tabCtx, release, err := pool.AcquireContext(ctx)
			if err != nil {
				return
			}
			defer release()

			// Set page timeout
			tabCtx, cancel := context.WithTimeout(tabCtx, timeoutPerPage+time.Duration(clickDepth)*40*time.Second)
			defer cancel()

			// Create HAR builder and attach network listeners
			harBuilder := cdp.NewHARBuilder()

			chromedp.ListenTarget(tabCtx, func(ev interface{}) {
				switch e := ev.(type) {
				case *network.EventRequestWillBeSent:
					harBuilder.OnRequestWillBeSent(e)
				case *network.EventResponseReceived:
					harBuilder.OnResponseReceived(e)
				case *network.EventLoadingFailed:
					harBuilder.OnLoadingFailed(e)
				}
			})

			// Enable network monitoring and navigate
			err = chromedp.Run(tabCtx,
				network.Enable(),
				chromedp.Navigate(targetURL),
				chromedp.WaitReady("body", chromedp.ByQuery),
			)
			if err != nil {
				return // page failed to load
			}

			// Wait for network to settle
			chromedp.Run(tabCtx, chromedp.Sleep(3*time.Second))

			// Collect JS URLs discovered during click interactions
			var extraJSURLs []string
			var jsMu sync.Mutex
			onJSFound := func(srcs []string) {
				jsMu.Lock()
				extraJSURLs = append(extraJSURLs, srcs...)
				jsMu.Unlock()
			}

			// Interact with page (click-back pattern: click → collect JS → back → next)
			if clickDepth > 0 {
				domain := extractDomain(targetURL)
				cdp.InteractWithPage(tabCtx, domain, cdp.InteractionOpts{
					ClickDepth:     clickDepth,
					MaxClicks:      20,
					WaitAfterClick: 3 * time.Second,
				}, onJSFound)
			}

			// JS URLs from interaction callback
			scriptSrcs := extraJSURLs

			// Get hostname for HAR filename
			hostname := extractHostname(targetURL)

			// Write HAR file
			if harBuilder.EntryCount() > 0 {
				harPath := filepath.Join(harDir, hostname+".har")
				harBuilder.WriteToFile(harPath)
				mu.Lock()
				totalHARs++
				mu.Unlock()
			}

			// Collect all URLs from HAR
			harURLs := harBuilder.URLs()

			// Write URLs to output file
			mu.Lock()
			for _, u := range harURLs {
				fmt.Fprintln(outWriter, u)
				totalURLs++
			}
			outWriter.Flush()
			mu.Unlock()

			// Download JS files (from HAR + script tags)
			jsURLs := harBuilder.JSURLs()
			allJSURLs := mergeStringSlices(jsURLs, scriptSrcs)

			for _, jsURL := range allJSURLs {
				if ctx.Err() != nil {
					break
				}
				filename := downloadJS(ctx, jsURL, jsDir, &mu, seenJSHash)
				if filename != "" {
					mu.Lock()
					totalJS++
					jsManifest[filename] = jsURL
					mu.Unlock()
				}
			}
		}(hostURL)
	}

	wg.Wait()
	outWriter.Flush()

	// Write JS manifest (filename → original URL mapping)
	if len(jsManifest) > 0 {
		manifestPath := filepath.Join(jsDir, "_manifest.json")
		manifestData, _ := json.MarshalIndent(jsManifest, "", "  ")
		os.WriteFile(manifestPath, manifestData, 0644)
	}

	return &Result{
		Count:      totalURLs,
		OutputFile: opts.Output,
		Extra: map[string]any{
			"har_files":    totalHARs,
			"js_files":     totalJS,
			"hosts_crawled": len(hosts),
		},
	}, nil
}

// downloadJS downloads a JS file, deduplicates by SHA256 hash. Returns filename if downloaded.
func downloadJS(ctx context.Context, jsURL, jsDir string, mu *sync.Mutex, seenHash map[string]bool) string {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon0/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	// Reject HTML (custom 404 pages)
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil || len(body) < 20 {
		return ""
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	filename := hash[:12] + "_" + safeFilename(jsURL)

	mu.Lock()
	if seenHash[hash] {
		mu.Unlock()
		// Already downloaded but still return filename for manifest mapping
		return filename
	}
	seenHash[hash] = true
	mu.Unlock()

	outPath := filepath.Join(jsDir, filename)
	if err := os.WriteFile(outPath, body, 0644); err != nil {
		return ""
	}

	return filename
}

func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

func extractHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unknown"
	}
	host := u.Hostname()
	if u.Port() != "" && u.Port() != "80" && u.Port() != "443" {
		host += "_" + u.Port()
	}
	return host
}

func safeFilename(rawURL string) string {
	path := rawURL
	if idx := strings.Index(path, "?"); idx > 0 {
		path = path[:idx]
	}
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		path = path[idx+1:]
	}
	path = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, path)
	if len(path) > 100 {
		path = path[:100]
	}
	if path == "" {
		path = "unknown.js"
	}
	return path
}

func mergeStringSlices(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var result []string
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}


func init() { Register(&CDPCrawl{}) }
