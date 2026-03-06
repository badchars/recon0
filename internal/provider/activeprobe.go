package provider

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/badchars/recon0/internal/config"
)

type ActiveProbe struct{}

func (a *ActiveProbe) Name() string       { return "activeprobe" }
func (a *ActiveProbe) Stage() string      { return "vuln" }
func (a *ActiveProbe) OutputType() string { return "findings" }
func (a *ActiveProbe) Check() error       { return nil }

// activeProbeFinding matches nuclei JSON output format for merge compatibility.
type activeProbeFinding struct {
	TemplateID  string `json:"template-id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Host        string `json:"host"`
	MatchedAt   string `json:"matched-at"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
}

// hostTarget holds parsed httpx data for a single host.
type hostTarget struct {
	URL    string
	Host   string
	Tech   []string
	Server string
}

func (a *ActiveProbe) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config

	timeout := config.GetDuration(extra, "timeout", 10*time.Second)
	maxConcurrent := config.GetInt(extra, "max_concurrent", 20)
	skipGeneric := config.GetBool(extra, "skip_generic", false)
	skipCORS := config.GetBool(extra, "skip_cors", false)

	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}

	// Parse httpx JSON for tech fingerprints
	httpxPath := filepath.Join(opts.WorkDir, "raw", "httpx.hosts.txt.json")
	targets := parseHTTPxTargets(httpxPath)
	if len(targets) == 0 {
		return &Result{Count: 0, OutputFile: opts.Output}, nil
	}

	// Enrich tech from HAR headers/cookies (httpx misses backend tech)
	harDir := filepath.Join(opts.WorkDir, "har")
	enrichTechFromHAR(harDir, targets)

	// Load probe sets
	allSets := AllProbeSets()

	// Prepare output file
	os.MkdirAll(filepath.Dir(opts.Output), 0755)
	outFile, err := os.Create(opts.Output)
	if err != nil {
		return nil, fmt.Errorf("activeprobe: create output: %w", err)
	}
	defer outFile.Close()

	var (
		mu        sync.Mutex
		writer    = bufio.NewWriter(outFile)
		total     int
		probeSent int
	)

	emit := func(f activeProbeFinding) {
		mu.Lock()
		data, _ := json.Marshal(f)
		fmt.Fprintln(writer, string(data))
		total++
		mu.Unlock()
	}

	// HTTP client: no redirects, skip TLS verify
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost: 10,
			MaxIdleConns:        100,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Worker pool
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}

		// Select probes for this host based on tech fingerprints
		probes := selectProbes(allSets, target, skipGeneric)
		if len(probes) == 0 {
			continue
		}

		// Cap probes per host
		if len(probes) > 50 {
			probes = probes[:50]
		}

		for _, probe := range probes {
			if ctx.Err() != nil {
				break
			}

			wg.Add(1)
			sem <- struct{}{} // acquire

			go func(t hostTarget, p Probe) {
				defer wg.Done()
				defer func() { <-sem }() // release

				mu.Lock()
				probeSent++
				mu.Unlock()

				finding := executeProbe(ctx, client, t, p)
				if finding != nil {
					emit(*finding)
				}
			}(target, probe)
		}

		// CORS probe
		if !skipCORS {
			wg.Add(1)
			sem <- struct{}{}

			go func(t hostTarget) {
				defer wg.Done()
				defer func() { <-sem }()

				mu.Lock()
				probeSent++
				mu.Unlock()

				finding := probeCORS(ctx, client, t)
				if finding != nil {
					emit(*finding)
				}
			}(target)
		}
	}

	wg.Wait()

	mu.Lock()
	writer.Flush()
	mu.Unlock()

	return &Result{
		Count:      total,
		OutputFile: opts.Output,
		Extra: map[string]any{
			"hosts_probed": len(targets),
			"probes_sent":  probeSent,
			"findings":     total,
		},
	}, nil
}

// parseHTTPxTargets reads httpx JSON Lines and extracts host info.
func parseHTTPxTargets(path string) []hostTarget {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var targets []hostTarget

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var entry struct {
			URL    string   `json:"url"`
			Host   string   `json:"host"`
			Tech   []string `json:"tech"`
			Server string   `json:"server"`
		}
		if json.Unmarshal(scanner.Bytes(), &entry) != nil || entry.URL == "" {
			continue
		}

		// Deduplicate by URL (httpx may have multiple entries per host for different ports)
		if seen[entry.URL] {
			continue
		}
		seen[entry.URL] = true

		targets = append(targets, hostTarget{
			URL:    entry.URL,
			Host:   entry.Host,
			Tech:   entry.Tech,
			Server: entry.Server,
		})
	}

	return targets
}

// selectProbes returns matching probes for a host based on its tech fingerprints.
func selectProbes(allSets []ProbeSet, target hostTarget, skipGeneric bool) []Probe {
	var probes []Probe

	for _, set := range allSets {
		// Generic set: TechMatch is nil
		if set.TechMatch == nil {
			if !skipGeneric {
				probes = append(probes, set.Probes...)
			}
			continue
		}

		// Check if any tech matches
		if matchesTech(target, set.TechMatch) {
			probes = append(probes, set.Probes...)
		}
	}

	return probes
}

// matchesTech checks if target's tech stack or server header matches any of the patterns.
func matchesTech(target hostTarget, patterns []string) bool {
	for _, pattern := range patterns {
		lower := strings.ToLower(pattern)

		// Check httpx tech array
		for _, tech := range target.Tech {
			if strings.Contains(strings.ToLower(tech), lower) {
				return true
			}
		}

		// Check server header (e.g. "Go-http-server/1.1" for Go detection)
		if target.Server != "" && strings.Contains(strings.ToLower(target.Server), lower) {
			return true
		}
	}
	return false
}

// executeProbe sends an HTTP request and evaluates the response.
func executeProbe(ctx context.Context, client *http.Client, target hostTarget, probe Probe) *activeProbeFinding {
	// Build URL
	probeURL := strings.TrimRight(target.URL, "/") + probe.Path

	method := probe.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if probe.Body != "" {
		bodyReader = strings.NewReader(probe.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, probeURL, bodyReader)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon0-probe/1.0)")
	for k, v := range probe.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read body (max 1MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}

	// Check status code
	statusMatch := false
	if len(probe.ExpectStatus) == 0 {
		statusMatch = resp.StatusCode == 200
	} else {
		for _, s := range probe.ExpectStatus {
			if resp.StatusCode == s {
				statusMatch = true
				break
			}
		}
	}
	if !statusMatch {
		return nil
	}

	bodyStr := string(body)

	// Special case: heapdump/pprof heap — check Content-Length for large binary
	if probe.RuleID == "spring-actuator-heapdump" || probe.RuleID == "go-pprof-heap" {
		if resp.ContentLength > 1024*1024 || len(body) > 1024*100 {
			return &activeProbeFinding{
				TemplateID:  probe.RuleID,
				Name:        probe.RuleName,
				Severity:    probe.Severity,
				Host:        target.URL,
				MatchedAt:   probeURL,
				Type:        "http",
				Description: probe.Description,
				Evidence:    fmt.Sprintf("Content-Length: %d bytes", resp.ContentLength),
			}
		}
		return nil
	}

	// Special case: pprof cmdline — any non-empty non-HTML response
	if probe.RuleID == "go-pprof-cmdline" {
		if len(body) > 0 && !strings.Contains(bodyStr, "<html") && !strings.Contains(bodyStr, "<HTML") {
			evidence := bodyStr
			if len(evidence) > 500 {
				evidence = evidence[:500]
			}
			return &activeProbeFinding{
				TemplateID:  probe.RuleID,
				Name:        probe.RuleName,
				Severity:    probe.Severity,
				Host:        target.URL,
				MatchedAt:   probeURL,
				Type:        "http",
				Description: probe.Description,
				Evidence:    evidence,
			}
		}
		return nil
	}

	// Reject body filter (false positive detection)
	for _, reject := range probe.RejectBody {
		if strings.Contains(bodyStr, reject) {
			return nil
		}
	}

	// Generic HTML 404 page filter
	if isGeneric404Page(bodyStr) && !containsExpectedBody(bodyStr, probe.ExpectBody) {
		return nil
	}

	// Expect body match
	if len(probe.ExpectBody) > 0 {
		if !containsExpectedBody(bodyStr, probe.ExpectBody) {
			return nil
		}
	} else if len(body) == 0 {
		// No body expectations and empty response
		return nil
	}

	// Build evidence (first 500 chars)
	evidence := bodyStr
	if len(evidence) > 500 {
		evidence = evidence[:500]
	}

	return &activeProbeFinding{
		TemplateID:  probe.RuleID,
		Name:        probe.RuleName,
		Severity:    probe.Severity,
		Host:        target.URL,
		MatchedAt:   probeURL,
		Type:        "http",
		Description: probe.Description,
		Evidence:    evidence,
	}
}

func containsExpectedBody(body string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

func isGeneric404Page(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<title>404") ||
		strings.Contains(lower, "page not found") ||
		strings.Contains(lower, "not found</") ||
		strings.Contains(lower, "404 not found")
}

// probeCORS checks for CORS misconfiguration.
func probeCORS(ctx context.Context, client *http.Client, target hostTarget) *activeProbeFinding {
	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon0-probe/1.0)")
	req.Header.Set("Origin", "https://evil.recon0.test")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "" {
		return nil
	}

	// Check if origin is reflected or wildcard
	if acao == "https://evil.recon0.test" {
		severity := "medium"
		desc := "CORS allows arbitrary origin reflection"
		if strings.EqualFold(acac, "true") {
			severity = "high"
			desc = "CORS allows arbitrary origin reflection WITH credentials — cookie theft possible"
		}
		return &activeProbeFinding{
			TemplateID:  "cors-origin-reflection",
			Name:        "CORS Origin Reflection",
			Severity:    severity,
			Host:        target.URL,
			MatchedAt:   target.URL,
			Type:        "http",
			Description: desc,
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s", acao, acac),
		}
	}

	if acao == "*" && strings.EqualFold(acac, "true") {
		return &activeProbeFinding{
			TemplateID:  "cors-wildcard-credentials",
			Name:        "CORS Wildcard with Credentials",
			Severity:    "medium",
			Host:        target.URL,
			MatchedAt:   target.URL,
			Type:        "http",
			Description: "CORS allows wildcard origin with credentials header",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: %s", acac),
		}
	}

	return nil
}

// ── HAR-based Tech Enrichment ──

// headerTechRule maps HTTP header patterns to tech names.
type headerTechRule struct {
	Header   string // header name (lowercase)
	Contains string // value substring match (lowercase)
	Tech     string // tech name to add
}

// cookieTechRule maps cookie names to tech.
type cookieTechRule struct {
	Cookie string // cookie name (case-insensitive)
	Tech   string
}

var headerTechRules = []headerTechRule{
	// Server header
	{"server", "go-http-server", "Go"},
	{"server", "gunicorn", "Python"},
	{"server", "uvicorn", "Python"},
	{"server", "daphne", "Django"},
	{"server", "werkzeug", "Flask"},
	{"server", "webrick", "Ruby"},
	{"server", "puma", "Ruby"},
	{"server", "unicorn", "Ruby"},
	{"server", "passenger", "Ruby"},
	{"server", "thin", "Ruby"},
	{"server", "kestrel", ".NET"},
	{"server", "microsoft-iis", "IIS"},
	{"server", "microsoft-httpapi", ".NET"},
	{"server", "apache-coyote", "Java"},
	{"server", "tomcat", "Java"},
	{"server", "jetty", "Java"},
	{"server", "wildfly", "Java"},
	{"server", "glassfish", "Java"},
	{"server", "openresty", "Nginx"},
	{"server", "envoy", "Envoy"},
	{"server", "istio-envoy", "Envoy"},
	{"server", "caddy", "Caddy"},
	{"server", "tornado", "Python"},

	// X-Powered-By
	{"x-powered-by", "express", "Express"},
	{"x-powered-by", "php", "PHP"},
	{"x-powered-by", "asp.net", "ASP.NET"},
	{"x-powered-by", "servlet", "Java"},
	{"x-powered-by", "jsp", "Java"},
	{"x-powered-by", "next.js", "Next.js"},
	{"x-powered-by", "nuxt", "Nuxt"},
	{"x-powered-by", "django", "Django"},
	{"x-powered-by", "flask", "Flask"},
	{"x-powered-by", "rails", "Ruby"},
	{"x-powered-by", "phusion passenger", "Ruby"},

	// X-Runtime → Ruby/Rails
	{"x-runtime", "", "Ruby"},

	// X-AspNet-Version → ASP.NET
	{"x-aspnet-version", "", "ASP.NET"},
	{"x-aspnetmvc-version", "", "ASP.NET"},

	// X-Generator
	{"x-generator", "drupal", "Drupal"},
	{"x-generator", "wordpress", "WordPress"},
	{"x-generator", "joomla", "Joomla"},

	// X-Turbo-Charged-By → LiteSpeed
	{"x-turbo-charged-by", "litespeed", "LiteSpeed"},

	// X-Debug-Token → Symfony
	{"x-debug-token", "", "Symfony"},
}

var cookieTechRules = []cookieTechRule{
	{"JSESSIONID", "Java"},
	{"PHPSESSID", "PHP"},
	{"laravel_session", "Laravel"},
	{"ASP.NET_SessionId", "ASP.NET"},
	{"ASPXAUTH", "ASP.NET"},
	{"connect.sid", "Express"},
	{"_csrf", "Ruby"},
	{"rack.session", "Ruby"},
	{"ci_session", "PHP"},     // CodeIgniter
	{"PLAY_SESSION", "Java"},  // Play Framework
	{"csrftoken", "Django"},
	{"sessionid", "Django"},   // Django default
	{"__cfduid", "Cloudflare"},
}

// enrichTechFromHAR reads HAR files and adds tech info to targets based on
// response headers, server headers, and cookies that httpx's Wappalyzer missed.
func enrichTechFromHAR(harDir string, targets []hostTarget) {
	// Build hostname → target index map
	hostIdx := make(map[string]int, len(targets))
	for i, t := range targets {
		hostIdx[t.Host] = i
	}

	harFiles, _ := filepath.Glob(filepath.Join(harDir, "*.har"))
	for _, harFile := range harFiles {
		enrichFromSingleHAR(harFile, targets, hostIdx)
	}
}

func enrichFromSingleHAR(harFile string, targets []hostTarget, hostIdx map[string]int) {
	f, err := os.Open(harFile)
	if err != nil {
		return
	}
	defer f.Close()

	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
				Response struct {
					Headers []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
					Cookies []struct {
						Name string `json:"name"`
					} `json:"cookies"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}

	data, err := io.ReadAll(io.LimitReader(f, 50*1024*1024))
	if err != nil {
		return
	}
	if json.Unmarshal(data, &har) != nil {
		return
	}

	for _, entry := range har.Log.Entries {
		// Extract hostname from request URL
		host := extractHostFromURL(entry.Request.URL)
		if host == "" {
			continue
		}

		idx, ok := hostIdx[host]
		if !ok {
			continue
		}

		// Check headers
		for _, h := range entry.Response.Headers {
			hLower := strings.ToLower(h.Name)
			vLower := strings.ToLower(h.Value)

			for _, rule := range headerTechRules {
				if hLower != rule.Header {
					continue
				}
				if rule.Contains == "" || strings.Contains(vLower, rule.Contains) {
					addTechIfNew(&targets[idx], rule.Tech)
				}
			}
		}

		// Check cookies
		for _, c := range entry.Response.Cookies {
			cLower := strings.ToLower(c.Name)
			for _, rule := range cookieTechRules {
				if cLower == strings.ToLower(rule.Cookie) {
					addTechIfNew(&targets[idx], rule.Tech)
				}
			}
		}
	}
}

func extractHostFromURL(rawURL string) string {
	// Fast hostname extraction without url.Parse
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest := rawURL[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			rest = rest[:slash]
		}
		// Remove port
		if colon := strings.LastIndex(rest, ":"); colon >= 0 {
			rest = rest[:colon]
		}
		return rest
	}
	return ""
}

func addTechIfNew(target *hostTarget, tech string) {
	for _, t := range target.Tech {
		if strings.EqualFold(t, tech) {
			return
		}
	}
	target.Tech = append(target.Tech, tech)
}

func init() { Register(&ActiveProbe{}) }
