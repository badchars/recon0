package cdp

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"sync"

	"github.com/chromedp/chromedp"
)

// BrowserOpts configures the Chrome browser pool.
type BrowserOpts struct {
	Headless       bool
	MaxConcurrency int
	UserAgent      string
	ViewportWidth  int
	ViewportHeight int
	ChromePath     string // auto-detect if empty
}

// BrowserPool manages a single Chrome process with multiple browser contexts.
type BrowserPool struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	sem         chan struct{}
	mu          sync.Mutex
	opts        BrowserOpts
}

// NewBrowserPool launches Chrome and creates a pool of concurrent contexts.
func NewBrowserPool(parentCtx context.Context, opts BrowserOpts) (*BrowserPool, error) {
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 5
	}
	if opts.ViewportWidth <= 0 {
		opts.ViewportWidth = 1920
	}
	if opts.ViewportHeight <= 0 {
		opts.ViewportHeight = 1080
	}
	if opts.ChromePath == "" {
		opts.ChromePath = findChrome()
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", opts.Headless),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("no-first-run", true),
		chromedp.WindowSize(opts.ViewportWidth, opts.ViewportHeight),
	)

	if opts.UserAgent != "" {
		allocOpts = append(allocOpts, chromedp.UserAgent(opts.UserAgent))
	}
	if opts.ChromePath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(opts.ChromePath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(parentCtx, allocOpts...)

	// Create a parent browser context to start Chrome
	browserCtx, _ := chromedp.NewContext(allocCtx)
	// Run a no-op to ensure Chrome starts
	if err := chromedp.Run(browserCtx); err != nil {
		allocCancel()
		return nil, err
	}

	return &BrowserPool{
		allocCtx:    browserCtx,
		allocCancel: allocCancel,
		sem:         make(chan struct{}, opts.MaxConcurrency),
		opts:        opts,
	}, nil
}

// AcquireContext creates a new isolated browser context (tab with separate cookies).
// It blocks if MaxConcurrency is reached. Returns context and a release function.
func (bp *BrowserPool) AcquireContext(parentCtx context.Context) (context.Context, context.CancelFunc, error) {
	select {
	case bp.sem <- struct{}{}:
	case <-parentCtx.Done():
		return nil, nil, parentCtx.Err()
	}

	ctx, cancel := chromedp.NewContext(bp.allocCtx)
	releaseCancel := func() {
		cancel()
		<-bp.sem
	}

	return ctx, releaseCancel, nil
}

// Close shuts down the Chrome process.
func (bp *BrowserPool) Close() {
	bp.allocCancel()
}

// findChrome locates Chrome/Chromium binary on the system.
func findChrome() string {
	// Env override
	if p := os.Getenv("CHROME_PATH"); p != "" {
		return p
	}

	var candidates []string
	switch runtime.GOOS {
	case "linux":
		candidates = []string{
			"/usr/bin/chromium-browser",
			"/usr/bin/chromium",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/google-chrome",
		}
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		}
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	// Fallback: try PATH
	if p, err := exec.LookPath("chromium-browser"); err == nil {
		return p
	}
	if p, err := exec.LookPath("chromium"); err == nil {
		return p
	}
	if p, err := exec.LookPath("google-chrome"); err == nil {
		return p
	}

	return "" // chromedp will use its default detection
}
