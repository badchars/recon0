package cdp

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// InteractionOpts configures page interaction behavior.
type InteractionOpts struct {
	ClickDepth     int           // how many rounds of click-back exploration (default: 1)
	MaxClicks      int           // max clicks per round (default: 20)
	WaitAfterClick time.Duration // wait for network after each click (default: 3s)
}

// InteractWithPage clicks interactive elements one-by-one, collecting JS from each
// navigated page, then navigates back to continue exploring other elements.
// onJSFound is called with newly discovered <script src> URLs after each click.
func InteractWithPage(ctx context.Context, targetDomain string, opts InteractionOpts, onJSFound func([]string)) error {
	if opts.ClickDepth <= 0 {
		opts.ClickDepth = 1
	}
	if opts.MaxClicks <= 0 {
		opts.MaxClicks = 20
	}
	if opts.WaitAfterClick <= 0 {
		opts.WaitAfterClick = 3 * time.Second
	}

	// Collect script srcs already present on the initial page
	if onJSFound != nil {
		if srcs := collectScriptSrcs(ctx); len(srcs) > 0 {
			onJSFound(srcs)
		}
	}

	for round := 0; round < opts.ClickDepth; round++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Remember current URL so we can detect navigation
		var currentURL string
		chromedp.Run(ctx, chromedp.Location(&currentURL))

		// Get all clickable element hrefs
		var hrefs []string
		err := chromedp.Run(ctx,
			chromedp.Evaluate(`
				(() => {
					const results = [];
					const seen = new Set();
					const clickable = document.querySelectorAll('a[href], button, [role="button"], input[type="submit"], [onclick]');
					for (const el of clickable) {
						if (el.offsetParent === null) continue;
						const rect = el.getBoundingClientRect();
						if (rect.width === 0 || rect.height === 0) continue;

						const href = el.getAttribute('href') || '';
						const text = (el.textContent || '').trim().toLowerCase();

						const dangerous = ['logout', 'signout', 'sign-out', 'log-out', 'delete', 'remove', 'unsubscribe', 'deactivate'];
						if (dangerous.some(d => text.includes(d) || href.includes(d))) continue;

						if (href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) continue;
						if (href === '#' || href === '') continue;

						if (seen.has(href)) continue;
						seen.add(href);

						if (href) results.push(href);
					}
					return results.slice(0, `+strconv.Itoa(opts.MaxClicks)+`);
				})()
			`, &hrefs),
		)
		if err != nil || len(hrefs) == 0 {
			break
		}

		clickCount := 0
		for _, href := range hrefs {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			// Skip external links
			if strings.HasPrefix(href, "http") && !strings.Contains(href, targetDomain) {
				continue
			}

			// Remember URL before click
			var beforeURL string
			chromedp.Run(ctx, chromedp.Location(&beforeURL))

			// Click the link
			err := chromedp.Run(ctx,
				chromedp.Click(`a[href="`+escapeSelector(href)+`"]`, chromedp.NodeVisible),
			)
			if err != nil {
				continue
			}

			clickCount++

			// Wait for network to settle (new JS bundles may load)
			chromedp.Run(ctx, chromedp.Sleep(opts.WaitAfterClick))

			// Collect any new <script src> URLs on this page
			if onJSFound != nil {
				if srcs := collectScriptSrcs(ctx); len(srcs) > 0 {
					onJSFound(srcs)
				}
			}

			// Check if URL changed (navigation happened)
			var afterURL string
			chromedp.Run(ctx, chromedp.Location(&afterURL))

			if afterURL != beforeURL {
				// Navigate back to original page
				chromedp.Run(ctx,
					chromedp.NavigateBack(),
					chromedp.Sleep(2*time.Second),
				)

				// Wait for page to restore
				chromedp.Run(ctx, chromedp.WaitReady("body", chromedp.ByQuery))
			}
		}

		if clickCount == 0 {
			break
		}

		// Scroll to trigger lazy loading
		chromedp.Run(ctx,
			chromedp.Evaluate(`window.scrollTo(0, document.body.scrollHeight)`, nil),
			chromedp.Sleep(1*time.Second),
		)

		// Collect any JS loaded by scrolling
		if onJSFound != nil {
			if srcs := collectScriptSrcs(ctx); len(srcs) > 0 {
				onJSFound(srcs)
			}
		}
	}

	return nil
}

// collectScriptSrcs extracts all <script src="..."> URLs from the current page.
func collectScriptSrcs(ctx context.Context) []string {
	var srcs []string
	chromedp.Run(ctx,
		chromedp.Evaluate(`
			Array.from(document.querySelectorAll('script[src]'))
				.map(s => s.src)
				.filter(s => s.startsWith('http'))
		`, &srcs),
	)
	return srcs
}

func escapeSelector(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
