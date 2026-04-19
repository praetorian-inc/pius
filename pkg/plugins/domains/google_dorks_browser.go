package domains

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// consentRejectSelector is the CSS selector for Google's "Reject all" consent button.
const consentRejectSelector = `.VtwTSb > form:nth-child(1) > div:nth-child(1) > div:nth-child(1) > button:nth-child(1)`

// initBrowser creates a single Chrome allocator and browser context for reuse across queries.
// The caller must invoke the returned cleanup function when done.
func (p *GoogleDorksPlugin) initBrowser(ctx context.Context) (context.Context, func(), error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-features", "AutomationControlled,EnableAutomationAPI"),
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("excludeSwitches", "enable-automation"),
		chromedp.Flag("disable-extensions", false),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)

	cleanup := func() {
		browserCancel()
		allocCancel()
	}

	// Verify Chrome can launch by navigating to about:blank.
	if err := chromedp.Run(browserCtx, chromedp.Navigate("about:blank")); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("launch chrome: %w", err)
	}

	return browserCtx, cleanup, nil
}

// handleConsent navigates to google.com and attempts to click the consent reject button.
// This is a best-effort operation — if the button is absent, execution continues normally.
func (p *GoogleDorksPlugin) handleConsent(browserCtx context.Context) {
	// Navigate to google.com — may show consent wall.
	if err := chromedp.Run(browserCtx,
		chromedp.Navigate("https://www.google.com/?hl=en&gl=us"),
		chromedp.WaitReady("body"),
	); err != nil {
		slog.Warn("[google-dorks] consent navigation failed", "err", err)
		return
	}

	// Try to click "Reject all" — best effort with a short timeout.
	clickCtx, clickCancel := context.WithTimeout(browserCtx, 5*time.Second)
	defer clickCancel()

	if err := chromedp.Run(clickCtx,
		chromedp.WaitVisible(consentRejectSelector, chromedp.ByQuery),
		chromedp.Click(consentRejectSelector, chromedp.ByQuery),
		chromedp.Sleep(1*time.Second),
	); err != nil {
		// No consent wall or button not found — that's fine, continue.
		slog.Debug("[google-dorks] no consent button found (may not be needed)")
	}
}

// fetchRenderedHTML navigates to searchURL in the shared browser, waits for #search results,
// and returns the raw HTML string. Falls back to a short sleep if #search never appears.
func (p *GoogleDorksPlugin) fetchRenderedHTML(browserCtx context.Context, searchURL string) (string, error) {
	// Per-query timeout.
	queryCtx, queryCancel := context.WithTimeout(browserCtx, 20*time.Second)
	defer queryCancel()

	if err := chromedp.Run(queryCtx, chromedp.Navigate(searchURL)); err != nil {
		return "", fmt.Errorf("navigate: %w", err)
	}

	// Wait for #search results div — fall back to Sleep if it doesn't appear.
	waitCtx, waitCancel := context.WithTimeout(queryCtx, 10*time.Second)
	defer waitCancel()
	if err := chromedp.Run(waitCtx, chromedp.WaitVisible("#search", chromedp.ByID)); err != nil {
		// #search not found — wait a bit and take whatever HTML is available.
		_ = chromedp.Run(queryCtx, chromedp.Sleep(3*time.Second))
	}

	var htmlContent string
	if err := chromedp.Run(queryCtx, chromedp.OuterHTML("html", &htmlContent)); err != nil {
		return "", fmt.Errorf("extract HTML: %w", err)
	}

	// Detect Google CAPTCHA or block page.
	if strings.Contains(htmlContent, "detected unusual traffic") ||
		strings.Contains(htmlContent, "/sorry/index") ||
		strings.Contains(htmlContent, "recaptcha") {
		return "", fmt.Errorf("google captcha/block detected")
	}

	return htmlContent, nil
}

// fetchSimpleHTML does a plain HTTP GET and returns the response body as a string.
// Used for testing and as a fallback path.
func (p *GoogleDorksPlugin) fetchSimpleHTML(ctx context.Context, searchURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; pius/1.0)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("google search: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("google returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	return string(body), nil
}
