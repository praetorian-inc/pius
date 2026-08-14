package domains

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("google-dorks", func() plugins.Plugin {
		return &GoogleDorksPlugin{
			renderEnabled: true,
		}
	})
}

// NewGoogleDorksPlugin builds the plugin with production rendering enabled. There
// is no client seam: the plugin drives a headless browser (chromedp) for the
// carousel render path and falls back to package-level http.DefaultClient
// otherwise, so egress here does not route through a caller-supplied transport.
func NewGoogleDorksPlugin() *GoogleDorksPlugin {
	return &GoogleDorksPlugin{renderEnabled: true}
}

// GoogleDorksPlugin discovers subsidiaries via Google Knowledge Graph carousel.
//
// Strategy:
//  1. Build a single query "subsidiaries:{name}" and fetch Google search results
//  2. Extract subsidiary company names from carousel elements with data-entityname attributes
//  3. For each subsidiary name, do another Google search and extract the first valid domain
//  4. Emit those domains as FindingDomain findings
//
// Phase 0 (independent): requires only Domain.
// Confidence ~55: between ConfidenceLow and ConfidenceHigh — marks findings needs_review.
type GoogleDorksPlugin struct {
	baseURL       string        // override for testing; default "https://www.google.com"
	renderEnabled bool          // false for testing, true for production
	queryDelay    time.Duration // delay between subsidiary lookups; 0 uses random 1-3s
}

// The two evidence entries sum to googleDorksConfidence, which sits between
// ConfidenceLow and ConfidenceHigh — so every finding here needs review.
const (
	// confGoogleDorksSubsidiary credits the Knowledge Graph naming the company
	// as a subsidiary of the target.
	confGoogleDorksSubsidiary = 30
	// confGoogleDorksDomain credits the follow-up search resolving that
	// subsidiary name to the emitted domain.
	confGoogleDorksDomain = 25

	googleDorksConfidence = confGoogleDorksSubsidiary + confGoogleDorksDomain
)

// maxSubsidiaries caps the number of carousel subsidiaries we resolve per run.
const maxSubsidiaries = 30

func (p *GoogleDorksPlugin) Name() string { return "google-dorks" }
func (p *GoogleDorksPlugin) Description() string {
	return "Google Dorks: discovers subsidiaries via Google Knowledge Graph carousel"
}
func (p *GoogleDorksPlugin) Category() string { return "domain" }
func (p *GoogleDorksPlugin) Phase() int       { return 0 }
func (p *GoogleDorksPlugin) Mode() string     { return plugins.ModePassive }

func (p *GoogleDorksPlugin) Accepts(input plugins.Input) bool {
	return isDomainName(input.Domain) || input.OrgName != ""
}

func (p *GoogleDorksPlugin) googleBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://www.google.com"
}

// makeFinding constructs a FindingDomain finding for a discovered subsidiary domain.
//
// The two evidence entries are independent: the Knowledge Graph naming a
// subsidiary is one observation, and a follow-up search resolving that
// subsidiary to a domain is another. Either can be right while the other is
// wrong, so they are scored and justified separately.
func (p *GoogleDorksPlugin) makeFinding(subsidiaryName, domainValue, inputDomain, discoveryURL, resolveURL string) plugins.Finding {
	f := plugins.Finding{
		Type:   plugins.FindingDomain,
		Value:  domainValue,
		Source: p.Name(),
		Data: map[string]any{
			"subsidiary": subsidiaryName,
			"domain":     inputDomain,
		},
	}
	plugins.AddConfidence(&f, confGoogleDorksSubsidiary,
		fmt.Sprintf("Google Knowledge Graph identifies %q as a subsidiary of the target", subsidiaryName),
		plugins.Reference{Label: "Subsidiary search results", URL: discoveryURL})
	plugins.AddConfidence(&f, confGoogleDorksDomain,
		fmt.Sprintf("A search for subsidiary %q resolves to the domain %q", subsidiaryName, domainValue),
		plugins.Reference{Label: "Domain search results", URL: resolveURL})
	return f
}

// Run discovers subsidiaries of the input domain via the Google Knowledge Graph carousel.
func (p *GoogleDorksPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	if input.Domain == "" && input.OrgName == "" {
		return nil, nil
	}

	var fetch func(string) (string, error)
	var cleanup func()

	if p.renderEnabled {
		browserCtx, cleanupFn, err := p.initBrowser(ctx)
		if err != nil {
			slog.Warn("[google-dorks] browser unavailable, falling back to HTTP", "err", err)
			cleanup = func() {}
			fetch = func(u string) (string, error) { return p.fetchSimpleHTML(ctx, u) }
		} else {
			cleanup = cleanupFn
			p.handleConsent(browserCtx)
			fetch = func(u string) (string, error) { return p.fetchRenderedHTML(browserCtx, u) }
		}
	} else {
		cleanup = func() {}
		fetch = func(u string) (string, error) { return p.fetchSimpleHTML(ctx, u) }
	}
	defer cleanup()

	// Step 1: Get carousel of subsidiary names.
	query := p.buildQuery(input)
	searchURL := fmt.Sprintf("%s/search?q=%s&hl=en&gl=us", p.googleBase(), url.QueryEscape(query))
	html, err := fetch(searchURL)
	if err != nil {
		slog.Warn("[google-dorks] carousel search failed", "query", query, "err", err)
		return nil, nil
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		slog.Warn("[google-dorks] carousel HTML parse failed", "err", err)
		return nil, nil
	}

	names := extractCarouselNames(doc.Selection)

	maxSubs := maxSubsidiaries
	if v, ok := input.Meta["google_dorks_max_subsidiaries"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxSubs = n
		}
	}

	if len(names) > maxSubs {
		names = names[:maxSubs]
	}

	// Step 2: Resolve each subsidiary name to a domain.
	seen := make(map[string]bool)
	var findings []plugins.Finding

	inputDomainLower := strings.ToLower(input.Domain)

	for _, name := range names {
		if ctx.Err() != nil {
			break
		}

		// Delay between queries to avoid rate limiting.
		delay := p.queryDelay
		if delay == 0 {
			delay = time.Duration(1000+rand.IntN(2000)) * time.Millisecond
		}
		t := time.NewTimer(delay)
		select {
		case <-t.C:
		case <-ctx.Done():
			if !t.Stop() {
				<-t.C
			}
		}
		if ctx.Err() != nil {
			break
		}

		resolveURL := fmt.Sprintf("%s/search?q=%s&num=5&hl=en&gl=us", p.googleBase(), url.QueryEscape(name))
		rHTML, err := fetch(resolveURL)
		if err != nil {
			slog.Warn("[google-dorks] subsidiary resolve failed", "subsidiary", name, "err", err)
			continue
		}

		rDoc, err := goquery.NewDocumentFromReader(strings.NewReader(rHTML))
		if err != nil {
			continue
		}

		// Prefer the Knowledge Panel official website link.
		if d := extractOfficialDomain(rDoc.Selection); d != "" {
			if !seen[d] && !matchesInputDomain(d, inputDomainLower) && !isExcludedDomain(d) {
				seen[d] = true
				findings = append(findings, p.makeFinding(name, d, input.Domain, searchURL, resolveURL))
				continue // next subsidiary
			}
		}

		// Fall back to first organic result domain.
		domains := extractDomainsFromSelection(rDoc.Selection)
		for _, d := range domains {
			d = strings.ToLower(d)
			if seen[d] || matchesInputDomain(d, inputDomainLower) || isExcludedDomain(d) {
				continue
			}
			seen[d] = true
			findings = append(findings, p.makeFinding(name, d, input.Domain, searchURL, resolveURL))
			break // one domain per subsidiary
		}
	}

	return findings, nil
}

// buildQuery returns a single subsidiary discovery query for the input.
func (p *GoogleDorksPlugin) buildQuery(input plugins.Input) string {
	name := input.OrgName
	if name == "" {
		parts := strings.Split(input.Domain, ".")
		if len(parts) >= 2 {
			name = parts[len(parts)-2] // second-level label
		} else {
			name = parts[0]
		}
	}
	return "subsidiaries:" + name
}
