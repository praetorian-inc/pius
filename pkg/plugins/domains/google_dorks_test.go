package domains

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGoogleDorksPlugin(baseURL string) *GoogleDorksPlugin {
	return &GoogleDorksPlugin{baseURL: baseURL, renderEnabled: false}
}

// carouselHTML returns HTML with <a data-entityname="Name"> elements for each name provided.
func carouselHTML(names ...string) string {
	var b strings.Builder
	b.WriteString("<html><body><div id=\"search\">")
	for _, name := range names {
		fmt.Fprintf(&b, `<a data-entityname="%s" class="klitem-tr">%s</a>`, name, name)
	}
	b.WriteString("</div></body></html>")
	return b.String()
}

// knowledgePanelHTML returns HTML simulating a Google Knowledge Panel with an official site link.
func knowledgePanelHTML(domain string) string {
	return fmt.Sprintf(`<html><body><div id="search">
		<a data-attrid="visit_official_site" href="https://%s">%s</a>
		<a href="https://noise-site.com">Some other link</a>
	</div></body></html>`, domain, domain)
}

// subsidiaryServer routes requests by the "q" query parameter:
//   - q starts with "subsidiaries:" → carousel HTML with all subsidiary keys
//   - q matches a subsidiary name → knowledgePanelHTML with the mapped domain
//   - otherwise → empty HTML
func subsidiaryServer(subsidiaries map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")

		if strings.HasPrefix(q, "subsidiaries:") {
			// Return carousel with all subsidiary names as keys
			names := make([]string, 0, len(subsidiaries))
			for name := range subsidiaries {
				names = append(names, name)
			}
			_, _ = w.Write([]byte(carouselHTML(names...)))
			return
		}

		// Check if this query matches a subsidiary name
		if domain, ok := subsidiaries[q]; ok {
			_, _ = w.Write([]byte(knowledgePanelHTML(domain)))
			return
		}

		_, _ = w.Write([]byte("<html><body></body></html>"))
	}))
}

// ── Interface tests ───────────────────────────────────────────────────────────

func TestGoogleDorksPlugin_Name(t *testing.T) {
	p := newGoogleDorksPlugin("")
	assert.Equal(t, "google-dorks", p.Name())
}

func TestGoogleDorksPlugin_Accepts(t *testing.T) {
	p := newGoogleDorksPlugin("")
	assert.True(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.True(t, p.Accepts(plugins.Input{Domain: "acme.com", OrgName: "Acme Corp"}))
	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: ""}))
}

func TestGoogleDorksPlugin_Category_Phase_Mode(t *testing.T) {
	p := newGoogleDorksPlugin("")
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, plugins.ModePassive, p.Mode())
	assert.NotEmpty(t, p.Description())
}

// ── Run() tests ───────────────────────────────────────────────────────────────

func TestGoogleDorksPlugin_Run_BothEmpty(t *testing.T) {
	p := newGoogleDorksPlugin("http://should-not-be-called")
	findings, err := p.Run(context.Background(), plugins.Input{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGoogleDorksPlugin_Run_OrgNameOnly(t *testing.T) {
	subsidiaries := map[string]string{
		"SubsidiaryA": "subsidiary-a.com",
	}
	srv := subsidiaryServer(subsidiaries)
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, plugins.FindingDomain, f.Type)
	assert.Equal(t, "subsidiary-a.com", f.Value)
	assert.Equal(t, "google-dorks", f.Source)
	assert.Equal(t, "SubsidiaryA", f.Data["subsidiary"])
	// Domain is empty in preseed mode — that's expected
	assert.Equal(t, "", f.Data["domain"])
}

func TestGoogleDorksPlugin_Run_FindsSubsidiaries(t *testing.T) {
	subsidiaries := map[string]string{
		"SubsidiaryA": "subsidiary-a.com",
		"SubsidiaryB": "subsidiary-b.com",
	}
	srv := subsidiaryServer(subsidiaries)
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "google-dorks", f.Source)
		assert.NotEmpty(t, f.Value)
		assert.InDelta(t, googleDorksConfidence, plugins.Confidence(f), 0.001)
		assert.True(t, plugins.NeedsReview(f))
		// Verify subsidiary name is in finding data
		assert.NotEmpty(t, f.Data["subsidiary"])
	}

	found := make(map[string]bool)
	for _, f := range findings {
		found[f.Value] = true
	}
	assert.True(t, found["subsidiary-a.com"] || found["subsidiary-b.com"],
		"expected at least one subsidiary domain in findings")
}

func TestGoogleDorksPlugin_Run_DeduplicatesDomains(t *testing.T) {
	// Two carousel items that resolve to the same domain
	subsidiaries := map[string]string{
		"SubsidiaryA": "shared-domain.com",
		"SubsidiaryB": "shared-domain.com",
	}
	srv := subsidiaryServer(subsidiaries)
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)

	count := 0
	for _, f := range findings {
		if f.Value == "shared-domain.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "same domain resolved from two subsidiaries should appear only once")
}

func TestGoogleDorksPlugin_Run_FiltersInputDomain(t *testing.T) {
	// Resolve returns the input domain itself
	subsidiaries := map[string]string{
		"SubsidiaryA": "acme.com",
	}
	srv := subsidiaryServer(subsidiaries)
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEqual(t, "acme.com", f.Value, "input domain should not appear in findings")
	}
}

func TestGoogleDorksPlugin_Run_FiltersWWWInputDomain(t *testing.T) {
	// Resolve returns www. variant of the input domain
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		if strings.HasPrefix(q, "subsidiaries:") {
			_, _ = w.Write([]byte(carouselHTML("SubsidiaryA")))
			return
		}
		// Knowledge panel returns www.acme.com for the subsidiary
		_, _ = w.Write([]byte(knowledgePanelHTML("www.acme.com")))
	}))
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEqual(t, "www.acme.com", f.Value, "www. variant of input domain should not appear in findings")
	}
}

func TestMatchesInputDomain(t *testing.T) {
	tests := []struct {
		d           string
		inputDomain string
		want        bool
	}{
		{"acme.com", "acme.com", true},
		{"www.acme.com", "acme.com", true},
		{"acme.com", "www.acme.com", true},
		{"other.com", "acme.com", false},
		{"notacme.com", "acme.com", false},
		{"sub.acme.com", "acme.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.d+"_vs_"+tt.inputDomain, func(t *testing.T) {
			assert.Equal(t, tt.want, matchesInputDomain(tt.d, tt.inputDomain))
		})
	}
}

func TestGoogleDorksPlugin_Run_FiltersGoogleDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		if strings.HasPrefix(q, "subsidiaries:") {
			_, _ = w.Write([]byte(carouselHTML("SubsidiaryA")))
			return
		}
		// Resolve returns google domains plus one real one
		html := `<html><body><div id="search">
			<a href="https://google.com">g</a>
			<a href="https://googleapis.com">api</a>
			<a href="https://gstatic.com">static</a>
			<a href="https://real-subsidiary.com">real</a>
		</div></body></html>`
		_, _ = w.Write([]byte(html))
	}))
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)

	for _, f := range findings {
		assert.False(t, isExcludedDomain(f.Value), "excluded domain %q should be filtered", f.Value)
	}
}

func TestGoogleDorksPlugin_Run_ContextCanceled(t *testing.T) {
	subsidiaries := map[string]string{
		"SubsidiaryA": "subsidiary.com",
	}
	srv := subsidiaryServer(subsidiaries)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately before any requests

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(ctx, plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGoogleDorksPlugin_Run_SearchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGoogleDorksPlugin_Run_WithOrgName(t *testing.T) {
	var firstQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if firstQuery == "" {
			firstQuery = q
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body></body></html>"))
	}))
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	_, err := p.Run(context.Background(), plugins.Input{
		Domain:  "qualcomm.com",
		OrgName: "Qualcomm",
	})
	require.NoError(t, err)

	assert.Contains(t, firstQuery, "Qualcomm", "first query should use OrgName when provided")
}

func TestGoogleDorksPlugin_Run_NoCarousel(t *testing.T) {
	// Server returns valid HTML but no carousel elements
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><div id=\"search\"><p>no results</p></div></body></html>"))
	}))
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGoogleDorksPlugin_Run_SubsidiaryInFindingData(t *testing.T) {
	subsidiaries := map[string]string{
		"Atheros": "atheros.com",
	}
	srv := subsidiaryServer(subsidiaries)
	defer srv.Close()

	p := newGoogleDorksPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "qualcomm.com"})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "Atheros", f.Data["subsidiary"])
	assert.Equal(t, "qualcomm.com", f.Data["domain"])
}

// ── extractCarouselNames tests ────────────────────────────────────────────────

func TestExtractCarouselNames(t *testing.T) {
	html := carouselHTML("Atheros", "CSR plc", "Wilocity")
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)

	names := extractCarouselNames(doc.Selection)
	assert.ElementsMatch(t, []string{"Atheros", "CSR plc", "Wilocity"}, names)
}

func TestExtractCarouselNames_Empty(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader("<html><body></body></html>"))
	require.NoError(t, err)

	names := extractCarouselNames(doc.Selection)
	assert.Empty(t, names)
}

func TestExtractCarouselNames_Deduplicates(t *testing.T) {
	html := `<html><body>
		<a data-entityname="Atheros">Atheros</a>
		<a data-entityname="Atheros">Atheros duplicate</a>
		<a data-entityname="CSR plc">CSR plc</a>
	</body></html>`
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)

	names := extractCarouselNames(doc.Selection)
	assert.ElementsMatch(t, []string{"Atheros", "CSR plc"}, names)
}

// ── buildQuery tests ──────────────────────────────────────────────────────────

func TestBuildQuery_WithOrgName(t *testing.T) {
	p := newGoogleDorksPlugin("")
	q := p.buildQuery(plugins.Input{Domain: "qualcomm.com", OrgName: "Qualcomm"})
	assert.Equal(t, "subsidiaries:Qualcomm", q)
}

func TestBuildQuery_WithoutOrgName(t *testing.T) {
	p := newGoogleDorksPlugin("")
	q := p.buildQuery(plugins.Input{Domain: "qualcomm.com"})
	assert.Equal(t, "subsidiaries:qualcomm", q)
}

// ── extractOfficialDomain tests ───────────────────────────────────────────────

func TestExtractOfficialDomain(t *testing.T) {
	html := knowledgePanelHTML("atheros.qualcomm.com")
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)
	assert.Equal(t, "atheros.qualcomm.com", extractOfficialDomain(doc.Selection))
}

func TestExtractOfficialDomain_NotFound(t *testing.T) {
	html := `<html><body><a href="https://example.com">Regular link</a></body></html>`
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)
	assert.Empty(t, extractOfficialDomain(doc.Selection))
}

func TestExtractOfficialDomain_GoogleRedirect(t *testing.T) {
	html := `<html><body><a data-attrid="visit_official_site" href="/url?q=https://real-site.com&sa=U">Site</a></body></html>`
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)
	assert.Equal(t, "real-site.com", extractOfficialDomain(doc.Selection))
}

func TestIsExcludedDomain(t *testing.T) {
	tests := []struct{ domain string; want bool }{
		// Google domains
		{"google.com", true},
		{"www.google.co.uk", true},
		{"accounts.google.com", true},
		{"gstatic.com", true},
		{"sub.gstatic.com", true},
		{"googleapis.com", true},
		// Excluded TLDs
		{"agency.gov", true},
		{"army.mil", true},
		{"mit.edu", true},
		{"sub.agency.gov", true},
		{"sub.army.mil", true},
		{"sub.mit.edu", true},
		// Newly added excluded domains
		{"justia.com", true},
		{"sub.justia.com", true},
		{"marketscreener.com", true},
		{"sub.marketscreener.com", true},
		// Not excluded
		{"acme.com", false},
		{"notgoogle.com", false},
		{"example.org", false},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			assert.Equal(t, tt.want, isExcludedDomain(tt.domain))
		})
	}
}

func TestExtractDomainsFromSelection_GoogleRedirect(t *testing.T) {
	html := `<html><body><a href="/url?q=https://real-site.com/page&sa=U">Result</a></body></html>`
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)
	domains := extractDomainsFromSelection(doc.Selection)
	require.Len(t, domains, 1)
	assert.Equal(t, "real-site.com", domains[0])
}

// ── buildQuery multi-segment domain tests ─────────────────────────────────────

func TestBuildQuery_MultiSegmentDomain(t *testing.T) {
	p := newGoogleDorksPlugin("")
	q := p.buildQuery(plugins.Input{Domain: "sub.qualcomm.com"})
	assert.Equal(t, "subsidiaries:qualcomm", q)
}

