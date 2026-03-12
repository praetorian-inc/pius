package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	piuscache "github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

func newWikidataPlugin(t *testing.T, baseURL string) *WikidataPlugin {
	t.Helper()
	c, err := piuscache.NewAPI(t.TempDir(), "wikidata")
	require.NoError(t, err)
	return &WikidataPlugin{
		httpClient: http.DefaultClient,
		baseURL:    baseURL,
		apiCache:   c,
	}
}

func wikidataCompanyResponse(entityID string) []byte {
	resp := sparqlResponse{
		Results: struct {
			Bindings []sparqlBinding `json:"bindings"`
		}{
			Bindings: []sparqlBinding{
				{Entity: sparqlValue{Type: "uri", Value: "http://www.wikidata.org/entity/" + entityID}},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func wikidataEmptyResponse() []byte {
	resp := sparqlResponse{
		Results: struct {
			Bindings []sparqlBinding `json:"bindings"`
		}{
			Bindings: []sparqlBinding{},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func wikidataSubsidiaryResponse(subsidiaries ...struct {
	id       string
	label    string
	website  string
	relation string
}) []byte {
	bindings := make([]sparqlBinding, len(subsidiaries))
	for i, sub := range subsidiaries {
		bindings[i] = sparqlBinding{
			Entity:      sparqlValue{Type: "uri", Value: "http://www.wikidata.org/entity/" + sub.id},
			EntityLabel: sparqlValue{Type: "literal", Value: sub.label},
			Website:     sparqlValue{Type: "uri", Value: sub.website},
			Relation:    sparqlValue{Type: "literal", Value: sub.relation},
		}
	}
	resp := sparqlResponse{
		Results: struct {
			Bindings []sparqlBinding `json:"bindings"`
		}{
			Bindings: bindings,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// ── Interface tests ──────────────────────────────────────────────────────────

func TestWikidataPlugin_Name(t *testing.T) {
	p := newWikidataPlugin(t, "")
	assert.Equal(t, "wikidata", p.Name())
}

func TestWikidataPlugin_Description(t *testing.T) {
	p := newWikidataPlugin(t, "")
	desc := p.Description()
	assert.Contains(t, desc, "Wikidata")
	assert.Contains(t, desc, "SPARQL")
	assert.Contains(t, desc, "subsidiaries")
}

func TestWikidataPlugin_Category(t *testing.T) {
	p := newWikidataPlugin(t, "")
	assert.Equal(t, "domain", p.Category())
}

func TestWikidataPlugin_Phase(t *testing.T) {
	p := newWikidataPlugin(t, "")
	assert.Equal(t, 0, p.Phase())
}

func TestWikidataPlugin_Mode(t *testing.T) {
	p := newWikidataPlugin(t, "")
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

func TestWikidataPlugin_Accepts(t *testing.T) {
	p := newWikidataPlugin(t, "")

	tests := []struct {
		name     string
		input    plugins.Input
		expected bool
	}{
		{
			name:     "accepts with OrgName",
			input:    plugins.Input{OrgName: "Microsoft"},
			expected: true,
		},
		{
			name:     "rejects empty OrgName",
			input:    plugins.Input{OrgName: ""},
			expected: false,
		},
		{
			name:     "rejects domain only",
			input:    plugins.Input{Domain: "microsoft.com"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Accepts(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// ── Run() tests ──────────────────────────────────────────────────────────────

func TestWikidataPlugin_Run_EmptyOrgName(t *testing.T) {
	p := newWikidataPlugin(t, "http://should-not-be-called")
	findings, err := p.Run(context.Background(), plugins.Input{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWikidataPlugin_Run_NoEntityFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sparql-results+json")
		w.Write(wikidataEmptyResponse())
	}))
	defer srv.Close()

	p := newWikidataPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "NonExistentCorp12345"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWikidataPlugin_Run_WithSubsidiariesAndWebsites(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sparql-results+json")
		requestCount++
		query := r.URL.Query().Get("query")

		// First request: company lookup
		if strings.Contains(query, "rdfs:label") && strings.Contains(query, "wdt:P31") {
			w.Write(wikidataCompanyResponse("Q2283"))
			return
		}

		// Second request: subsidiaries
		if strings.Contains(query, "P749") || strings.Contains(query, "P355") {
			w.Write(wikidataSubsidiaryResponse(
				struct{ id, label, website, relation string }{"Q18593264", "LinkedIn", "https://www.linkedin.com", "subsidiary (P749)"},
				struct{ id, label, website, relation string }{"Q42904", "GitHub", "https://github.com", "subsidiary (P749)"},
				struct{ id, label, website, relation string }{"Q191789", "Skype", "https://www.skype.com", "owned-by (P127)"},
			))
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := newWikidataPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Microsoft"})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(findings), 3) // At least 3 domain findings

	// Check for domain findings
	domains := make(map[string]bool)
	for _, f := range findings {
		if f.Type == plugins.FindingDomain {
			domains[f.Value] = true
			assert.Equal(t, "wikidata", f.Source)
			assert.NotEmpty(t, f.Data["subsidiary"])
			assert.NotEmpty(t, f.Data["wikidata_id"])
			assert.Equal(t, "wikidata-sparql", f.Data["method"])
		}
	}

	assert.True(t, domains["linkedin.com"], "should find linkedin.com")
	assert.True(t, domains["github.com"], "should find github.com")
	assert.True(t, domains["skype.com"], "should find skype.com")
}

func TestWikidataPlugin_Run_SubsidiaryWithoutWebsite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sparql-results+json")
		query := r.URL.Query().Get("query")

		if strings.Contains(query, "rdfs:label") && strings.Contains(query, "wdt:P31") {
			w.Write(wikidataCompanyResponse("Q312"))
			return
		}

		if strings.Contains(query, "P749") {
			// Subsidiary without website
			w.Write(wikidataSubsidiaryResponse(
				struct{ id, label, website, relation string }{"Q123456", "Apple Subsidiary LLC", "", "subsidiary (P749)"},
			))
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := newWikidataPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Apple Inc"})
	require.NoError(t, err)

	// Should have a FindingCIDRHandle for the subsidiary name (for further enrichment)
	var handleFindings []plugins.Finding
	for _, f := range findings {
		if f.Type == plugins.FindingCIDRHandle {
			handleFindings = append(handleFindings, f)
		}
	}

	require.Len(t, handleFindings, 1)
	assert.Equal(t, "Apple Subsidiary LLC", handleFindings[0].Value)
	assert.Equal(t, "wikidata", handleFindings[0].Source)
}

func TestWikidataPlugin_Run_Deduplication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sparql-results+json")
		query := r.URL.Query().Get("query")

		if strings.Contains(query, "rdfs:label") && strings.Contains(query, "wdt:P31") {
			w.Write(wikidataCompanyResponse("Q2283"))
			return
		}

		if strings.Contains(query, "P749") {
			// Same subsidiary appears via different relationships
			w.Write(wikidataSubsidiaryResponse(
				struct{ id, label, website, relation string }{"Q42904", "GitHub", "https://github.com", "subsidiary (P749)"},
				struct{ id, label, website, relation string }{"Q42904", "GitHub", "https://github.com", "subsidiary (P355)"},
				struct{ id, label, website, relation string }{"Q42904", "GitHub", "https://github.com", "owned-by (P127)"},
			))
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := newWikidataPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Microsoft"})
	require.NoError(t, err)

	// Should deduplicate github.com
	githubCount := 0
	for _, f := range findings {
		if f.Type == plugins.FindingDomain && f.Value == "github.com" {
			githubCount++
		}
	}
	assert.Equal(t, 1, githubCount, "github.com should appear only once")
}

func TestWikidataPlugin_Run_ConfidenceScoring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sparql-results+json")
		query := r.URL.Query().Get("query")

		if strings.Contains(query, "rdfs:label") && strings.Contains(query, "wdt:P31") {
			w.Write(wikidataCompanyResponse("Q2283"))
			return
		}

		if strings.Contains(query, "P749") {
			w.Write(wikidataSubsidiaryResponse(
				struct{ id, label, website, relation string }{"Q42904", "GitHub", "https://github.com", "subsidiary (P749)"},
				struct{ id, label, website, relation string }{"Q123", "NoWebsite Corp", "", "subsidiary (P749)"},
			))
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := newWikidataPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Microsoft"})
	require.NoError(t, err)

	for _, f := range findings {
		conf, ok := f.Data["confidence"].(float64)
		require.True(t, ok, "confidence should be set")

		if f.Type == plugins.FindingDomain {
			// Domain findings from website should have high confidence
			assert.Equal(t, plugins.ConfidenceHigh, conf, "domain findings should have high confidence")
		} else if f.Type == plugins.FindingCIDRHandle {
			// Subsidiary name findings should have medium confidence
			assert.Equal(t, 0.55, conf, "subsidiary name findings should have medium confidence")
		}
	}
}

func TestWikidataPlugin_Run_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newWikidataPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Microsoft"})
	require.NoError(t, err) // Plugin should handle errors gracefully
	assert.Empty(t, findings)
}

func TestWikidataPlugin_Run_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sparql-results+json")
		w.Write([]byte("not valid json"))
	}))
	defer srv.Close()

	p := newWikidataPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Microsoft"})
	require.NoError(t, err) // Plugin should handle errors gracefully
	assert.Empty(t, findings)
}

func TestWikidataPlugin_Run_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow response that should be interrupted
		select {
		case <-r.Context().Done():
			return
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	p := newWikidataPlugin(t, srv.URL)
	findings, err := p.Run(ctx, plugins.Input{OrgName: "Microsoft"})
	// Either nil error or context error
	if err != nil {
		assert.ErrorIs(t, err, context.Canceled)
	}
	assert.Empty(t, findings)
}

func TestWikidataPlugin_Run_ExcludesOrgFromFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sparql-results+json")
		query := r.URL.Query().Get("query")

		if strings.Contains(query, "rdfs:label") && strings.Contains(query, "wdt:P31") {
			w.Write(wikidataCompanyResponse("Q2283"))
			return
		}

		if strings.Contains(query, "P749") {
			// Include the parent org name in subsidiaries (should be excluded)
			w.Write(wikidataSubsidiaryResponse(
				struct{ id, label, website, relation string }{"Q2283", "Microsoft", "https://microsoft.com", "subsidiary (P749)"},
				struct{ id, label, website, relation string }{"Q42904", "GitHub", "https://github.com", "subsidiary (P749)"},
			))
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := newWikidataPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Microsoft"})
	require.NoError(t, err)

	// Should not emit "Microsoft" as a FindingCIDRHandle (but domain is OK)
	for _, f := range findings {
		if f.Type == plugins.FindingCIDRHandle {
			assert.NotEqual(t, "Microsoft", f.Value, "should not emit org name as CIDR handle")
		}
	}
}

// ── Helper function tests ────────────────────────────────────────────────────

func TestExtractEntityID(t *testing.T) {
	tests := []struct {
		uri      string
		expected string
	}{
		{"http://www.wikidata.org/entity/Q312", "Q312"},
		{"http://www.wikidata.org/entity/Q2283", "Q2283"},
		{"Q123", "Q123"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			got := extractEntityID(tt.uri)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestExtractDomainFromURL(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://www.github.com", "github.com"},
		{"https://github.com/about", "github.com"},
		{"http://linkedin.com", "linkedin.com"},
		{"https://WWW.MICROSOFT.COM", "microsoft.com"},
		{"https://www.example.com:8080/path", "example.com"},
		{"not-a-url", ""},
		{"", ""},
		{"https://localhost", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractDomainFromURL(tt.url)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestEscapeSPARQL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{`quote"test`, `quote\"test`},
		{"back\\slash", "back\\\\slash"},
		{"new\nline", "new\\nline"},
		{"tab\there", "tab\\there"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeSPARQL(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// ── Plugin registration test ─────────────────────────────────────────────────

func TestWikidataPlugin_Registered(t *testing.T) {
	p, ok := plugins.Get("wikidata")
	require.True(t, ok, "wikidata plugin should be registered")
	assert.Equal(t, "wikidata", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, plugins.ModePassive, p.Mode())
}
