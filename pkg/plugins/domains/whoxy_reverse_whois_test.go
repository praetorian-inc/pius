package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoxyReverseWhois_Accepts_WithKeyAndOrg(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")
	p := &WhoxyReverseWhoisPlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

func TestWhoxyReverseWhois_Accepts_RejectsWithoutKey(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	p := &WhoxyReverseWhoisPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

func TestWhoxyReverseWhois_Accepts_RejectsWithoutOrgName(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")
	p := &WhoxyReverseWhoisPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

func TestWhoxyReverseWhois_Accepts_WithKeyAndEmail(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")
	p := &WhoxyReverseWhoisPlugin{client: client.New()}
	assert.True(t, p.Accepts(plugins.Input{Email: "admin@acme.com"}))
}

func TestWhoxyReverseWhois_Accepts_RejectsWithoutKeyOrSeed(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")
	p := &WhoxyReverseWhoisPlugin{client: client.New()}
	assert.False(t, p.Accepts(plugins.Input{})) // neither org nor email
	t.Setenv("WHOXY_API_KEY", "")
	assert.False(t, p.Accepts(plugins.Input{Email: "a@b.com"})) // email but no key
}

func TestWhoxyReverseWhois_Metadata(t *testing.T) {
	p, ok := plugins.Get("whoxy-reverse-whois")
	require.True(t, ok, "whoxy-reverse-whois plugin must be registered")

	assert.Equal(t, "whoxy-reverse-whois", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModePassive, p.Mode())
	assert.Contains(t, p.Description(), "WHOXY_API_KEY")
}

func mockWhoxyPage(domains []string, totalPages int) []byte {
	type result struct {
		DomainName string `json:"domain_name"`
		QueryTime  string `json:"query_time"`
	}
	type resp struct {
		TotalPages   int      `json:"total_pages"`
		SearchResult []result `json:"search_result"`
	}
	var results []result
	for _, d := range domains {
		results = append(results, result{DomainName: d, QueryTime: "2020-01-01 00:00:00"})
	}
	data, _ := json.Marshal(resp{TotalPages: totalPages, SearchResult: results})
	return data
}

func TestWhoxyReverseWhois_Run_EmitsFindings(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.RawQuery, "reverse=whois")
		assert.Contains(t, r.URL.RawQuery, "name=")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockWhoxyPage([]string{"acme.com", "acme-corp.com"}, 1))
	}))
	defer srv.Close()

	// Hermetic verification: both candidates resolve to unverifiable registrants
	// (empty) so neither is dropped and both surface in the needs_review band.
	stub := &stubResolver{}
	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL, resolver: stub}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})

	require.NoError(t, err)
	require.Len(t, findings, 2)

	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "whoxy-reverse-whois", f.Source)
		assert.Equal(t, "Acme Corp", f.Data["org"])
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "acme.com")
	assert.Contains(t, values, "acme-corp.com")
}

// TestWhoxyReverseWhois_Run_ConfidenceScore asserts the ENG-5123 bands: a
// candidate whose own registrant corroborates the query org ranks at the top of
// the needs_review band (0.60), an unverifiable candidate sits at the mid-band
// (0.50), and BOTH stay strictly below ConfidenceHigh — reverse-whois never
// auto-cleans.
func TestWhoxyReverseWhois_Run_ConfidenceScore(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockWhoxyPage([]string{"acme.com", "acme-corp.com"}, 1))
	}))
	defer srv.Close()

	stub := &stubResolver{
		byDomain: map[string]registrantResult{
			"acme.com":      org("Acme Corp"), // corroborates "Acme" → 0.60
			"acme-corp.com": {},               // unresolvable → 0.50
		},
	}
	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL, resolver: stub}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	require.NoError(t, err)
	require.Len(t, findings, 2)

	byDomain := map[string]plugins.Finding{}
	for _, f := range findings {
		byDomain[f.Value] = f
	}
	assert.InDelta(t, confReverseWhoisCorroborated, plugins.Confidence(byDomain["acme.com"]), 0.001,
		"corroborated match must rank at the 0.60 top-of-band value")
	assert.InDelta(t, confReverseWhoisUnverified, plugins.Confidence(byDomain["acme-corp.com"]), 0.001,
		"unresolvable match must sit at the 0.50 mid-band value")

	for _, f := range findings {
		conf := plugins.Confidence(f)
		assert.GreaterOrEqual(t, conf, plugins.ConfidenceLow,
			"confidence for %q must be at or above the noise floor", f.Value)
		assert.Less(t, conf, plugins.ConfidenceHigh,
			"confidence for %q must be below ConfidenceHigh so it is not clean", f.Value)
		assert.True(t, plugins.NeedsReview(f),
			"match %q must be flagged needs_review", f.Value)
	}
}

// TestWhoxyReverseWhois_Run_DeRanksClearMismatch proves the de-rank path works
// end-to-end through the Whoxy plugin (parity with the ViewDNS invariant): a
// candidate whose own registrant is present, unmasked, and a clear mismatch
// against the query org is emitted at the bottom of the needs_review band —
// NOT dropped — while an unverifiable sibling surfaces higher in the band.
// Nothing is ever removed from the graph (ENG-5123 #1).
func TestWhoxyReverseWhois_Run_DeRanksClearMismatch(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockWhoxyPage([]string{"acme.com", "walmart.com"}, 1))
	}))
	defer srv.Close()

	stub := &stubResolver{
		byDomain: map[string]registrantResult{
			"acme.com":    {},                  // unresolvable → unverified, kept
			"walmart.com": org("Walmart Inc."), // clear mismatch → de-ranked, kept
		},
	}
	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL, resolver: stub}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Leica Biosystems Richmond, Inc."})

	require.NoError(t, err)
	require.Len(t, findings, 2, "clear-mismatch candidate must be de-ranked, never dropped")

	byDomain := map[string]plugins.Finding{}
	for _, f := range findings {
		byDomain[f.Value] = f
		assert.Less(t, plugins.Confidence(f), plugins.ConfidenceHigh)
		assert.True(t, plugins.NeedsReview(f))
	}
	require.Contains(t, byDomain, "acme.com")
	require.Contains(t, byDomain, "walmart.com")
	assert.InDelta(t, confReverseWhoisUnverified, plugins.Confidence(byDomain["acme.com"]), 0.001)
	assert.InDelta(t, confReverseWhoisMismatch, plugins.Confidence(byDomain["walmart.com"]), 0.001,
		"clear mismatch is de-ranked to the bottom of the band")
}

func TestWhoxyReverseWhois_Run_FiltersTenYearOldDomains(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type result struct {
			DomainName string `json:"domain_name"`
			QueryTime  string `json:"query_time"`
		}
		type resp struct {
			TotalPages   int      `json:"total_pages"`
			SearchResult []result `json:"search_result"`
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(resp{
			TotalPages: 1,
			SearchResult: []result{
				{DomainName: "recent.com", QueryTime: "2022-06-15 12:00:00"},
				{DomainName: "old.com", QueryTime: "2010-01-01 00:00:00"},
			},
		})
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	stub := &stubResolver{}
	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL, resolver: stub}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "recent.com", findings[0].Value)
	// Staleness filtering happens BEFORE verification, so the stale record must
	// never trigger a registrant lookup.
	assert.True(t, stub.queried("recent.com"), "the fresh candidate must be verified")
	assert.False(t, stub.queried("old.com"), "the stale candidate must be filtered before verification")
}

func TestWhoxyReverseWhois_Run_PaginatesResults(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")

	pageCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageCount++
		w.Header().Set("Content-Type", "application/json")
		switch pageCount {
		case 1:
			_, _ = w.Write(mockWhoxyPage([]string{"page1.com"}, 2))
		default:
			_, _ = w.Write(mockWhoxyPage([]string{"page2.com"}, 2))
		}
	}))
	defer srv.Close()

	stub := &stubResolver{}
	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL, resolver: stub}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	require.NoError(t, err)
	assert.Equal(t, 2, pageCount, "must fetch both pages")

	var values []string
	for _, f := range findings {
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "page1.com")
	assert.Contains(t, values, "page2.com")
}

func TestWhoxyReverseWhois_Run_EmptyResponse(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockWhoxyPage(nil, 0))
	}))
	defer srv.Close()

	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Unknown Corp"})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWhoxyReverseWhois_IsRegistered(t *testing.T) {
	_, ok := plugins.Get("whoxy-reverse-whois")
	assert.True(t, ok)
}

func TestWhoxyReverseWhois_Run_EmailMode(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		assert.Equal(t, "whois", q.Get("reverse"))
		assert.Equal(t, "admin@acme.com", q.Get("email"))
		assert.Empty(t, q.Get("name")) // email mode must NOT send name=
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockWhoxyPage([]string{"acme.com"}, 1))
	}))
	defer srv.Close()
	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Email: "admin@acme.com"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "admin@acme.com", findings[0].Data["org"])
}
