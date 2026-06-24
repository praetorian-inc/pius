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
	assert.False(t, p.Accepts(plugins.Input{}))                 // neither org nor email
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

	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
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

func TestWhoxyReverseWhois_Run_ConfidenceScore(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockWhoxyPage([]string{"acme.com"}, 1))
	}))
	defer srv.Close()

	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	conf, ok := findings[0].Data["confidence"].(float64)
	require.True(t, ok, "confidence must be set")
	assert.InDelta(t, 0.75, conf, 0.001)
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

	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "recent.com", findings[0].Value)
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

	p := &WhoxyReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
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
