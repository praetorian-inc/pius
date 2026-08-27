package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	httpclient "github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newWhoxyReverseWhoisTestPlugin(rawClient *http.Client, baseURL string, apiKeys ...string) *WhoxyReverseWhoisPlugin {
	apiKey := ""
	if len(apiKeys) > 0 {
		apiKey = apiKeys[0]
	}
	plugin := NewWhoxyReverseWhoisPlugin(httpclient.NewWithHTTPClient(rawClient), apiKey)
	plugin.client.WithBaseURL(baseURL)
	return plugin
}

func TestWhoxyReverseWhois_Accepts_WithKeyAndOrg(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")
	p := NewWhoxyReverseWhoisPlugin(nil, "")
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

func TestWhoxyReverseWhois_Accepts_RejectsWithoutKey(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	p := NewWhoxyReverseWhoisPlugin(nil, "")
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

func TestWhoxyReverseWhois_Accepts_RejectsWithoutOrgName(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")
	p := NewWhoxyReverseWhoisPlugin(nil, "")
	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

func TestWhoxyReverseWhois_Accepts_WithKeyAndEmail(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")
	p := NewWhoxyReverseWhoisPlugin(nil, "")
	assert.True(t, p.Accepts(plugins.Input{Email: "admin@acme.com"}))
}

func TestWhoxyReverseWhois_Metadata(t *testing.T) {
	p, ok := plugins.Get("whoxy-reverse-whois")
	require.True(t, ok)
	assert.Equal(t, "whoxy-reverse-whois", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModePassive, p.Mode())
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
	t.Setenv("WHOXY_API_KEY", "env-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "constructor-key", r.URL.Query().Get("key"))
		assert.Contains(t, r.URL.RawQuery, "reverse=whois")
		assert.Contains(t, r.URL.RawQuery, "company=")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockWhoxyPage([]string{"acme.com", "acme-corp.com"}, 1))
	}))
	defer srv.Close()

	p := newWhoxyReverseWhoisTestPlugin(srv.Client(), srv.URL, "constructor-key")
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	require.Len(t, findings, 2)

	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.NotEmpty(t, f.Source)
		assert.Equal(t, []WhoisParameter{{Field: "company", Value: "Acme Corp"}},
			findingReverseWhoisParameters(t, f))
		require.Len(t, f.Confidences, 1)
		assert.Equal(t, 50, plugins.TotalConfidence(f))
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "acme.com")
	assert.Contains(t, values, "acme-corp.com")
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

	p := newWhoxyReverseWhoisTestPlugin(srv.Client(), srv.URL)
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

	p := newWhoxyReverseWhoisTestPlugin(srv.Client(), srv.URL)
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
		_, _ = w.Write(mockWhoxyPage(nil, 0))
	}))
	defer srv.Close()

	p := newWhoxyReverseWhoisTestPlugin(srv.Client(), srv.URL)
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
		assert.Empty(t, q.Get("name"), "should not use name param for email queries")
		assert.Empty(t, q.Get("company"), "should not use company param for email queries")
		_, _ = w.Write(mockWhoxyPage([]string{"acme.com"}, 1))
	}))
	defer srv.Close()

	p := newWhoxyReverseWhoisTestPlugin(srv.Client(), srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Email: "admin@acme.com"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, []WhoisParameter{{Field: "email", Value: "admin@acme.com"}},
		findingReverseWhoisParameters(t, findings[0]))
}

func TestWhoxyReverseWhois_Run_PreservesParametersPerDomain(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("company") != "":
			_, _ = w.Write(mockWhoxyPage([]string{"company.example", "shared.example"}, 1))
		case r.URL.Query().Get("name") != "":
			_, _ = w.Write(mockWhoxyPage([]string{"name.example", "shared.example"}, 1))
		case r.URL.Query().Get("email") != "":
			_, _ = w.Write(mockWhoxyPage([]string{"email.example"}, 1))
		default:
			t.Fatal("request did not contain a supported reverse-WHOIS parameter")
		}
	}))
	defer srv.Close()

	p := newWhoxyReverseWhoisTestPlugin(srv.Client(), srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp", PersonName: "Alice Smith", Email: "alice@acme.com",
	})
	require.NoError(t, err)
	require.Len(t, findings, 4)
	assert.Contains(t, []string{"company.example", "shared.example", "name.example", "email.example"}, findings[0].Value)
	assert.Contains(t, []string{"company.example", "shared.example", "name.example", "email.example"}, findings[1].Value)
	assert.Contains(t, []string{"company.example", "shared.example", "name.example", "email.example"}, findings[2].Value)
	assert.Contains(t, []string{"company.example", "shared.example", "name.example", "email.example"}, findings[3].Value)
	var sharedFinding *plugins.Finding
	for i := range findings {
		if findings[i].Value == "shared.example" {
			sharedFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, sharedFinding)
	assert.Equal(t, []WhoisParameter{
		{Field: "company", Value: "Acme Corp"},
		{Field: "name", Value: "Alice Smith"},
	}, findingReverseWhoisParameters(t, *sharedFinding))
	require.Len(t, sharedFinding.Confidences, 1, "duplicate results must keep one baseline entry")
	assert.Equal(t, 50, plugins.TotalConfidence(*sharedFinding))
}
