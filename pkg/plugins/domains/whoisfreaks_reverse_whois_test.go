package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newWhoisFreaksReverseWhoisTestPlugin(rawClient *http.Client, baseURL string, apiKeys ...string) *WhoisFreaksReverseWhoisPlugin {
	apiKey := ""
	if len(apiKeys) > 0 {
		apiKey = apiKeys[0]
	}
	plugin := NewWhoisFreaksReverseWhoisPlugin(rawClient, apiKey)
	plugin.client.WithReverseBaseURL(baseURL)
	return plugin
}

func mockWhoisFreaksPage(domains []string, totalPages int) []byte {
	type result struct {
		DomainName string `json:"domain_name"`
		QueryTime  string `json:"query_time"`
	}
	type resp struct {
		TotalPages int      `json:"total_Pages"`
		Records    []result `json:"whois_domains_historical"`
	}
	results := make([]result, 0, len(domains))
	for _, domain := range domains {
		results = append(results, result{DomainName: domain, QueryTime: "2020-01-01 00:00:00"})
	}
	data, _ := json.Marshal(resp{TotalPages: totalPages, Records: results})
	return data
}

func TestWhoisFreaksReverseWhois_Accepts_WithKeyAndOrg(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	p := NewWhoisFreaksReverseWhoisPlugin(nil, "")
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

func TestWhoisFreaksReverseWhois_Accepts_RejectsWithoutKey(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "")
	p := NewWhoisFreaksReverseWhoisPlugin(nil, "")
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

func TestWhoisFreaksReverseWhois_Accepts_RejectsWithoutOrgName(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	p := NewWhoisFreaksReverseWhoisPlugin(nil, "")
	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

func TestWhoisFreaksReverseWhois_Metadata(t *testing.T) {
	p, ok := plugins.Get("whoisfreaks-reverse-whois")
	require.True(t, ok)
	assert.Equal(t, "whoisfreaks-reverse-whois", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

func TestWhoisFreaksReverseWhois_Run_QueriesCompanyAndOwnerForOrg(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "env-key")

	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "constructor-key", r.URL.Query().Get("apiKey"))
		assert.Equal(t, "true", r.URL.Query().Get("exact"))
		switch {
		case r.URL.Query().Get("company") != "":
			got = append(got, "company="+r.URL.Query().Get("company"))
			_, _ = w.Write(mockWhoisFreaksPage([]string{"company.example", "shared.example"}, 1))
		case r.URL.Query().Get("owner") != "":
			got = append(got, "owner="+r.URL.Query().Get("owner"))
			_, _ = w.Write(mockWhoisFreaksPage([]string{"owner.example", "shared.example"}, 1))
		default:
			t.Fatal("request did not contain company or owner")
		}
	}))
	defer srv.Close()

	p := newWhoisFreaksReverseWhoisTestPlugin(srv.Client(), srv.URL, "constructor-key")
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Inc"})
	require.NoError(t, err)
	assert.Equal(t, []string{"company=Acme Inc", "owner=Acme Inc"}, got)

	require.Len(t, findings, 3)
	byDomain := map[string][]WhoisParameter{}
	for _, finding := range findings {
		byDomain[finding.Value] = findingReverseWhoisParameters(t, finding)
		require.Len(t, finding.Confidences, 1)
		assert.Equal(t, 50, plugins.TotalConfidence(finding))
	}
	assert.Equal(t, []WhoisParameter{{Field: "company", Value: "Acme Inc"}}, byDomain["company.example"])
	assert.Equal(t, []WhoisParameter{{Field: "name", Value: "Acme Inc"}}, byDomain["owner.example"])
	assert.Equal(t, []WhoisParameter{
		{Field: "company", Value: "Acme Inc"},
		{Field: "name", Value: "Acme Inc"},
	}, byDomain["shared.example"])
}

func TestWhoisFreaksReverseWhois_Run_QueriesSuffixAliases(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "test-key")

	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("company") != "":
			got = append(got, "company="+q.Get("company"))
		case q.Get("owner") != "":
			got = append(got, "owner="+q.Get("owner"))
		}
		if q.Get("company") == "Example Pharmacy, LP" {
			_, _ = w.Write(mockWhoisFreaksPage([]string{"example-pharmacy.org"}, 1))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Record Not Found"}`))
	}))
	defer srv.Close()

	p := newWhoisFreaksReverseWhoisTestPlugin(srv.Client(), srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Example Pharmacy, L.P."})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"company=Example Pharmacy, L.P.",
		"owner=Example Pharmacy, L.P.",
		"company=Example Pharmacy, LP",
		"owner=Example Pharmacy, LP",
	}, got)
	require.Len(t, findings, 1)
	assert.Equal(t, "example-pharmacy.org", findings[0].Value)
	assert.Equal(t, []WhoisParameter{{Field: "company", Value: "Example Pharmacy, LP"}},
		findingReverseWhoisParameters(t, findings[0]))
}

func TestWhoisFreaksReverseWhois_Run_EmailMode(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		assert.Equal(t, "admin@acme.com", q.Get("email"))
		assert.Empty(t, q.Get("owner"))
		assert.Empty(t, q.Get("company"))
		_, _ = w.Write(mockWhoisFreaksPage([]string{"acme.com"}, 1))
	}))
	defer srv.Close()

	p := newWhoisFreaksReverseWhoisTestPlugin(srv.Client(), srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{Email: "admin@acme.com"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, []WhoisParameter{{Field: "email", Value: "admin@acme.com"}},
		findingReverseWhoisParameters(t, findings[0]))
}

func TestWhoisFreaksReverseWhois_Run_FiltersTenYearOldDomains(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type result struct {
			DomainName string `json:"domain_name"`
			QueryTime  string `json:"query_time"`
		}
		type resp struct {
			TotalPages int      `json:"total_Pages"`
			Records    []result `json:"whois_domains_historical"`
		}
		data, _ := json.Marshal(resp{
			TotalPages: 1,
			Records: []result{
				{DomainName: "recent.com", QueryTime: "2022-06-15 12:00:00"},
				{DomainName: "old.com", QueryTime: "2010-01-01 00:00:00"},
			},
		})
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	p := newWhoisFreaksReverseWhoisTestPlugin(srv.Client(), srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{PersonName: "Alice Smith"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "recent.com", findings[0].Value)
}

func TestWhoisFreaksReverseWhois_Run_PaginatesResults(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	pageCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageCount++
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write(mockWhoisFreaksPage([]string{"page1.com"}, 2))
		default:
			_, _ = w.Write(mockWhoisFreaksPage([]string{"page2.com"}, 2))
		}
	}))
	defer srv.Close()

	p := newWhoisFreaksReverseWhoisTestPlugin(srv.Client(), srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{PersonName: "Alice Smith"})
	require.NoError(t, err)
	assert.Equal(t, 2, pageCount, "must fetch both pages")

	var values []string
	for _, f := range findings {
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "page1.com")
	assert.Contains(t, values, "page2.com")
}

func TestWhoisFreaksReverseWhois_Run_EmptyResponse(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Record Not Found","message":"Record not found"}`))
	}))
	defer srv.Close()

	p := newWhoisFreaksReverseWhoisTestPlugin(srv.Client(), srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Unknown Corp"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWhoisFreaksReverseWhois_Run_ErrorsDoNotLeakAPIKey(t *testing.T) {
	t.Setenv("WHOISFREAKS_API_KEY", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := newWhoisFreaksReverseWhoisTestPlugin(srv.Client(), srv.URL, "super-secret-key")
	findings, err := p.Run(context.Background(), plugins.Input{Email: "admin@secret-corp.com"})
	require.NoError(t, err, "query failures are skipped")
	assert.Empty(t, findings)
}
