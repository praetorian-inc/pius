package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockCRTShServer(entries []map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
}

func TestCRTShPlugin_ParsesDomains(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "api.example.com"},
		{"name_value": "www.example.com"},
		{"name_value": "mail.example.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "crt-sh", f.Source)
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "api.example.com")
	assert.Contains(t, values, "www.example.com")
	assert.Contains(t, values, "mail.example.com")
}

func TestCRTShPlugin_SkipsWildcards(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "*.example.com"},
		{"name_value": "api.example.com"},
		{"name_value": "*"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	for _, f := range findings {
		assert.False(t, strings.HasPrefix(f.Value, "*"), "wildcards must be filtered: %s", f.Value)
	}
	require.Len(t, findings, 1)
	assert.Equal(t, "api.example.com", findings[0].Value)
}

func TestCRTShPlugin_DeduplicatesDomains(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "example.com\nexample.com"},
		{"name_value": "example.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	count := 0
	for _, f := range findings {
		if f.Value == "example.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "example.com should appear exactly once after dedup")
}

func TestCRTShPlugin_NormalizesDomains(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "EXAMPLE.COM"},
		{"name_value": "api.example.com."},
		{"name_value": "  mail.example.com  "},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	values := make(map[string]bool)
	for _, f := range findings {
		values[f.Value] = true
		assert.Equal(t, strings.ToLower(strings.TrimSpace(f.Value)), f.Value,
			"value %q must be lowercase and trimmed", f.Value)
	}
	assert.True(t, values["example.com"], "EXAMPLE.COM should normalize to example.com")
	assert.True(t, values["api.example.com"], "trailing dot should be removed")
	assert.True(t, values["mail.example.com"], "whitespace should be trimmed")
}

func TestCRTShPlugin_MultipleDomainsInNameValue(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "api.example.com\nwww.example.com\nmail.example.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Len(t, findings, 3)
}

func TestCRTShPlugin_PrefersDomainOverOrgName(t *testing.T) {
	var receivedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL}
	_, _ = p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Domain:  "acme.com",
	})
	assert.Equal(t, "acme.com", receivedQuery, "domain should be used over org name")
}

func TestCRTShPlugin_GracefulOnNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}
