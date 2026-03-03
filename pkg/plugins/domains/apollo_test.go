package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	piuscache "github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPlugin creates an ApolloPlugin with a temp-dir APICache for isolated testing.
func newTestPlugin(t *testing.T, baseURL string) *ApolloPlugin {
	t.Helper()
	c, err := piuscache.NewAPI(t.TempDir(), "apollo")
	require.NoError(t, err)
	return &ApolloPlugin{
		client:   client.New(),
		baseURL:  baseURL,
		apiCache: c,
	}
}

// ── Accepts ───────────────────────────────────────────────────────────────────

func TestApolloPlugin_Accepts_RequiresOrgNameAndAPIKey(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")
	p := &ApolloPlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp", Domain: "acme.com"}))
}

func TestApolloPlugin_Accepts_RejectsWithoutOrgName(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")
	p := &ApolloPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

func TestApolloPlugin_Accepts_RejectsWithoutAPIKey(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "")
	p := &ApolloPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestApolloPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("apollo")
	require.True(t, ok, "apollo plugin must be registered")

	assert.Equal(t, "apollo", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Contains(t, p.Description(), "Apollo.io")
	assert.Contains(t, p.Description(), "APOLLO_API_KEY")
}

// ── stripScheme ───────────────────────────────────────────────────────────────

func TestStripScheme(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://blog.example.com/path", "blog.example.com"},
		{"http://example.com", "example.com"},
		{"example.com", "example.com"},
		{"https://example.com/", "example.com"},
		{"HTTPS://EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  example.com  ", "example.com"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, stripScheme(tt.input))
		})
	}
}

// ── extractFindings ───────────────────────────────────────────────────────────

func TestApolloPlugin_ExtractFindings_AllFields(t *testing.T) {
	p := &ApolloPlugin{}
	primary := "acme.com"
	website := "https://www.acme.com"
	blog := "https://blog.acme.com/posts"

	org := &apolloOrg{
		PrimaryDomain:    &primary,
		PersonnelDomains: []string{"acme.com", "acme-corp.com", "acmeinc.com"},
		WebsiteURL:       &website,
		BlogURL:          &blog,
	}

	findings := p.extractFindings("Acme Corp", org)

	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "apollo", f.Source)
		assert.Equal(t, "Acme Corp", f.Data["org"])
		values = append(values, f.Value)
	}

	assert.Contains(t, values, "acme.com")
	assert.Contains(t, values, "acme-corp.com")
	assert.Contains(t, values, "acmeinc.com")
	assert.Contains(t, values, "www.acme.com")
	assert.Contains(t, values, "blog.acme.com")
}

func TestApolloPlugin_ExtractFindings_DeduplicatesDomains(t *testing.T) {
	p := &ApolloPlugin{}
	primary := "acme.com"
	website := "https://acme.com"

	org := &apolloOrg{
		PrimaryDomain:    &primary,
		PersonnelDomains: []string{"acme.com", "acme.com"},
		WebsiteURL:       &website,
	}

	findings := p.extractFindings("Acme Corp", org)

	count := 0
	for _, f := range findings {
		if f.Value == "acme.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "acme.com should appear exactly once")
}

func TestApolloPlugin_ExtractFindings_EmptyOrg(t *testing.T) {
	p := &ApolloPlugin{}
	assert.Empty(t, p.extractFindings("Acme", &apolloOrg{}))
}

func TestApolloPlugin_ExtractFindings_FieldLabels(t *testing.T) {
	p := &ApolloPlugin{}
	primary := "acme.com"
	blog := "https://blog.acme.io"

	org := &apolloOrg{
		PrimaryDomain:    &primary,
		PersonnelDomains: []string{"acme-email.com"},
		BlogURL:          &blog,
	}

	findings := p.extractFindings("Acme", org)
	fieldMap := make(map[string]string)
	for _, f := range findings {
		fieldMap[f.Value] = f.Data["field"].(string)
	}

	assert.Equal(t, "primary_domain", fieldMap["acme.com"])
	assert.Equal(t, "personnel_domain", fieldMap["acme-email.com"])
	assert.Equal(t, "blog_url", fieldMap["blog.acme.io"])
}

// ── APICache integration ──────────────────────────────────────────────────────

func TestApolloPlugin_Cache_WriteAndRead(t *testing.T) {
	c, err := piuscache.NewAPI(t.TempDir(), "apollo")
	require.NoError(t, err)

	key := "acme corp|acme.com"
	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "acme.com", Source: "apollo",
			Data: map[string]any{"org": "Acme Corp", "field": "primary_domain"}},
	}

	c.Set(key, findings)

	var cached []plugins.Finding
	ok := c.Get(key, &cached)
	require.True(t, ok, "cache should hit after Set")
	require.Len(t, cached, 1)
	assert.Equal(t, "acme.com", cached[0].Value)
}

func TestApolloPlugin_Cache_MissForUnknownKey(t *testing.T) {
	c, err := piuscache.NewAPI(t.TempDir(), "apollo")
	require.NoError(t, err)

	var v []plugins.Finding
	assert.False(t, c.Get("never-written-key", &v))
}

// ── Run with mock server ──────────────────────────────────────────────────────

func mockApolloResponse(primary, website, blog string, personnel []string) []byte {
	org := apolloOrg{
		PrimaryDomain:    &primary,
		PersonnelDomains: personnel,
		WebsiteURL:       &website,
		BlogURL:          &blog,
	}
	resp := apolloResponse{Organization: org}
	data, _ := json.Marshal(resp)
	return data
}

func TestApolloPlugin_Run_ExtractsDomains(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.RawQuery, "organization_name=")
		assert.Equal(t, "test-key", r.Header.Get("X-Api-Key"))
		w.Header().Set("Content-Type", "application/json")
		w.Write(mockApolloResponse(
			"acme.com", "https://www.acme.com", "https://blog.acme.io",
			[]string{"acme-corp.com", "acmeinc.com"},
		))
	}))
	defer srv.Close()

	p := newTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})

	require.NoError(t, err)
	require.NotEmpty(t, findings)

	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "acme.com")
	assert.Contains(t, values, "www.acme.com")
	assert.Contains(t, values, "blog.acme.io")
	assert.Contains(t, values, "acme-corp.com")
}

func TestApolloPlugin_Run_PrefersDomainOverOrgName(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")

	var receivedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		primary := "praetorian.com"
		resp := apolloResponse{Organization: apolloOrg{PrimaryDomain: &primary}}
		data, _ := json.Marshal(resp)
		w.Write(data)
	}))
	defer srv.Close()

	p := newTestPlugin(t, srv.URL)
	_, _ = p.Run(context.Background(), plugins.Input{OrgName: "Praetorian", Domain: "praetorian.com"})

	assert.Contains(t, receivedQuery, "domain=")
	assert.NotContains(t, receivedQuery, "organization_name=")
}

func TestApolloPlugin_Run_GracefulOnBadCredentials(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "bad-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"Invalid access credentials"}`))
	}))
	defer srv.Close()

	p := newTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestApolloPlugin_Run_GracefulOnInsufficientCredits(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "real-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"You have insufficient credits"}`))
	}))
	defer srv.Close()

	p := newTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestApolloPlugin_Run_UsesCacheOnSecondCall(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		primary := "acme.com"
		resp := apolloResponse{Organization: apolloOrg{PrimaryDomain: &primary}}
		data, _ := json.Marshal(resp)
		w.Write(data)
	}))
	defer srv.Close()

	p := newTestPlugin(t, srv.URL)
	input := plugins.Input{OrgName: "Acme Corp"}

	f1, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	f2, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "second call must use cache, not hit API")
	assert.Equal(t, len(f1), len(f2))
}

func TestApolloPlugin_Run_EmptyResponseNoFindings(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"organization":{}}`))
	}))
	defer srv.Close()

	p := newTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Unknown Corp"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestApolloPlugin_Run_GracefulOnNetworkError(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	p := newTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestApolloPlugin_Run_PersonnelDomainsNull(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"organization":{"primary_domain":"acme.com","personnel_domains":null}}`))
	}))
	defer srv.Close()

	p := newTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "acme.com", findings[0].Value)
}

// ── Registry ──────────────────────────────────────────────────────────────────

func TestApolloPlugin_IsRegistered(t *testing.T) {
	_, ok := plugins.Get("apollo")
	assert.True(t, ok)
}

func TestApolloPlugin_AppearsinList(t *testing.T) {
	found := false
	for _, n := range plugins.List() {
		if n == "apollo" {
			found = true
			break
		}
	}
	assert.True(t, found)
}

// ── Edge cases ────────────────────────────────────────────────────────────────

func TestStripScheme_URLWithPath(t *testing.T) {
	assert.Equal(t, "blog.acme.com", stripScheme("https://blog.acme.com/posts/2025"))
}

func TestStripScheme_PlainDomain(t *testing.T) {
	assert.Equal(t, "acme-corp.com", stripScheme("acme-corp.com"))
}
