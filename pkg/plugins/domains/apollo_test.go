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
	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"})) // domain alone not enough
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
	assert.Equal(t, 0, p.Phase(), "apollo is independent (phase 0)")
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

	// Collect values for assertions
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
	website := "https://acme.com" // same as primary — should deduplicate

	org := &apolloOrg{
		PrimaryDomain:    &primary,
		PersonnelDomains: []string{"acme.com", "acme.com"}, // duplicates
		WebsiteURL:       &website,
	}

	findings := p.extractFindings("Acme Corp", org)

	// acme.com should appear exactly once
	count := 0
	for _, f := range findings {
		if f.Value == "acme.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "acme.com should appear exactly once after deduplication")
}

func TestApolloPlugin_ExtractFindings_EmptyOrg(t *testing.T) {
	p := &ApolloPlugin{}
	findings := p.extractFindings("Acme", &apolloOrg{})
	assert.Empty(t, findings)
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

	fieldMap := make(map[string]string) // value → field
	for _, f := range findings {
		fieldMap[f.Value] = f.Data["field"].(string)
	}

	assert.Equal(t, "primary_domain", fieldMap["acme.com"])
	assert.Equal(t, "personnel_domain", fieldMap["acme-email.com"])
	assert.Equal(t, "blog_url", fieldMap["blog.acme.io"])
}

// ── cache ─────────────────────────────────────────────────────────────────────

func TestApolloPlugin_Cache_WriteAndRead(t *testing.T) {
	// Override cache dir via temp dir
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	p := &ApolloPlugin{}
	key := "acme corp|acme.com"
	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "acme.com", Source: "apollo",
			Data: map[string]any{"org": "Acme Corp", "field": "primary_domain"}},
		{Type: plugins.FindingDomain, Value: "acme-email.com", Source: "apollo",
			Data: map[string]any{"org": "Acme Corp", "field": "personnel_domain"}},
	}

	// Write
	p.writeCache(key, findings)

	// Read back
	cached, ok := p.readCache(key)
	require.True(t, ok, "cache should hit after write")
	require.Len(t, cached, 2)
	assert.Equal(t, "acme.com", cached[0].Value)
	assert.Equal(t, "acme-email.com", cached[1].Value)
}

func TestApolloPlugin_Cache_MissForUnknownKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	p := &ApolloPlugin{}
	_, ok := p.readCache("unknown key that was never written")
	assert.False(t, ok)
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
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify org name was sent
		assert.Contains(t, r.URL.RawQuery, "organization_name=")
		assert.Equal(t, "test-key", r.Header.Get("X-Api-Key"))

		w.Header().Set("Content-Type", "application/json")
		w.Write(mockApolloResponse(
			"acme.com",
			"https://www.acme.com",
			"https://blog.acme.io",
			[]string{"acme-corp.com", "acmeinc.com"},
		))
	}))
	defer srv.Close()

	p := &ApolloPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})

	require.NoError(t, err)
	require.NotEmpty(t, findings)

	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "apollo", f.Source)
		values = append(values, f.Value)
	}

	assert.Contains(t, values, "acme.com")
	assert.Contains(t, values, "www.acme.com")
	assert.Contains(t, values, "blog.acme.io")
	assert.Contains(t, values, "acme-corp.com")
	assert.Contains(t, values, "acmeinc.com")
}

func TestApolloPlugin_Run_PrefersDomainOverOrgName(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

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

	p := &ApolloPlugin{client: client.New(), baseURL: srv.URL}
	_, _ = p.Run(context.Background(), plugins.Input{
		OrgName: "Praetorian",
		Domain:  "praetorian.com",
	})

	// When domain provided, should query by domain not org name
	assert.Contains(t, receivedQuery, "domain=")
	assert.NotContains(t, receivedQuery, "organization_name=")
}

func TestApolloPlugin_Run_GracefulOnBadCredentials(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "bad-key")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"Invalid access credentials","status":"unauthorized"}`))
	}))
	defer srv.Close()

	p := &ApolloPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	assert.NoError(t, err)
	assert.Empty(t, findings, "bad credentials should return empty gracefully")
}

func TestApolloPlugin_Run_GracefulOnInsufficientCredits(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "real-key")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"You have insufficient credits","status":"payment_required"}`))
	}))
	defer srv.Close()

	p := &ApolloPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestApolloPlugin_Run_UsesCacheOnSecondCall(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

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

	p := &ApolloPlugin{client: client.New(), baseURL: srv.URL}
	input := plugins.Input{OrgName: "Acme Corp"}

	// First call — hits API
	f1, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call — should use cache, not hit API
	f2, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "second call must use cache, not hit API")

	// Both should return same findings
	require.Len(t, f1, len(f2))
}

func TestApolloPlugin_Run_EmptyResponseNoFindings(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Organization with no domain data
		w.Write([]byte(`{"organization":{}}`))
	}))
	defer srv.Close()

	p := &ApolloPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Unknown Corp"})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

// ── Integration: appears in pius list ────────────────────────────────────────

func TestApolloPlugin_IsRegistered(t *testing.T) {
	_, ok := plugins.Get("apollo")
	assert.True(t, ok, "apollo plugin must be in the global registry")
}

func TestApolloPlugin_AppearsinList(t *testing.T) {
	names := plugins.List()
	found := false
	for _, n := range names {
		if n == "apollo" {
			found = true
			break
		}
	}
	assert.True(t, found, "apollo must appear in plugins.List()")
}

// ── Edge cases ────────────────────────────────────────────────────────────────

func TestStripScheme_URLWithPath(t *testing.T) {
	// blog_url often includes paths — we only want the host
	assert.Equal(t, "blog.acme.com", stripScheme("https://blog.acme.com/posts/2025"))
}

func TestStripScheme_PlainDomain(t *testing.T) {
	// Personnel domains are plain strings without schemes
	assert.Equal(t, "acme-corp.com", stripScheme("acme-corp.com"))
}

func TestApolloPlugin_Run_GracefulOnNetworkError(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Use a server that's immediately closed (simulates network error)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // Close immediately

	p := &ApolloPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	// Should degrade gracefully, not return error
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestApolloPlugin_Run_PersonnelDomainsField(t *testing.T) {
	t.Setenv("APOLLO_API_KEY", "test-key")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Apollo sometimes returns personnel_domains as null
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"organization":{"primary_domain":"acme.com","personnel_domains":null}}`))
	}))
	defer srv.Close()

	p := &ApolloPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	assert.NoError(t, err)
	// Should still get primary_domain finding
	require.Len(t, findings, 1)
	assert.Equal(t, "acme.com", findings[0].Value)
}

