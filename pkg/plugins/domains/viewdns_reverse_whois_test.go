package domains

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestViewDNSReverseWhoisPlugin_Accepts(t *testing.T) {
	originalKey := os.Getenv("VIEWDNS_API_KEY")
	defer func() {
		if originalKey == "" {
			_ = os.Unsetenv("VIEWDNS_API_KEY")
		} else {
			_ = os.Setenv("VIEWDNS_API_KEY", originalKey)
		}
	}()

	p, ok := plugins.Get("viewdns-reverse-whois")
	require.True(t, ok, "viewdns-reverse-whois plugin should be registered")

	tests := []struct {
		name     string
		apiKey   string
		input    plugins.Input
		expected bool
	}{
		{
			name:     "accepts with API key and org name",
			apiKey:   "test-key",
			input:    plugins.Input{OrgName: "Acme Corp"},
			expected: true,
		},
		{
			name:     "rejects without API key",
			apiKey:   "",
			input:    plugins.Input{OrgName: "Acme Corp"},
			expected: false,
		},
		{
			name:     "rejects without org name",
			apiKey:   "test-key",
			input:    plugins.Input{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.apiKey == "" {
				_ = os.Unsetenv("VIEWDNS_API_KEY")
			} else {
				_ = os.Setenv("VIEWDNS_API_KEY", tt.apiKey)
			}
			result := p.Accepts(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestViewDNSReverseWhois_Accepts_InjectedKeyWithoutEnvironment(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "")
	require.NoError(t, os.Unsetenv("VIEWDNS_API_KEY"))

	p := NewViewDNSReverseWhoisPlugin(client.New(), "injected-key")

	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.False(t, p.Accepts(plugins.Input{}))
}

func TestViewDNSReverseWhois_Run_InjectedKeyTakesPrecedence(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "environment-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "injected-key", r.URL.Query().Get("apikey"))
		_, _ = w.Write([]byte(`{"response":{"matches":[{"domain":"acme.com"}]}}`))
	}))
	defer srv.Close()

	p := NewViewDNSReverseWhoisPlugin(client.New(), "injected-key")
	p.baseURL = srv.URL
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "acme.com", findings[0].Value)
}

func TestViewDNSReverseWhois_Run_EnvironmentFallback(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "environment-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "environment-key", r.URL.Query().Get("apikey"))
		_, _ = w.Write([]byte(`{"response":{"matches":[{"domain":"acme.com"}]}}`))
	}))
	defer srv.Close()

	p := NewViewDNSReverseWhoisPlugin(client.New(), "")
	p.baseURL = srv.URL
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "acme.com", findings[0].Value)
}

func TestViewDNSReverseWhois_Run_MissingInputSkipsRequest(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewViewDNSReverseWhoisPlugin(client.New(), "")
	p.baseURL = srv.URL
	findings, err := p.Run(context.Background(), plugins.Input{})

	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Zero(t, requests, "missing input must not issue a request")
}

func TestViewDNSReverseWhois_Run_OrgMode(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.RawQuery, "q=")
		_, _ = w.Write([]byte(`{"response":{"match_count":2,"matches":[{"domain":"acme.com"},{"domain":"acme.net"}]}}`))
	}))
	defer srv.Close()

	p := &ViewDNSReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	require.Len(t, findings, 2)

	assert.ElementsMatch(t, []string{"acme.com", "acme.net"}, []string{
		findings[0].Value,
		findings[1].Value,
	})
	for _, finding := range findings {
		assert.Equal(t, plugins.FindingDomain, finding.Type)
		assert.Equal(t, []WhoisParameter{{Field: "company", Value: "Acme Corp"}},
			findingReverseWhoisParameters(t, finding))
		require.Len(t, finding.Confidences, 1)
		assert.Equal(t, 50, plugins.TotalConfidence(finding))
	}
}

func TestViewDNSReverseWhois_Run_Dedup(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"matches":[{"domain":"acme.com"},{"domain":"ACME.COM"},{"domain":"acme.com."}]}}`))
	}))
	defer srv.Close()

	p := &ViewDNSReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.NoError(t, err)
	require.Len(t, findings, 1, "duplicates should be deduped")
}

func TestViewDNSReverseWhois_Accepts_WithKeyAndEmail(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	p := &ViewDNSReverseWhoisPlugin{client: client.New()}
	assert.True(t, p.Accepts(plugins.Input{Email: "admin@acme.com"}))
	assert.False(t, p.Accepts(plugins.Input{}))
}

func TestViewDNSReverseWhois_Run_EmailMode(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.RawQuery, "q=admin%40acme.com")
		_, _ = w.Write([]byte(`{"response":{"match_count":1,"matches":[{"domain":"acme.com"}]}}`))
	}))
	defer srv.Close()

	p := &ViewDNSReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Email: "admin@acme.com"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "acme.com", findings[0].Value)
	assert.Equal(t, []WhoisParameter{{Field: "email", Value: "admin@acme.com"}},
		findingReverseWhoisParameters(t, findings[0]))
}

func TestViewDNSReverseWhois_Run_NameMode(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Alice Smith", r.URL.Query().Get("q"))
		_, _ = w.Write([]byte(`{"response":{"matches":[{"domain":"example.com"}]}}`))
	}))
	defer srv.Close()

	p := &ViewDNSReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{PersonName: "Alice Smith"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, []WhoisParameter{{Field: "name", Value: "Alice Smith"}},
		findingReverseWhoisParameters(t, findings[0]))
}

func TestViewDNSReverseWhois_Run_QueriesEveryParameter(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("q"))
		_, _ = w.Write([]byte(`{"response":{"matches":[{"domain":"shared.example"}]}}`))
	}))
	defer srv.Close()

	p := &ViewDNSReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Email:   "admin@acme.com",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"Acme Corp", "admin@acme.com"}, queries)
	require.Len(t, findings, 1)
	assert.Equal(t, []WhoisParameter{
		{Field: "company", Value: "Acme Corp"},
		{Field: "email", Value: "admin@acme.com"},
	}, findingReverseWhoisParameters(t, findings[0]))
	require.Len(t, findings[0].Confidences, 1)
}

func TestViewDNSReverseWhois_Run_ParseErrorOmitsSecrets(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := &ViewDNSReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	_, err := p.Run(context.Background(), plugins.Input{Email: "admin@secret-corp.com"})
	require.Error(t, err)

	assert.NotContains(t, err.Error(), "test-key", "error must not contain the API key")
	assert.NotContains(t, err.Error(), "admin@secret-corp.com", "error must not contain the raw email")
}

func TestViewDNSReverseWhois_Run_RequestErrorOmitsSecrets(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "environment-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "injected-secret-key", r.URL.Query().Get("apikey"))
		assert.Equal(t, "admin@secret-corp.com", r.URL.Query().Get("q"))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewViewDNSReverseWhoisPlugin(client.New(), "injected-secret-key")
	p.baseURL = srv.URL
	_, err := p.Run(context.Background(), plugins.Input{Email: "admin@secret-corp.com"})
	require.Error(t, err)

	assert.Contains(t, err.Error(), "request failed")
	assert.NotContains(t, err.Error(), "injected-secret-key", "error must not contain the API key")
	assert.NotContains(t, err.Error(), "admin@secret-corp.com", "error must not contain the raw email")
	assert.NotContains(t, err.Error(), "secret-corp.com", "error must not contain an encoded email")
}
