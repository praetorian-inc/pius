package domains

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

	assert.Equal(t, plugins.FindingDomain, findings[0].Type)
	assert.Equal(t, "acme.com", findings[0].Value)
	assert.Equal(t, []ReverseWhoisParameter{{Field: "company", Value: "Acme Corp"}},
		findingReverseWhoisParameters(t, findings[0]))

	assert.Equal(t, "acme.net", findings[1].Value)
	assert.Equal(t, []ReverseWhoisParameter{{Field: "company", Value: "Acme Corp"}},
		findingReverseWhoisParameters(t, findings[1]))
	for _, finding := range findings {
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
	assert.Equal(t, []ReverseWhoisParameter{{Field: "email", Value: "admin@acme.com"}},
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
	findings, err := p.Run(context.Background(), plugins.Input{PersonName: "Alice Smith", Email: "alice@example.com"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, []ReverseWhoisParameter{{Field: "name", Value: "Alice Smith"}},
		findingReverseWhoisParameters(t, findings[0]))
}

func TestViewDNSReverseWhois_Run_SkipsInvalidHigherPriorityParameter(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "admin@acme.com", r.URL.Query().Get("q"))
		_, _ = w.Write([]byte(`{"response":{"matches":[{"domain":"example.com"}]}}`))
	}))
	defer srv.Close()

	p := &ViewDNSReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Privacy Redaction",
		Email:   "admin@acme.com",
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, []ReverseWhoisParameter{{Field: "email", Value: "admin@acme.com"}},
		findingReverseWhoisParameters(t, findings[0]))
}

func TestViewDNSReverseWhois_Run_ErrorOmitsURL(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := &ViewDNSReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	_, err := p.Run(context.Background(), plugins.Input{Email: "admin@secret-corp.com"})
	require.Error(t, err)

	// Error must not contain the API key or raw email
	assert.False(t, strings.Contains(err.Error(), "admin@secret-corp.com"),
		"error must not contain the raw email")
}
