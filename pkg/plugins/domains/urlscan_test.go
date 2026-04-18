package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockURLScanServer creates a test HTTP server that returns the given URLScan response body.
func mockURLScanServer(response urlscanResponse) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
}

// TestURLScanPlugin_Metadata verifies Name, Description, Category, Phase, and Mode.
func TestURLScanPlugin_Metadata(t *testing.T) {
	p := &URLScanPlugin{client: client.New()}

	assert.Equal(t, "urlscan", p.Name())
	assert.NotEmpty(t, p.Description())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase(), "urlscan is independent (phase 0)")
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

// TestURLScanPlugin_Accepts verifies the Accepts gate.
func TestURLScanPlugin_Accepts(t *testing.T) {
	p := &URLScanPlugin{client: client.New()}

	tests := []struct {
		name     string
		input    plugins.Input
		expected bool
	}{
		{
			name:     "accepts when domain is set",
			input:    plugins.Input{Domain: "praetorian.com"},
			expected: true,
		},
		{
			name:     "rejects when domain is empty",
			input:    plugins.Input{OrgName: "Praetorian"},
			expected: false,
		},
		{
			name:     "rejects when input is zero value",
			input:    plugins.Input{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.Accepts(tt.input))
		})
	}
}

// TestURLScanPlugin_BasicSubdomainDiscovery verifies that subdomains are extracted
// from both results[].page.domain and results[].task.domain.
func TestURLScanPlugin_BasicSubdomainDiscovery(t *testing.T) {
	response := urlscanResponse{
		Results: []urlscanResult{
			{
				Page: urlscanPage{Domain: "www.praetorian.com"},
				Task: urlscanTask{Domain: "api.praetorian.com"},
			},
			{
				Page: urlscanPage{Domain: "blog.praetorian.com"},
				Task: urlscanTask{Domain: "blog.praetorian.com"},
			},
		},
	}

	srv := mockURLScanServer(response)
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})

	require.NoError(t, err)
	require.NotEmpty(t, findings)

	values := make(map[string]bool)
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "urlscan", f.Source)
		values[f.Value] = true
	}

	assert.True(t, values["www.praetorian.com"], "expected www.praetorian.com in findings")
	assert.True(t, values["api.praetorian.com"], "expected api.praetorian.com in findings")
	assert.True(t, values["blog.praetorian.com"], "expected blog.praetorian.com in findings")
}

// TestURLScanPlugin_Deduplication verifies that the same domain appearing in
// multiple results is returned only once.
func TestURLScanPlugin_Deduplication(t *testing.T) {
	response := urlscanResponse{
		Results: []urlscanResult{
			{
				Page: urlscanPage{Domain: "www.praetorian.com"},
				Task: urlscanTask{Domain: "www.praetorian.com"},
			},
			{
				Page: urlscanPage{Domain: "www.praetorian.com"},
				Task: urlscanTask{Domain: "www.praetorian.com"},
			},
			{
				Page: urlscanPage{Domain: "www.praetorian.com"},
				Task: urlscanTask{Domain: "api.praetorian.com"},
			},
		},
	}

	srv := mockURLScanServer(response)
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})

	require.NoError(t, err)

	count := 0
	for _, f := range findings {
		if f.Value == "www.praetorian.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "www.praetorian.com should appear exactly once after dedup")
}

// TestURLScanPlugin_SubdomainFiltering verifies that domains not under the input
// domain are excluded from results.
func TestURLScanPlugin_SubdomainFiltering(t *testing.T) {
	response := urlscanResponse{
		Results: []urlscanResult{
			{
				Page: urlscanPage{Domain: "www.praetorian.com"},
				Task: urlscanTask{Domain: "www.other.com"},
			},
			{
				Page: urlscanPage{Domain: "evil.com"},
				Task: urlscanTask{Domain: "notpraetorian.com"},
			},
			{
				Page: urlscanPage{Domain: "api.praetorian.com"},
				Task: urlscanTask{Domain: "api.praetorian.com"},
			},
		},
	}

	srv := mockURLScanServer(response)
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})

	require.NoError(t, err)

	for _, f := range findings {
		assert.True(t,
			matchesDomain(f.Value, "praetorian.com"),
			"finding %q should be praetorian.com or a subdomain of it", f.Value,
		)
	}
	values := make(map[string]bool)
	for _, f := range findings {
		values[f.Value] = true
	}
	assert.False(t, values["www.other.com"], "www.other.com should be filtered out")
	assert.False(t, values["evil.com"], "evil.com should be filtered out")
	assert.False(t, values["notpraetorian.com"], "notpraetorian.com should be filtered out")
	assert.True(t, values["www.praetorian.com"], "www.praetorian.com should be included")
	assert.True(t, values["api.praetorian.com"], "api.praetorian.com should be included")
}

// TestURLScanPlugin_Normalization verifies that uppercase and trailing dot are
// normalized before output.
func TestURLScanPlugin_Normalization(t *testing.T) {
	response := urlscanResponse{
		Results: []urlscanResult{
			{
				Page: urlscanPage{Domain: "WWW.PRAETORIAN.COM"},
				Task: urlscanTask{Domain: "API.PRAETORIAN.COM."},
			},
		},
	}

	srv := mockURLScanServer(response)
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})

	require.NoError(t, err)

	values := make(map[string]bool)
	for _, f := range findings {
		values[f.Value] = true
		assert.Equal(t, f.Value, normalizeDomain(f.Value), "finding %q should already be normalized", f.Value)
	}
	assert.True(t, values["www.praetorian.com"], "WWW.PRAETORIAN.COM should normalize to www.praetorian.com")
	assert.True(t, values["api.praetorian.com"], "API.PRAETORIAN.COM. should normalize to api.praetorian.com")
}

// TestURLScanPlugin_ErrorHandling verifies graceful behavior when the API is
// unavailable.
func TestURLScanPlugin_ErrorHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // immediately close so requests fail

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

// TestURLScanPlugin_EmptyResults verifies that an empty results array returns no findings.
func TestURLScanPlugin_EmptyResults(t *testing.T) {
	response := urlscanResponse{
		Results: []urlscanResult{},
		Total:   0,
	}

	srv := mockURLScanServer(response)
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})

	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestURLScanPlugin_APIKeyHeader verifies that when URLSCAN_API_KEY is set,
// the API-Key header is included in the request.
func TestURLScanPlugin_APIKeyHeader(t *testing.T) {
	originalKey := os.Getenv("URLSCAN_API_KEY")
	defer func() {
		if originalKey == "" {
			_ = os.Unsetenv("URLSCAN_API_KEY")
		} else {
			_ = os.Setenv("URLSCAN_API_KEY", originalKey)
		}
	}()
	_ = os.Setenv("URLSCAN_API_KEY", "test-api-key-12345")

	var receivedAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAPIKey = r.Header.Get("API-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(urlscanResponse{Results: []urlscanResult{}})
	}))
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}
	_, err := p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})

	require.NoError(t, err)
	assert.Equal(t, "test-api-key-12345", receivedAPIKey, "API-Key header should be set when env var is present")
}

// TestURLScanPlugin_QueryUsesApexDomain verifies that the search query sent to
// URLScan.io uses page.apexDomain: (not domain:) so results are scoped to real
// subdomains of the target rather than unrelated pages that merely mention it.
func TestURLScanPlugin_QueryUsesApexDomain(t *testing.T) {
	var receivedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(urlscanResponse{Results: []urlscanResult{}})
	}))
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}
	_, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.True(t,
		len(receivedQuery) > 0 && receivedQuery[:len("page.apexDomain:")] == "page.apexDomain:",
		"query should start with page.apexDomain: but got %q", receivedQuery,
	)
}

// TestURLScanPlugin_NoAPIKeyHeader verifies that when URLSCAN_API_KEY is not
// set, no API-Key header is sent.
func TestURLScanPlugin_NoAPIKeyHeader(t *testing.T) {
	originalKey := os.Getenv("URLSCAN_API_KEY")
	defer func() {
		if originalKey == "" {
			_ = os.Unsetenv("URLSCAN_API_KEY")
		} else {
			_ = os.Setenv("URLSCAN_API_KEY", originalKey)
		}
	}()
	_ = os.Unsetenv("URLSCAN_API_KEY")

	var receivedAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAPIKey = r.Header.Get("API-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(urlscanResponse{Results: []urlscanResult{}})
	}))
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}
	_, _ = p.Run(context.Background(), plugins.Input{Domain: "praetorian.com"})

	assert.Empty(t, receivedAPIKey, "API-Key header should not be sent when env var is absent")
}
