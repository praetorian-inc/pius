package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Basic interface tests
// ============================================================================

func TestDoHEnumPlugin_Name(t *testing.T) {
	p := &DoHEnumPlugin{}
	assert.Equal(t, "doh-enum", p.Name())
}

func TestDoHEnumPlugin_Description(t *testing.T) {
	p := &DoHEnumPlugin{}
	assert.NotEmpty(t, p.Description())
}

func TestDoHEnumPlugin_Category(t *testing.T) {
	p := &DoHEnumPlugin{}
	assert.Equal(t, "domain", p.Category())
}

func TestDoHEnumPlugin_Phase(t *testing.T) {
	p := &DoHEnumPlugin{}
	assert.Equal(t, 0, p.Phase())
}

func TestDoHEnumPlugin_Mode(t *testing.T) {
	p := &DoHEnumPlugin{}
	assert.Equal(t, plugins.ModeActive, p.Mode())
}

// ============================================================================
// Accepts tests
// ============================================================================

func TestDoHEnumPlugin_Accepts(t *testing.T) {
	p := &DoHEnumPlugin{}

	assert.True(t, p.Accepts(plugins.Input{Domain: "example.com"}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.False(t, p.Accepts(plugins.Input{}))
}

// ============================================================================
// dohResponse-based Run tests using mock HTTP server
// ============================================================================

// mockDoHServer builds an httptest.Server that answers DoH JSON queries.
// resolvedSubdomains is the set of FQDNs that should resolve (NOERROR).
// All other queries return NXDOMAIN (Status 3, no answers).
func mockDoHServer(t *testing.T, resolvedSubdomains map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/dns-json")

		if resolvedSubdomains[name] {
			resp := dohResponse{
				Status: 0,
				Answer: []struct {
					Name string `json:"name"`
					Type int    `json:"type"`
					Data string `json:"data"`
				}{
					{Name: name, Type: 1, Data: "1.2.3.4"},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// NXDOMAIN
		resp := dohResponse{Status: 3}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestDoHEnumPlugin_Run_FindsSubdomains(t *testing.T) {
	resolved := map[string]bool{
		"www.example.com":  true,
		"mail.example.com": true,
	}
	srv := mockDoHServer(t, resolved)
	defer srv.Close()

	p := &DoHEnumPlugin{doer: srv.Client()}

	// Override endpoint to use the test server
	// We call queryDoH directly via a custom endpoint
	endpoint := DoHEndpoint{URL: srv.URL, Name: "test"}

	// Test queryDoH directly for existing subdomain
	exists, err := p.queryDoH(context.Background(), "www.example.com", endpoint)
	require.NoError(t, err)
	assert.True(t, exists, "www.example.com should be found")

	// Test queryDoH for non-existent subdomain
	exists, err = p.queryDoH(context.Background(), "nope.example.com", endpoint)
	require.NoError(t, err)
	assert.False(t, exists, "nope.example.com should not be found")
}

func TestDoHEnumPlugin_Run_HandlesNXDOMAIN(t *testing.T) {
	// All subdomains return NXDOMAIN
	srv := mockDoHServer(t, map[string]bool{})
	defer srv.Close()

	p := &DoHEnumPlugin{doer: srv.Client()}
	endpoint := DoHEndpoint{URL: srv.URL, Name: "test"}

	exists, err := p.queryDoH(context.Background(), "nxdomain.example.com", endpoint)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestDoHEnumPlugin_Run_ContextCancellation(t *testing.T) {
	// A server that blocks briefly; we cancel context immediately
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return immediately so we don't actually block
		w.Header().Set("Content-Type", "application/dns-json")
		resp := dohResponse{Status: 3}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Create a small temp wordlist so resolveWordlist succeeds
	tmpDir := t.TempDir()
	wlPath := filepath.Join(tmpDir, "wordlist.txt")
	err := os.WriteFile(wlPath, []byte("www\nmail\n"), 0o600)
	require.NoError(t, err)

	p := &DoHEnumPlugin{doer: srv.Client()}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// With cancelled context, Run should stop and return without error
	findings, err := p.Run(ctx, plugins.Input{
		Domain: "example.com",
		Meta: map[string]string{
			"doh_servers":  srv.URL,
			"doh_wordlist": wlPath,
		},
	})
	// No error expected; context cancellation just stops enumeration
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDoHEnumPlugin_Run_RateLimitRetry(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call: 429
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		// Second call: success
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/dns-json")
		resp := dohResponse{
			Status: 0,
			Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				Data string `json:"data"`
			}{{Name: name, Type: 1, Data: "1.2.3.4"}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &DoHEnumPlugin{doer: srv.Client()}
	endpoint := DoHEndpoint{URL: srv.URL, Name: "test"}
	rotation := []DoHEndpoint{endpoint}

	finding, ok := p.queryWithRetry(context.Background(), "www.example.com", rotation)
	assert.True(t, ok, "should succeed after retry")
	assert.Equal(t, "www.example.com", finding.Value)
	assert.GreaterOrEqual(t, callCount, 2, "should have made at least 2 calls")
}

func TestDoHEnumPlugin_Run_CustomWordlist(t *testing.T) {
	// Create a temp wordlist file
	tmpDir := t.TempDir()
	wlPath := filepath.Join(tmpDir, "wordlist.txt")
	err := os.WriteFile(wlPath, []byte("custom1\ncustom2\n# comment\n"), 0o600)
	require.NoError(t, err)

	srv := mockDoHServer(t, map[string]bool{
		"custom1.example.com": true,
	})
	defer srv.Close()

	p := &DoHEnumPlugin{doer: srv.Client()}
	meta := map[string]string{
		"doh_wordlist": wlPath,
		"doh_servers":  srv.URL,
	}

	wordlist, err := p.resolveWordlist(meta)
	require.NoError(t, err)
	assert.Equal(t, []string{"custom1", "custom2"}, wordlist)
}

// ============================================================================
// detectWildcardDoH tests
// ============================================================================

func TestDoHEnumPlugin_DetectWildcardDoH(t *testing.T) {
	// Server that resolves ALL subdomains (wildcard behavior)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		name := r.URL.Query().Get("name")
		resp := dohResponse{
			Status: 0,
			Answer: []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				Data string `json:"data"`
			}{{Name: name, Type: 1, Data: "1.2.3.4"}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &DoHEnumPlugin{doer: srv.Client()}
	endpoints := []DoHEndpoint{{URL: srv.URL, Name: "test"}}

	assert.True(t, p.detectWildcardDoH(context.Background(), "example.com", endpoints))
}

func TestDoHEnumPlugin_DetectWildcardDoH_NoWildcard(t *testing.T) {
	// Server that returns NXDOMAIN for everything
	srv := mockDoHServer(t, map[string]bool{})
	defer srv.Close()

	p := &DoHEnumPlugin{doer: srv.Client()}
	endpoints := []DoHEndpoint{{URL: srv.URL, Name: "test"}}

	assert.False(t, p.detectWildcardDoH(context.Background(), "example.com", endpoints))
}

// ============================================================================
// resolveEndpoints priority tests
// ============================================================================

func TestDoHEnumPlugin_ResolveEndpoints_Defaults(t *testing.T) {
	p := &DoHEnumPlugin{}
	endpoints, cleanup, err := p.resolveEndpoints(context.Background(), nil)
	defer cleanup()
	require.NoError(t, err)
	assert.Equal(t, defaultDoHEndpoints, endpoints)
}

func TestDoHEnumPlugin_ResolveEndpoints_CustomServers(t *testing.T) {
	p := &DoHEnumPlugin{}
	meta := map[string]string{
		"doh_servers": "https://server1.example.com,https://server2.example.com",
	}
	endpoints, cleanup, err := p.resolveEndpoints(context.Background(), meta)
	defer cleanup()
	require.NoError(t, err)
	require.Len(t, endpoints, 2)
	assert.Equal(t, "https://server1.example.com", endpoints[0].URL)
	assert.Equal(t, "https://server2.example.com", endpoints[1].URL)
}

func TestDoHEnumPlugin_ResolveEndpoints_Gateways(t *testing.T) {
	p := &DoHEnumPlugin{}
	meta := map[string]string{
		"doh_gateways": "https://gw1.execute-api.us-east-1.amazonaws.com/pius,https://gw2.execute-api.eu-west-1.amazonaws.com/pius",
		"doh_servers":  "https://ignored.example.com",
	}
	endpoints, cleanup, err := p.resolveEndpoints(context.Background(), meta)
	defer cleanup()
	require.NoError(t, err)
	require.Len(t, endpoints, 2)
	assert.Equal(t, "https://gw1.execute-api.us-east-1.amazonaws.com/pius", endpoints[0].URL)
	// gateways take priority over servers
}

func TestDoHEnumPlugin_ResolveEndpoints_DeployGatewaysNoCredentials(t *testing.T) {
	// Unset AWS credentials so detectAWSCredentials fails
	// Clear credential env vars
	for _, env := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"} {
		t.Setenv(env, "")
	}
	// Point config/credentials files to nonexistent paths to prevent SDK fallback
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/tmp/nonexistent-aws-creds")
	t.Setenv("AWS_CONFIG_FILE", "/tmp/nonexistent-aws-config")

	p := &DoHEnumPlugin{}
	meta := map[string]string{
		"doh_deploy_gateways": "true",
		"doh_servers":         "https://cloudflare-dns.com/dns-query",
	}
	endpoints, cleanup, err := p.resolveEndpoints(context.Background(), meta)
	defer cleanup()
	// With credentials cleared, deployment should fail
	assert.Error(t, err)
	assert.Nil(t, endpoints)
}

// ============================================================================
// Helper function tests
// ============================================================================

func TestParseCSV(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"  a , b , c  ", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"", []string(nil)},
		{"a,,b", []string{"a", "b"}},
	}

	for _, tt := range tests {
		result := parseCSV(tt.input)
		assert.Equal(t, tt.expected, result, "input: %q", tt.input)
	}
}

func TestLoadWordlistFile(t *testing.T) {
	tmpDir := t.TempDir()
	wlPath := filepath.Join(tmpDir, "words.txt")
	content := "www\nmail\n# skip comment\n  api  \n\n"
	err := os.WriteFile(wlPath, []byte(content), 0o600)
	require.NoError(t, err)

	words, err := loadWordlistFile(wlPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"www", "mail", "api"}, words)
}

func TestLoadWordlistFile_NotFound(t *testing.T) {
	_, err := loadWordlistFile("/nonexistent/path/words.txt")
	assert.Error(t, err)
}

// ============================================================================
// isRetryableDoHError tests
// ============================================================================

func TestIsRetryableDoHError(t *testing.T) {
	assert.True(t, isRetryableDoHError(&dohRateLimitError{msg: "rate limited"}))
	assert.True(t, isRetryableDoHError(&dohServerError{msg: "server error"}))
	assert.False(t, isRetryableDoHError(fmt.Errorf("generic error")))
}

// ============================================================================
// buildSwaggerBody test
// ============================================================================

func TestBuildSwaggerBody(t *testing.T) {
	body, err := buildSwaggerBody("https://cloudflare-dns.com/dns-query")
	require.NoError(t, err)
	assert.Contains(t, string(body), "https://cloudflare-dns.com/dns-query")
	// Verify it's valid JSON
	var raw map[string]any
	err = json.Unmarshal(body, &raw)
	require.NoError(t, err)
}
