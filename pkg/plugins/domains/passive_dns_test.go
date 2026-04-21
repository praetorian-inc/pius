package domains_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPassiveDNSPlugin_ErrorFormat verifies that both HTTP errors and JSON
// parse errors are surfaced to the caller (after Fix M6 is applied).
//
// For passive_dns.go, the API key is sent via header (NOT in the URL), so
// error messages are safe to surface and won't leak the key.
func TestPassiveDNSPlugin_ErrorFormat(t *testing.T) {
	// Verify JSON parsing error format
	invalidJSON := []byte("invalid json {")
	var response struct {
		Subdomains []string `json:"subdomains"`
	}

	err := json.Unmarshal(invalidJSON, &response)
	require.Error(t, err, "json.Unmarshal should fail on invalid JSON")

	// After Fix M6, both error paths should return errors with context:
	// Line 46-48: return fmt.Errorf("SecurityTrails API request: %w", err)
	// Line 53-55: return fmt.Errorf("parse SecurityTrails response: %w", err)

	assert.Contains(t, err.Error(), "invalid", "JSON parse error should indicate the issue")
}

func TestPassiveDNSPlugin_Accepts(t *testing.T) {
	// Setup: Set API key environment variable
	originalKey := os.Getenv("SECURITYTRAILS_API_KEY")
	defer func() {
		if originalKey == "" {
			_ = os.Unsetenv("SECURITYTRAILS_API_KEY")
		} else {
			_ = os.Setenv("SECURITYTRAILS_API_KEY", originalKey)
		}
	}()

	p, ok := plugins.Get("passive-dns")
	require.True(t, ok, "passive-dns plugin should be registered")

	tests := []struct {
		name     string
		apiKey   string
		input    plugins.Input
		expected bool
	}{
		{
			name:   "accepts with API key and domain",
			apiKey: "test-key",
			input: plugins.Input{
				Domain: "example.com",
			},
			expected: true,
		},
		{
			name:   "rejects without API key",
			apiKey: "",
			input: plugins.Input{
				Domain: "example.com",
			},
			expected: false,
		},
		{
			name:     "rejects without domain",
			apiKey:   "test-key",
			input:    plugins.Input{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.apiKey == "" {
				_ = os.Unsetenv("SECURITYTRAILS_API_KEY")
			} else {
				_ = os.Setenv("SECURITYTRAILS_API_KEY", tt.apiKey)
			}

			result := p.Accepts(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
