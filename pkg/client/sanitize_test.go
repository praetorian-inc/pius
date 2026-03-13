package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Internal tests for sanitizeURL function edge cases
func TestSanitizeURL_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		contains []string    // strings that MUST be in output
		excludes []string    // strings that MUST NOT be in output
	}{
		{
			name:     "basic key param",
			input:    "https://api.shodan.io/search?key=SECRET123&query=test",
			contains: []string{"REDACTED", "query=test"},
			excludes: []string{"SECRET123"},
		},
		{
			name:     "multiple sensitive params",
			input:    "https://api.example.com/search?key=KEY1&token=TOKEN2&query=test",
			contains: []string{"REDACTED", "query=test"},
			excludes: []string{"KEY1", "TOKEN2"},
		},
		{
			name:     "no sensitive params - preserved exactly",
			input:    "https://api.example.com/search?query=test&page=1",
			expected: "https://api.example.com/search?query=test&page=1",
		},
		{
			name:     "URL with fragment",
			input:    "https://api.example.com/search?key=SECRET#section",
			contains: []string{"REDACTED", "#section"},
			excludes: []string{"SECRET"},
		},
		{
			name:     "URL with port",
			input:    "https://api.example.com:8443/search?key=SECRET",
			contains: []string{"REDACTED", ":8443"},
			excludes: []string{"SECRET"},
		},
		{
			name:     "URL with no query params",
			input:    "https://api.example.com/search",
			expected: "https://api.example.com/search",
		},
		{
			name:     "URL with empty query",
			input:    "https://api.example.com/search?",
			expected: "https://api.example.com/search?",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "relative URL with key",
			input:    "/api/search?key=SECRET&q=test",
			contains: []string{"REDACTED", "q=test"},
			excludes: []string{"SECRET"},
		},
		{
			name:     "key param with special characters in value",
			input:    "https://api.example.com/search?key=abc%2B123%3D%3D&query=test",
			contains: []string{"REDACTED", "query=test"},
			excludes: []string{"abc%2B123"},
		},
		{
			name:     "apikey param (ViewDNS style)",
			input:    "https://viewdns.info/reverseip/?host=1.2.3.4&apikey=VIEWDNS_SECRET&output=json",
			contains: []string{"REDACTED", "host=1.2.3.4", "output=json"},
			excludes: []string{"VIEWDNS_SECRET"},
		},
		{
			name:     "access_token param (OAuth style)",
			input:    "https://api.example.com/me?access_token=OAUTH_SECRET&fields=id,name",
			contains: []string{"REDACTED", "fields=id"},
			excludes: []string{"OAUTH_SECRET"},
		},
		{
			name:     "case sensitivity - KEY vs key",
			input:    "https://api.example.com/search?KEY=UPPERCASE_SECRET&query=test",
			// KEY (uppercase) is NOT in our list, so should be preserved
			contains: []string{"KEY=UPPERCASE_SECRET", "query=test"},
		},
		{
			name:     "invalid URL returns marker",
			input:    "://invalid",
			expected: "[invalid URL]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeURL(tt.input)

			if tt.expected != "" {
				assert.Equal(t, tt.expected, result)
			}

			for _, s := range tt.contains {
				assert.Contains(t, result, s, "result should contain %q", s)
			}

			for _, s := range tt.excludes {
				assert.NotContains(t, result, s, "result should NOT contain %q", s)
			}
		})
	}
}

func TestSanitizeURL_PreservesURLStructure(t *testing.T) {
	// Test that non-sensitive parts of the URL are preserved exactly
	input := "https://user:pass@api.example.com:8443/v1/search?key=SECRET&query=org%3AAcme#results"
	result := sanitizeURL(input)

	// Should preserve:
	assert.Contains(t, result, "https://")
	assert.Contains(t, result, "user:pass@")
	assert.Contains(t, result, "api.example.com:8443")
	assert.Contains(t, result, "/v1/search")
	assert.Contains(t, result, "#results")
	assert.Contains(t, result, "query=org%3AAcme") // URL-encoded query preserved

	// Should redact:
	assert.NotContains(t, result, "SECRET")
	assert.Contains(t, result, "REDACTED")
}
