package domains_test

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

func TestCRTShPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("crt-sh")
	if !ok {
		t.Skip("crt-sh plugin not registered")
	}

	tests := []struct {
		name     string
		input    plugins.Input
		expected bool
	}{
		{
			name: "accepts with domain",
			input: plugins.Input{
				Domain: "example.com",
			},
			expected: true,
		},
		{
			name: "accepts with org name",
			input: plugins.Input{
				OrgName: "Acme Corp",
			},
			expected: true,
		},
		{
			name: "accepts with both domain and org",
			input: plugins.Input{
				Domain:  "example.com",
				OrgName: "Acme Corp",
			},
			expected: true,
		},
		{
			name: "rejects with neither domain nor org",
			input: plugins.Input{
				Email: "admin@example.com",
			},
			expected: false,
		},
		{
			name: "rejects with empty domain and empty org",
			input: plugins.Input{
				Domain:  "",
				OrgName: "",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Accepts(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCRTShPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("crt-sh")
	if !ok {
		t.Skip("crt-sh plugin not registered")
	}

	assert.Equal(t, "crt-sh", p.Name())
	assert.Contains(t, p.Description(), "crt.sh")
	assert.Contains(t, p.Description(), "Certificate Transparency")
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase(), "crt.sh is independent (phase 0)")
}

func TestCRTShPlugin_ParsesDomains(t *testing.T) {
	// Test documents expected crt.sh response parsing behavior:
	// - Parses JSON array of {name_value: string}
	// - Splits name_value on newlines (multiple domains per entry)
	// - Deduplicates domains
	// - Skips wildcard domains (*.example.com)
	// - Normalizes: lowercase, trim whitespace, remove trailing dot
	// - Returns Finding with Type=FindingDomain

	t.Skip("Requires HTTP client injection or httptest server integration")
}

func TestCRTShPlugin_DeduplicatesDomains(t *testing.T) {
	// Expected deduplication behavior:
	// - If "example.com" appears in multiple crt.sh entries:
	//   Only one Finding emitted
	// - If name_value contains "api.example.com\nexample.com":
	//   Both domains returned, but each only once

	t.Skip("Requires HTTP client injection")
}

func TestCRTShPlugin_SkipsWildcards(t *testing.T) {
	// Expected wildcard behavior:
	// - "*.example.com" should be skipped
	// - "*" should be skipped
	// - "mail.*.example.com" should be skipped
	// - Regular domains should be kept

	t.Skip("Requires HTTP client injection")
}

func TestCRTShPlugin_NormalizesDomains(t *testing.T) {
	// Expected normalization:
	// - "EXAMPLE.COM" → "example.com" (lowercase)
	// - "example.com." → "example.com" (trim trailing dot)
	// - "  example.com  " → "example.com" (trim whitespace)
	// - All normalizations applied before deduplication

	t.Skip("Requires HTTP client injection")
}

func TestCRTShPlugin_HandlesNetworkErrors(t *testing.T) {
	// Expected error handling:
	// - Rate limit: returns (nil, nil) - not critical
	// - Network error: returns (nil, nil) - not critical
	// - Invalid JSON: returns (nil, nil) - not critical
	// - Partial success: returns what was parsed

	t.Skip("Requires HTTP client injection")
}

func TestCRTShPlugin_PrefersDomainOverOrgName(t *testing.T) {
	// Expected query priority:
	// - If Domain is set: query by Domain
	// - If Domain empty but OrgName set: query by OrgName
	// - Query should be URL-encoded

	t.Skip("Requires HTTP client injection")
}

// Integration test example with httptest server
func TestCRTShPlugin_IntegrationWithMockServer(t *testing.T) {
	t.Skip("Example of integration test structure")

	// Mock crt.sh response:
	mockResponse := `[
		{"name_value": "api.example.com\nexample.com"},
		{"name_value": "*.example.com"},
		{"name_value": "mail.example.com"},
		{"name_value": "example.com"}
	]`

	_ = mockResponse

	// Expected results:
	// - "api.example.com" (from first entry split)
	// - "example.com" (from first entry split, deduplicated)
	// - "mail.example.com" (from third entry)
	// - NOT "*.example.com" (wildcard skipped)
	// - Total: 3 unique domains

	// Would verify:
	// - 3 findings returned
	// - Each has Type=FindingDomain
	// - Each has Source="crt-sh"
	// - Values are ["api.example.com", "example.com", "mail.example.com"]
	// - Finding.Data["query"] matches input
	// - Finding.Data["org"] matches input.OrgName
}
