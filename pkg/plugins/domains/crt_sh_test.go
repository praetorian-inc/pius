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

// Integration test example with httptest server
