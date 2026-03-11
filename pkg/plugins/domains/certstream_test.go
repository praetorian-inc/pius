package domains

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

func TestCertstreamPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("certstream")
	if !ok {
		t.Fatal("certstream plugin not registered")
	}

	assert.Equal(t, "certstream", p.Name())
	assert.Contains(t, p.Description(), "CERTSTREAM")
	assert.Contains(t, p.Description(), "Certificate Transparency")
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase(), "certstream is independent (phase 0)")
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

func TestCertstreamPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("certstream")
	if !ok {
		t.Fatal("certstream plugin not registered")
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
			name: "rejects without domain",
			input: plugins.Input{
				OrgName: "Acme Corp",
			},
			expected: false,
		},
		{
			name: "rejects with empty domain",
			input: plugins.Input{
				Domain: "",
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

func TestCleanCertDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"*.example.com", "example.com"},
		{"example.com.", "example.com"},
		{"  example.com  ", "example.com"},
		{"*.SUB.EXAMPLE.COM.", "sub.example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanCertDomain(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		base     string
		expected bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"subdomain match", "sub.example.com", "example.com", true},
		{"deep subdomain", "a.b.c.example.com", "example.com", true},
		{"no match different domain", "example.org", "example.com", false},
		{"no match partial", "notexample.com", "example.com", false},
		{"no match suffix trick", "fakeexample.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesDomain(tt.domain, tt.base)
			assert.Equal(t, tt.expected, got)
		})
	}
}
