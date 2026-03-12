package domains

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReverseIPPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("reverse-ip")
	require.True(t, ok, "reverse-ip plugin not registered")

	assert.Equal(t, "reverse-ip", p.Name())
	assert.Contains(t, p.Description(), "Reverse IP")
	assert.Contains(t, p.Description(), "PTR")
	assert.Contains(t, p.Description(), "HackerTarget")
	assert.Contains(t, p.Description(), "ViewDNS")
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 3, p.Phase()) // Phase 3: consumes CIDRs from Phase 2
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

func TestReverseIPPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("reverse-ip")
	require.True(t, ok)

	tests := []struct {
		name     string
		input    plugins.Input
		expected bool
	}{
		{
			name: "accepts with CIDRs in Meta",
			input: plugins.Input{
				OrgName: "Acme Corp",
				Meta:    map[string]string{"cidrs": "192.0.2.0/24"},
			},
			expected: true,
		},
		{
			name: "accepts with multiple CIDRs",
			input: plugins.Input{
				OrgName: "Acme Corp",
				Meta:    map[string]string{"cidrs": "192.0.2.0/24,198.51.100.0/24"},
			},
			expected: true,
		},
		{
			name:     "rejects without Meta",
			input:    plugins.Input{OrgName: "Acme Corp"},
			expected: false,
		},
		{
			name: "rejects with empty CIDRs",
			input: plugins.Input{
				OrgName: "Acme Corp",
				Meta:    map[string]string{"cidrs": ""},
			},
			expected: false,
		},
		{
			name: "rejects with nil Meta",
			input: plugins.Input{
				OrgName: "Acme Corp",
				Meta:    nil,
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

func TestReverseIPPlugin_HackerTargetLookup(t *testing.T) {
	// Mock HackerTarget API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/reverseiplookup/")
		ip := r.URL.Query().Get("q")
		if ip == "192.0.2.1" {
			w.Write([]byte("www.example.com\napi.example.com\nmail.example.com"))
		} else if ip == "192.0.2.99" {
			w.Write([]byte("API count exceeded - 100 per day"))
		} else {
			w.Write([]byte(""))
		}
	}))
	defer server.Close()

	p := &ReverseIPPlugin{
		client:  client.New(),
		baseURL: server.URL,
	}

	t.Run("successful lookup", func(t *testing.T) {
		hosts := p.hackerTargetLookup(context.Background(), "192.0.2.1")
		assert.Len(t, hosts, 3)
		assert.Contains(t, hosts, "www.example.com")
		assert.Contains(t, hosts, "api.example.com")
		assert.Contains(t, hosts, "mail.example.com")
	})

	t.Run("API rate limit", func(t *testing.T) {
		hosts := p.hackerTargetLookup(context.Background(), "192.0.2.99")
		assert.Empty(t, hosts)
	})

	t.Run("no results", func(t *testing.T) {
		hosts := p.hackerTargetLookup(context.Background(), "192.0.2.50")
		assert.Empty(t, hosts)
	})

	t.Run("invalid IP", func(t *testing.T) {
		hosts := p.hackerTargetLookup(context.Background(), "not-an-ip")
		assert.Empty(t, hosts)
	})
}

func TestReverseIPPlugin_HackerTargetResponseParsing(t *testing.T) {
	tests := []struct {
		name     string
		response string
		expected []string
	}{
		{
			name:     "simple hostnames",
			response: "www.example.com\napi.example.com",
			expected: []string{"www.example.com", "api.example.com"},
		},
		{
			name:     "with empty lines",
			response: "www.example.com\n\napi.example.com\n",
			expected: []string{"www.example.com", "api.example.com"},
		},
		{
			name:     "error message",
			response: "error invalid input",
			expected: nil,
		},
		{
			name:     "API limit message",
			response: "API count exceeded - 100 per day",
			expected: nil,
		},
		{
			name:     "mixed valid and invalid",
			response: "www.example.com\nerror message\napi.example.com",
			expected: []string{"www.example.com", "api.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			p := &ReverseIPPlugin{
				client:  client.New(),
				baseURL: server.URL,
			}

			hosts := p.hackerTargetLookup(context.Background(), "192.0.2.1")
			assert.Equal(t, tt.expected, hosts)
		})
	}
}

func TestReverseIPPlugin_ViewDNSLookup(t *testing.T) {
	// Mock ViewDNS API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/reverseip/")
		ip := r.URL.Query().Get("host")
		apiKey := r.URL.Query().Get("apikey")

		// Check API key is passed
		assert.NotEmpty(t, apiKey)

		if ip == "192.0.2.1" {
			w.Write([]byte(`{
				"query": {"tool": "reverseip_PRO", "host": "192.0.2.1"},
				"response": {
					"domain_count": "3",
					"domains": [
						{"name": "www.example.com", "last_resolved": "2024-06-19"},
						{"name": "api.example.com", "last_resolved": "2024-06-19"},
						{"name": "mail.example.com", "last_resolved": "2024-06-19"}
					]
				}
			}`))
		} else if ip == "192.0.2.99" {
			// Empty result
			w.Write([]byte(`{
				"query": {"tool": "reverseip_PRO", "host": "192.0.2.99"},
				"response": {
					"domain_count": "0",
					"domains": []
				}
			}`))
		} else {
			w.Write([]byte(`{"error": "invalid request"}`))
		}
	}))
	defer server.Close()

	p := &ReverseIPPlugin{
		client:     client.New(),
		viewDNSURL: server.URL,
	}

	t.Run("successful lookup", func(t *testing.T) {
		hosts := p.viewDNSLookup(context.Background(), "192.0.2.1", "test-api-key")
		assert.Len(t, hosts, 3)
		assert.Contains(t, hosts, "www.example.com")
		assert.Contains(t, hosts, "api.example.com")
		assert.Contains(t, hosts, "mail.example.com")
	})

	t.Run("no results", func(t *testing.T) {
		hosts := p.viewDNSLookup(context.Background(), "192.0.2.99", "test-api-key")
		assert.Empty(t, hosts)
	})

	t.Run("invalid IP", func(t *testing.T) {
		hosts := p.viewDNSLookup(context.Background(), "not-an-ip", "test-api-key")
		assert.Empty(t, hosts)
	})
}

func TestReverseIPPlugin_ViewDNSResponseParsing(t *testing.T) {
	tests := []struct {
		name     string
		response string
		expected []string
	}{
		{
			name: "valid response with domains",
			response: `{
				"response": {
					"domain_count": "2",
					"domains": [
						{"name": "www.example.com", "last_resolved": "2024-06-19"},
						{"name": "api.example.com", "last_resolved": "2024-06-19"}
					]
				}
			}`,
			expected: []string{"www.example.com", "api.example.com"},
		},
		{
			name: "empty domains array",
			response: `{
				"response": {
					"domain_count": "0",
					"domains": []
				}
			}`,
			expected: nil,
		},
		{
			name:     "invalid JSON",
			response: "not valid json",
			expected: nil,
		},
		{
			name: "domains with empty names filtered",
			response: `{
				"response": {
					"domain_count": "3",
					"domains": [
						{"name": "www.example.com", "last_resolved": "2024-06-19"},
						{"name": "", "last_resolved": "2024-06-19"},
						{"name": "api.example.com", "last_resolved": "2024-06-19"}
					]
				}
			}`,
			expected: []string{"www.example.com", "api.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			p := &ReverseIPPlugin{
				client:     client.New(),
				viewDNSURL: server.URL,
			}

			hosts := p.viewDNSLookup(context.Background(), "192.0.2.1", "test-api-key")
			assert.Equal(t, tt.expected, hosts)
		})
	}
}

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		maxIPs   int
		expected int // expected number of IPs
	}{
		{
			name:     "single IP /32",
			cidr:     "192.0.2.1/32",
			maxIPs:   256,
			expected: 1,
		},
		{
			name:     "small /30",
			cidr:     "192.0.2.0/30",
			maxIPs:   256,
			expected: 4,
		},
		{
			name:     "full /24",
			cidr:     "192.0.2.0/24",
			maxIPs:   256,
			expected: 256,
		},
		{
			name:     "capped /16",
			cidr:     "192.0.0.0/16",
			maxIPs:   256,
			expected: 256, // capped at maxIPs
		},
		{
			name:     "bare IP without prefix",
			cidr:     "192.0.2.1",
			maxIPs:   256,
			expected: 1,
		},
		{
			name:     "invalid CIDR",
			cidr:     "not-a-cidr",
			maxIPs:   256,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := expandCIDR(tt.cidr, tt.maxIPs)
			assert.Len(t, ips, tt.expected)
		})
	}
}

func TestIsKnownCDN(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Cloudflare IPs
		{name: "cloudflare 104.16.x.x", ip: "104.16.1.1", expected: true},
		{name: "cloudflare 172.67.x.x", ip: "172.67.43.196", expected: true},
		{name: "cloudflare 172.64.x.x", ip: "172.64.1.1", expected: true},
		// Fastly IPs
		{name: "fastly 151.101.x.x", ip: "151.101.1.1", expected: true},
		// Akamai IPs
		{name: "akamai 23.32.x.x", ip: "23.32.1.1", expected: true},
		// AWS CloudFront
		{name: "cloudfront 13.32.x.x", ip: "13.32.1.1", expected: true},
		// Non-CDN IPs
		{name: "regular IP", ip: "192.0.2.1", expected: false},
		{name: "private IP", ip: "10.0.0.1", expected: false},
		{name: "google dns", ip: "8.8.8.8", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isKnownCDN(tt.ip)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCalculateConfidence(t *testing.T) {
	tests := []struct {
		name       string
		hostname   string
		baseDomain string
		orgName    string
		isCDN      bool
		expected   float64
	}{
		// Non-CDN, matching domain
		{
			name:       "exact domain match on non-CDN",
			hostname:   "example.com",
			baseDomain: "example.com",
			orgName:    "Example Inc",
			isCDN:      false,
			expected:   0.85,
		},
		{
			name:       "subdomain match on non-CDN",
			hostname:   "www.example.com",
			baseDomain: "example.com",
			orgName:    "Example Inc",
			isCDN:      false,
			expected:   0.85,
		},
		// Non-CDN, org name match
		{
			name:       "org name in hostname",
			hostname:   "mail.exampleinc.net",
			baseDomain: "example.com",
			orgName:    "Example Inc",
			isCDN:      false,
			expected:   0.70,
		},
		// Non-CDN, no match
		{
			name:       "no match on non-CDN",
			hostname:   "unrelated.net",
			baseDomain: "example.com",
			orgName:    "Example Inc",
			isCDN:      false,
			expected:   0.55,
		},
		// CDN IP, matching domain
		{
			name:       "matching domain on CDN",
			hostname:   "www.example.com",
			baseDomain: "example.com",
			orgName:    "Example Inc",
			isCDN:      true,
			expected:   0.55,
		},
		// CDN IP, no match
		{
			name:       "no match on CDN",
			hostname:   "unrelated.net",
			baseDomain: "example.com",
			orgName:    "Example Inc",
			isCDN:      true,
			expected:   0.25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateConfidence(tt.hostname, tt.baseDomain, tt.orgName, tt.isCDN)
			assert.Equal(t, tt.expected, got)
		})
	}
}
