package cidrs

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

func TestShodanPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("shodan")
	require.True(t, ok, "shodan plugin not registered")

	assert.Equal(t, "shodan", p.Name())
	assert.Contains(t, p.Description(), "Shodan")
	assert.Contains(t, p.Description(), "SHODAN_API_KEY")
	assert.Equal(t, "cidr", p.Category())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

func TestShodanPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("shodan")
	require.True(t, ok)

	tests := []struct {
		name     string
		apiKey   string
		input    plugins.Input
		expected bool
	}{
		{
			name:     "accepts with org and api key",
			apiKey:   "test-key",
			input:    plugins.Input{OrgName: "Acme Corp"},
			expected: true,
		},
		{
			name:     "accepts with domain and api key",
			apiKey:   "test-key",
			input:    plugins.Input{Domain: "example.com"},
			expected: true,
		},
		{
			name:     "accepts with ASN and api key",
			apiKey:   "test-key",
			input:    plugins.Input{ASN: "AS12345"},
			expected: true,
		},
		{
			name:     "rejects without api key",
			apiKey:   "",
			input:    plugins.Input{OrgName: "Acme Corp"},
			expected: false,
		},
		{
			name:     "rejects with api key but no input",
			apiKey:   "test-key",
			input:    plugins.Input{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.apiKey != "" {
				os.Setenv("SHODAN_API_KEY", tt.apiKey)
				defer os.Unsetenv("SHODAN_API_KEY")
			} else {
				os.Unsetenv("SHODAN_API_KEY")
			}

			got := p.Accepts(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestShodanPlugin_BuildQuery(t *testing.T) {
	p := &ShodanPlugin{}

	tests := []struct {
		name     string
		input    plugins.Input
		expected string
	}{
		{
			name:     "org only",
			input:    plugins.Input{OrgName: "Acme Corp"},
			expected: `org:"Acme Corp"`,
		},
		{
			name:     "domain only",
			input:    plugins.Input{Domain: "example.com"},
			expected: "hostname:example.com",
		},
		{
			name:     "ASN only with prefix",
			input:    plugins.Input{ASN: "AS12345"},
			expected: "asn:AS12345",
		},
		{
			name:     "ASN only without prefix",
			input:    plugins.Input{ASN: "12345"},
			expected: "asn:AS12345",
		},
		{
			name:     "all fields",
			input:    plugins.Input{OrgName: "Acme", ASN: "AS123", Domain: "acme.com"},
			expected: `org:"Acme" asn:AS123 hostname:acme.com`,
		},
		{
			name:     "empty input",
			input:    plugins.Input{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.buildQuery(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestShodanPlugin_Run(t *testing.T) {
	// Mock Shodan API response
	mockResponse := `{
		"matches": [
			{
				"ip_str": "192.0.2.1",
				"port": 443,
				"hostnames": ["www.example.com", "api.example.com"],
				"asn": "AS12345",
				"isp": "Example ISP"
			},
			{
				"ip_str": "192.0.2.2",
				"port": 22,
				"hostnames": [],
				"asn": "AS12345"
			}
		],
		"total": 2
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/shodan/host/search")
		assert.Contains(t, r.URL.RawQuery, "key=test-key")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(mockResponse))
	}))
	defer server.Close()

	os.Setenv("SHODAN_API_KEY", "test-key")
	defer os.Unsetenv("SHODAN_API_KEY")

	p := &ShodanPlugin{
		client:  client.New(),
		baseURL: server.URL,
	}

	input := plugins.Input{
		OrgName: "Example Corp",
		Domain:  "example.com",
	}

	findings, err := p.Run(context.Background(), input)
	require.NoError(t, err)

	// Should have 2 IPs + 2 hostnames = 4 findings
	assert.Len(t, findings, 4)

	// Check CIDR findings
	cidrFindings := filterFindings(findings, plugins.FindingCIDR)
	assert.Len(t, cidrFindings, 2)
	assert.Equal(t, "192.0.2.1/32", cidrFindings[0].Value)
	assert.Equal(t, "192.0.2.2/32", cidrFindings[1].Value)

	// Check domain findings
	domainFindings := filterFindings(findings, plugins.FindingDomain)
	assert.Len(t, domainFindings, 2)
	domains := []string{domainFindings[0].Value, domainFindings[1].Value}
	assert.Contains(t, domains, "www.example.com")
	assert.Contains(t, domains, "api.example.com")
}

func TestShodanPlugin_Run_NoAPIKey(t *testing.T) {
	os.Unsetenv("SHODAN_API_KEY")

	p := &ShodanPlugin{client: client.New()}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Test"})

	assert.NoError(t, err)
	assert.Nil(t, findings)
}

func TestShodanPlugin_Run_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	os.Setenv("SHODAN_API_KEY", "test-key")
	defer os.Unsetenv("SHODAN_API_KEY")

	p := &ShodanPlugin{
		client:  client.New(),
		baseURL: server.URL,
	}

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Test"})

	// Should gracefully degrade
	assert.NoError(t, err)
	assert.Nil(t, findings)
}

func filterFindings(findings []plugins.Finding, ft plugins.FindingType) []plugins.Finding {
	var result []plugins.Finding
	for _, f := range findings {
		if f.Type == ft {
			result = append(result, f)
		}
	}
	return result
}
