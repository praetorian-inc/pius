package domains

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Accepts tests ---

func TestDNSDBPlugin_Accepts(t *testing.T) {
	original := os.Getenv("DNSDB_API_KEY")
	defer func() {
		if original == "" {
			os.Unsetenv("DNSDB_API_KEY")
		} else {
			os.Setenv("DNSDB_API_KEY", original)
		}
	}()

	p, ok := plugins.Get("dnsdb")
	require.True(t, ok, "dnsdb plugin should be registered")

	tests := []struct {
		name     string
		apiKey   string
		input    plugins.Input
		expected bool
	}{
		{
			name:   "accepts with API key and domains",
			apiKey: "test-key",
			input: plugins.Input{
				Domains: []string{"example.com"},
			},
			expected: true,
		},
		{
			name:   "rejects without API key",
			apiKey: "",
			input: plugins.Input{
				Domains: []string{"example.com"},
			},
			expected: false,
		},
		{
			name:   "rejects without domains",
			apiKey: "test-key",
			input:  plugins.Input{},
			expected: false,
		},
		{
			name:   "rejects with empty domains slice",
			apiKey: "test-key",
			input: plugins.Input{
				Domains: []string{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.apiKey == "" {
				os.Unsetenv("DNSDB_API_KEY")
			} else {
				os.Setenv("DNSDB_API_KEY", tt.apiKey)
			}
			assert.Equal(t, tt.expected, p.Accepts(tt.input))
		})
	}
}

func TestDNSDBPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("dnsdb")
	require.True(t, ok)

	assert.Equal(t, "dnsdb", p.Name())
	assert.Contains(t, p.Description(), "DNSDB")
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

// --- Domain parsing tests ---

func TestParseDomains(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []domainParts
	}{
		{
			name:  "simple domain",
			input: []string{"acme.com"},
			expected: []domainParts{
				{name: "acme", suffix: "com"},
			},
		},
		{
			name:  "multi-level TLD",
			input: []string{"acme.co.uk"},
			expected: []domainParts{
				{name: "acme", suffix: "co.uk"},
			},
		},
		{
			name:  "subdomain seed",
			input: []string{"sub.acme.com"},
			expected: []domainParts{
				{name: "sub.acme", suffix: "com"},
			},
		},
		{
			name:  "filters blacklisted domains",
			input: []string{"test.azurewebsites.net", "acme.com"},
			expected: []domainParts{
				{name: "acme", suffix: "com"},
			},
		},
		{
			name:  "filters exact blacklisted domain",
			input: []string{"amazonaws.com", "acme.com"},
			expected: []domainParts{
				{name: "acme", suffix: "com"},
			},
		},
		{
			name:     "skips empty strings",
			input:    []string{"", "  ", "acme.com"},
			expected: []domainParts{{name: "acme", suffix: "com"}},
		},
		{
			name:  "normalizes to lowercase",
			input: []string{"ACME.COM"},
			expected: []domainParts{
				{name: "acme", suffix: "com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDomains(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- Query building tests ---

func TestBuildQueries_SingleDomain(t *testing.T) {
	queries := buildQueries("https://api.dnsdb.info", []domainParts{
		{name: "acme", suffix: "com"},
	})

	require.Len(t, queries, 1)
	assert.Contains(t, queries[0].url, "/dnsdb/v2/regex/rrnames/")
	assert.Contains(t, queries[0].url, "acme")
	assert.Contains(t, queries[0].url, "com")
}

func TestBuildQueries_MultiTLD(t *testing.T) {
	queries := buildQueries("https://api.dnsdb.info", []domainParts{
		{name: "acme", suffix: "com"},
		{name: "acme", suffix: "org"},
		{name: "acme", suffix: "net"},
	})

	// All three TLDs share the same name → one domain-grouped query.
	require.Len(t, queries, 1)
	url := queries[0].url

	// Should be a domain-grouped regex: \.acme\.(com|org|net)
	assert.Contains(t, url, `\.acme\.`)
	// All three TLDs should appear in the alternation.
	for _, tld := range []string{"com", "org", "net"} {
		assert.Contains(t, url, tld)
	}
}

func TestBuildQueries_TLDGrouped(t *testing.T) {
	queries := buildQueries("https://api.dnsdb.info", []domainParts{
		{name: "alpha", suffix: "com"},
		{name: "beta", suffix: "com"},
	})

	require.Len(t, queries, 1)
	url := queries[0].url

	// Should be TLD-grouped: \.(alpha|beta)\.com
	assert.Contains(t, url, `\.com\.`)
	assert.Contains(t, url, "alpha")
	assert.Contains(t, url, "beta")
}

func TestBuildQueries_MixedGrouping(t *testing.T) {
	queries := buildQueries("https://api.dnsdb.info", []domainParts{
		{name: "acme", suffix: "com"},
		{name: "acme", suffix: "org"},  // acme is multi-TLD
		{name: "beta", suffix: "com"},  // beta is single-TLD
		{name: "gamma", suffix: "com"}, // gamma is single-TLD
	})

	// Should produce 2 queries: one domain-grouped (acme), one TLD-grouped (beta+gamma under com).
	require.Len(t, queries, 2)
}

func TestBuildQueries_BatchSplitting(t *testing.T) {
	// Create more items than the split threshold to force multiple batches.
	var parts []domainParts
	for i := 0; i < dnsdbSplitThreshold+10; i++ {
		parts = append(parts, domainParts{
			name:   fmt.Sprintf("domain%d", i),
			suffix: "com",
		})
	}

	queries := buildQueries("https://api.dnsdb.info", parts)

	// Should produce 2 batches for the TLD-grouped query.
	assert.Len(t, queries, 2)
}

func TestBuildQueries_EscapesDots(t *testing.T) {
	queries := buildQueries("https://api.dnsdb.info", []domainParts{
		{name: "sub.acme", suffix: "co.uk"},
	})

	require.Len(t, queries, 1)
	assert.Contains(t, queries[0].url, `sub\.acme`)
	assert.Contains(t, queries[0].url, `co\.uk`)
}

// --- NDJSON parsing tests ---

func TestParseNDJSON(t *testing.T) {
	ndjson := strings.Join([]string{
		`{"cond":"begin"}`,
		`{"obj":{"rrname":"api.acme.com.","rrtype":"A","rdata":["1.2.3.4"]}}`,
		`{"obj":{"rrname":"www.acme.com.","rrtype":"CNAME","rdata":["cdn.acme.com."]}}`,
		`{"obj":{"rrname":"ns1.acme.com.","rrtype":"NS","rdata":["dns1.example.com."]}}`,
		`{"obj":{"rrname":"acme.com.","rrtype":"SOA","rdata":["ns1.acme.com. admin.acme.com. 1 3600 600 86400 300"]}}`,
		`{"obj":{"rrname":"mail.acme.com.","rrtype":"MX","rdata":["10 mail.acme.com."]}}`,
		`{"cond":"limited","msg":"Results limited"}`,
	}, "\n")

	domains, err := parseNDJSON(strings.NewReader(ndjson))
	require.NoError(t, err)

	// A, CNAME, NS, SOA → 4 records; MX is excluded; begin/limited metadata is skipped.
	assert.Len(t, domains, 4)
	assert.Contains(t, domains, "api.acme.com")
	assert.Contains(t, domains, "www.acme.com")
	assert.Contains(t, domains, "ns1.acme.com")
	assert.Contains(t, domains, "acme.com")
}

func TestParseNDJSON_Deduplicates(t *testing.T) {
	ndjson := strings.Join([]string{
		`{"obj":{"rrname":"api.acme.com.","rrtype":"A","rdata":["1.2.3.4"]}}`,
		`{"obj":{"rrname":"api.acme.com.","rrtype":"A","rdata":["5.6.7.8"]}}`,
		`{"obj":{"rrname":"API.ACME.COM.","rrtype":"CNAME","rdata":["cdn.acme.com."]}}`,
	}, "\n")

	domains, err := parseNDJSON(strings.NewReader(ndjson))
	require.NoError(t, err)
	assert.Len(t, domains, 1, "duplicate rrnames should be deduplicated")
	assert.Equal(t, "api.acme.com", domains[0])
}

func TestParseNDJSON_EmptyInput(t *testing.T) {
	domains, err := parseNDJSON(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, domains)
}

func TestParseNDJSON_MalformedLines(t *testing.T) {
	ndjson := "not json\n{\"obj\":{\"rrname\":\"ok.acme.com.\",\"rrtype\":\"A\"}}\nbroken{"

	domains, err := parseNDJSON(strings.NewReader(ndjson))
	require.NoError(t, err)
	assert.Len(t, domains, 1)
	assert.Equal(t, "ok.acme.com", domains[0])
}

// --- Integration tests with httptest ---

func mockDNSDBServer(t *testing.T, responses map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify API key header.
		if r.Header.Get("X-API-Key") == "" {
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}

		// Return canned response based on URL path.
		for pattern, body := range responses {
			if strings.Contains(r.URL.Path, pattern) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, body)
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
}

func TestDNSDBPlugin_Run_SingleDomain(t *testing.T) {
	ndjson := strings.Join([]string{
		`{"cond":"begin"}`,
		`{"obj":{"rrname":"api.acme.com.","rrtype":"A","rdata":["1.2.3.4"]}}`,
		`{"obj":{"rrname":"www.acme.com.","rrtype":"A","rdata":["5.6.7.8"]}}`,
		`{"cond":"limited"}`,
	}, "\n")

	srv := mockDNSDBServer(t, map[string]string{
		"regex/rrnames": ndjson,
	})
	defer srv.Close()

	os.Setenv("DNSDB_API_KEY", "test-key")
	defer os.Unsetenv("DNSDB_API_KEY")

	p := &DNSDBPlugin{
		doer:    srv.Client(),
		baseURL: srv.URL,
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Domains: []string{"acme.com"},
	})

	require.NoError(t, err)
	require.Len(t, findings, 2)

	values := make(map[string]bool)
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "dnsdb", f.Source)
		values[f.Value] = true
	}
	assert.True(t, values["api.acme.com"])
	assert.True(t, values["www.acme.com"])
}

func TestDNSDBPlugin_Run_MultiTLD(t *testing.T) {
	ndjson := strings.Join([]string{
		`{"obj":{"rrname":"api.acme.com.","rrtype":"A","rdata":["1.2.3.4"]}}`,
		`{"obj":{"rrname":"api.acme.org.","rrtype":"A","rdata":["5.6.7.8"]}}`,
	}, "\n")

	srv := mockDNSDBServer(t, map[string]string{
		"regex/rrnames": ndjson,
	})
	defer srv.Close()

	os.Setenv("DNSDB_API_KEY", "test-key")
	defer os.Unsetenv("DNSDB_API_KEY")

	p := &DNSDBPlugin{
		doer:    srv.Client(),
		baseURL: srv.URL,
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Domains: []string{"acme.com", "acme.org"},
	})

	require.NoError(t, err)
	require.Len(t, findings, 2)

	values := make(map[string]bool)
	for _, f := range findings {
		values[f.Value] = true
	}
	assert.True(t, values["api.acme.com"])
	assert.True(t, values["api.acme.org"])
}

func TestDNSDBPlugin_Run_GracefulOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	os.Setenv("DNSDB_API_KEY", "test-key")
	defer os.Unsetenv("DNSDB_API_KEY")

	p := &DNSDBPlugin{
		doer:    srv.Client(),
		baseURL: srv.URL,
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Domains: []string{"acme.com"},
	})

	// Should not return an error — graceful degradation.
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDNSDBPlugin_Run_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow server — should be cancelled.
		select {}
	}))
	defer srv.Close()

	os.Setenv("DNSDB_API_KEY", "test-key")
	defer os.Unsetenv("DNSDB_API_KEY")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	p := &DNSDBPlugin{
		doer:    srv.Client(),
		baseURL: srv.URL,
	}

	findings, err := p.Run(ctx, plugins.Input{
		OrgName: "Acme Corp",
		Domains: []string{"acme.com"},
	})

	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, findings)
}

// --- Blacklist tests ---

func TestIsBlacklisted(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"test.azurewebsites.net", true},
		{"azurewebsites.net", true},
		{"sub.test.amazonaws.com", true},
		{"github.com", true},
		{"onmicrosoft.com", true},
		{"acme.com", false},
		{"example.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			assert.Equal(t, tt.expected, isBlacklisted(tt.domain))
		})
	}
}

// --- Helper tests ---

func TestUniqueStrings(t *testing.T) {
	assert.Equal(t, []string{"a", "b", "c"}, uniqueStrings([]string{"a", "b", "a", "c", "b"}))
}
