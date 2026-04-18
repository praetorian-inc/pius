package domains

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Interface ────────────────────────────────────────────────────────────────

func TestDNSPermutationPlugin_Interface(t *testing.T) {
	p := &DNSPermutationPlugin{}
	assert.Equal(t, "dns-permutation", p.Name())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 3, p.Phase())
	assert.Equal(t, plugins.ModeActive, p.Mode())
	assert.NotEmpty(t, p.Description())
}

func TestDNSPermutationPlugin_Accepts(t *testing.T) {
	p := &DNSPermutationPlugin{}

	// Requires discovered_domains in Meta
	assert.True(t, p.Accepts(plugins.Input{
		Meta: map[string]string{"discovered_domains": "api.example.com"},
	}))
	assert.False(t, p.Accepts(plugins.Input{
		Meta: map[string]string{},
	}))
	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "example.com"}))
}

// ── extractLabels ────────────────────────────────────────────────────────────

func TestExtractLabels(t *testing.T) {
	tests := []struct {
		name   string
		fqdn   string
		base   string
		expect []string
	}{
		{"single label", "api.example.com", "example.com", []string{"api"}},
		{"multi label", "api.v1.example.com", "example.com", []string{"api", "v1"}},
		{"deep nesting", "a.b.c.example.com", "example.com", []string{"a", "b", "c"}},
		{"base only", "example.com", "example.com", nil},
		{"different base", "api.other.com", "example.com", nil},
		{"case insensitive", "API.Example.COM", "example.com", []string{"api"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLabels(tt.fqdn, tt.base)
			assert.Equal(t, tt.expect, got)
		})
	}
}

// ── guessBaseDomain ──────────────────────────────────────────────────────────

func TestGuessBaseDomain(t *testing.T) {
	assert.Equal(t, "example.com", guessBaseDomain("api.example.com"))
	assert.Equal(t, "example.com", guessBaseDomain("a.b.c.example.com"))
	assert.Equal(t, "example.com", guessBaseDomain("example.com"))
	assert.Equal(t, "localhost", guessBaseDomain("localhost"))
}

// ── joinFQDN ─────────────────────────────────────────────────────────────────

func TestJoinFQDN(t *testing.T) {
	assert.Equal(t, "api.v1.example.com", joinFQDN([]string{"api", "v1"}, "example.com"))
	assert.Equal(t, "dev.example.com", joinFQDN([]string{"dev"}, "example.com"))

	// Invalid: empty label
	assert.Equal(t, "", joinFQDN([]string{""}, "example.com"))
	assert.Equal(t, "", joinFQDN([]string{"api", ""}, "example.com"))

	// Invalid: leading/trailing dash
	assert.Equal(t, "", joinFQDN([]string{"-api"}, "example.com"))
	assert.Equal(t, "", joinFQDN([]string{"api-"}, "example.com"))
}

// ── splitDomains ─────────────────────────────────────────────────────────────

func TestSplitDomains(t *testing.T) {
	assert.Equal(t, []string{"a.com", "b.com"}, splitDomains("a.com,b.com"))
	assert.Equal(t, []string{"a.com"}, splitDomains("a.com"))
	assert.Nil(t, splitDomains(""))
	assert.Equal(t, []string{"a.com", "b.com"}, splitDomains(" a.com , b.com "))
}

// ── groupByBaseDomain ────────────────────────────────────────────────────────

func TestGroupByBaseDomain(t *testing.T) {
	domains := []string{
		"api.example.com",
		"mail.example.com",
		"api.other.com",
	}
	groups := groupByBaseDomain(domains)
	assert.Len(t, groups, 2)
	assert.ElementsMatch(t, []string{"api.example.com", "mail.example.com"}, groups["example.com"])
	assert.ElementsMatch(t, []string{"api.other.com"}, groups["other.com"])
}

// ── Permutation strategies ───────────────────────────────────────────────────

func TestDashConcat(t *testing.T) {
	p := &DNSPermutationPlugin{wordlist: []string{"dev", "prod"}}
	labels := []string{"api"}
	base := "example.com"
	candidates := p.dashConcat(labels, base)

	assert.Contains(t, candidates, "api-dev.example.com")
	assert.Contains(t, candidates, "dev-api.example.com")
	assert.Contains(t, candidates, "api-prod.example.com")
	assert.Contains(t, candidates, "prod-api.example.com")
	assert.Len(t, candidates, 4)
}

func TestDashConcat_MultiLabel(t *testing.T) {
	p := &DNSPermutationPlugin{wordlist: []string{"dev"}}
	labels := []string{"api", "v1"}
	base := "example.com"
	candidates := p.dashConcat(labels, base)

	assert.Contains(t, candidates, "api-dev.v1.example.com")
	assert.Contains(t, candidates, "dev-api.v1.example.com")
	assert.Contains(t, candidates, "api.v1-dev.example.com")
	assert.Contains(t, candidates, "api.dev-v1.example.com")
	assert.Len(t, candidates, 4)
}

func TestDirectConcat(t *testing.T) {
	p := &DNSPermutationPlugin{wordlist: []string{"dev", "prod"}}
	labels := []string{"api"}
	base := "example.com"
	candidates := p.directConcat(labels, base)

	assert.Contains(t, candidates, "apidev.example.com")
	assert.Contains(t, candidates, "devapi.example.com")
	assert.Contains(t, candidates, "apiprod.example.com")
	assert.Contains(t, candidates, "prodapi.example.com")
	assert.Len(t, candidates, 4)
}

func TestInsertWord(t *testing.T) {
	p := &DNSPermutationPlugin{wordlist: []string{"dev"}}
	labels := []string{"api", "v1"}
	base := "example.com"
	candidates := p.insertWord(labels, base)

	// Insert at index 0: dev.api.v1.example.com
	// Insert at index 1: api.dev.v1.example.com
	// Insert at index 2: api.v1.dev.example.com
	assert.Contains(t, candidates, "dev.api.v1.example.com")
	assert.Contains(t, candidates, "api.dev.v1.example.com")
	assert.Contains(t, candidates, "api.v1.dev.example.com")
	assert.Len(t, candidates, 3)
}

func TestNumberSuffix(t *testing.T) {
	labels := []string{"api"}
	base := "example.com"
	candidates := numberSuffix(labels, base)

	// 10 digits × 2 variants (dash, no-dash) × 1 label = 20
	assert.Len(t, candidates, 20)

	assert.Contains(t, candidates, "api-0.example.com")
	assert.Contains(t, candidates, "api0.example.com")
	assert.Contains(t, candidates, "api-9.example.com")
	assert.Contains(t, candidates, "api9.example.com")
}

func TestNumberSuffix_MultiLabel(t *testing.T) {
	labels := []string{"api", "v1"}
	base := "example.com"
	candidates := numberSuffix(labels, base)

	// 10 digits × 2 variants × 2 labels = 40
	assert.Len(t, candidates, 40)
	assert.Contains(t, candidates, "api-1.v1.example.com")
	assert.Contains(t, candidates, "api.v1-1.example.com")
}

// ── generateCandidates ───────────────────────────────────────────────────────

func TestGenerateCandidates_Dedup(t *testing.T) {
	p := &DNSPermutationPlugin{wordlist: []string{"dev"}}
	seeds := []string{"api.example.com"}
	candidates := p.generateCandidates(seeds, "example.com")

	// Should have dash, direct, insert, and number strategies combined
	assert.NotEmpty(t, candidates)
	assert.Contains(t, candidates, "api-dev.example.com")
	assert.Contains(t, candidates, "apidev.example.com")
	assert.Contains(t, candidates, "dev.api.example.com")
	assert.Contains(t, candidates, "api-0.example.com")
}

func TestGenerateCandidates_SkipsBaseOnly(t *testing.T) {
	p := &DNSPermutationPlugin{wordlist: []string{"dev"}}
	// example.com has no subdomain labels relative to base
	seeds := []string{"example.com"}
	candidates := p.generateCandidates(seeds, "example.com")
	assert.Empty(t, candidates)
}

// ── isWildcardMatch ──────────────────────────────────────────────────────────

func TestIsWildcardMatch(t *testing.T) {
	wildcardIPs := map[string]bool{"1.2.3.4": true}

	assert.True(t, isWildcardMatch([]string{"1.2.3.4"}, wildcardIPs))
	assert.False(t, isWildcardMatch([]string{"5.6.7.8"}, wildcardIPs))
	assert.False(t, isWildcardMatch([]string{"1.2.3.4", "5.6.7.8"}, wildcardIPs))
	assert.False(t, isWildcardMatch([]string{"1.2.3.4"}, nil))
	assert.False(t, isWildcardMatch([]string{"1.2.3.4"}, map[string]bool{}))
}

// ── Full integration: Run with mock DNS ──────────────────────────────────────

func TestDNSPermutationPlugin_Run(t *testing.T) {
	// Start a local DNS server that resolves dev-api.example.com but nothing else
	serveMux := dns.NewServeMux()
	serveMux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			name := q.Name
			if name == "dev-api.example.com." && q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("10.0.0.1"),
				})
			} else {
				m.Rcode = dns.RcodeNameError
			}
		}
		_ = w.WriteMsg(m)
	})
	// Handle wildcard check (random subdomain) → NXDOMAIN
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: serveMux}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ListenAndServe() }()
	defer func() { _ = server.Shutdown() }()
	<-started

	p := &DNSPermutationPlugin{
		resolver: server.PacketConn.LocalAddr().String(),
		wordlist: []string{"dev"},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{
			"discovered_domains": "api.example.com",
		},
	})
	require.NoError(t, err)

	// Should discover dev-api.example.com
	found := false
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "dns-permutation", f.Source)
		if f.Value == "dev-api.example.com" {
			found = true
		}
	}
	assert.True(t, found, "should find dev-api.example.com")
}

func TestDNSPermutationPlugin_Run_NoMatch(t *testing.T) {
	// DNS server that returns NXDOMAIN for everything
	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: serveMux}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ListenAndServe() }()
	defer func() { _ = server.Shutdown() }()
	<-started

	p := &DNSPermutationPlugin{
		resolver: server.PacketConn.LocalAddr().String(),
		wordlist: []string{"dev", "staging"},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{
			"discovered_domains": "api.example.com",
		},
	})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDNSPermutationPlugin_Run_WildcardFiltering(t *testing.T) {
	// DNS server that resolves EVERYTHING to 1.2.3.4 (wildcard)
	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("1.2.3.4"),
				})
			}
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: serveMux}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ListenAndServe() }()
	defer func() { _ = server.Shutdown() }()
	<-started

	p := &DNSPermutationPlugin{
		resolver: server.PacketConn.LocalAddr().String(),
		wordlist: []string{"dev", "staging"},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{
			"discovered_domains": "api.example.com",
		},
	})
	require.NoError(t, err)
	assert.Empty(t, findings, "all results should be filtered as wildcard matches")
}

func TestDNSPermutationPlugin_Run_EmptySeeds(t *testing.T) {
	p := &DNSPermutationPlugin{wordlist: []string{"dev"}}
	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"discovered_domains": ""},
	})
	require.NoError(t, err)
	assert.Nil(t, findings)
}

func TestDNSPermutationPlugin_Run_ExcludesSeeds(t *testing.T) {
	// DNS server that resolves api.example.com and dev-api.example.com
	serveMux := dns.NewServeMux()
	serveMux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("10.0.0.1"),
				})
			}
		}
		_ = w.WriteMsg(m)
	})
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: serveMux}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ListenAndServe() }()
	defer func() { _ = server.Shutdown() }()
	<-started

	p := &DNSPermutationPlugin{
		resolver: server.PacketConn.LocalAddr().String(),
		wordlist: []string{"dev"},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{
			"discovered_domains": "api.example.com",
		},
	})
	require.NoError(t, err)

	// The seed domain "api.example.com" itself should NOT appear in findings
	for _, f := range findings {
		assert.NotEqual(t, "api.example.com", f.Value, "seed domain should be excluded from results")
	}
}

// ── Embedded wordlist ────────────────────────────────────────────────────────

func TestDefaultPermutationWordlist_Loaded(t *testing.T) {
	words := parseWordlist(defaultPermutationWordlist)
	assert.True(t, len(words) > 200, "permutation wordlist should have 200+ words, got %d", len(words))

	// Spot-check a few expected words
	wordSet := make(map[string]bool)
	for _, w := range words {
		wordSet[w] = true
	}
	assert.True(t, wordSet["dev"], "should contain 'dev'")
	assert.True(t, wordSet["staging"], "should contain 'staging'")
	assert.True(t, wordSet["api"], "should contain 'api'")
	assert.True(t, wordSet["prod"], "should contain 'prod'")
	assert.True(t, wordSet["internal"], "should contain 'internal'")
}

// ── Plugin registration ──────────────────────────────────────────────────────

func TestDNSPermutationPlugin_Registered(t *testing.T) {
	p, ok := plugins.Get("dns-permutation")
	require.True(t, ok, "dns-permutation should be registered")
	assert.Equal(t, "dns-permutation", p.Name())
	assert.Equal(t, 3, p.Phase())
	assert.Equal(t, plugins.ModeActive, p.Mode())
}
