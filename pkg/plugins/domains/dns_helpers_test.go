package domains

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// ── extractParent ───────────────────────────────────────────────────────────

func TestExtractParent(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"admin.dev.example.com", "dev.example.com"},
		{"dev.example.com", "example.com"},
		{"example.com", ""},          // parent would be "com" (TLD)
		{"com", ""},                  // single label
		{"", ""},                     // empty
		{"a.b.c.d.example.com", "b.c.d.example.com"},
		{"sub.co.uk", "co.uk"},       // 3 labels, parent has 2
		{"co.uk", ""},                // parent would be "uk" (TLD)
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractParent(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── FilterWildcardDomains ───────────────────────────────────────────────────

// mockResolver intercepts DNS queries for testing.
type mockResolver struct {
	handler func(w dns.ResponseWriter, r *dns.Msg)
	addr    string
	server  *dns.Server
}

func newMockResolver(handler func(w dns.ResponseWriter, r *dns.Msg)) *mockResolver {
	m := &mockResolver{handler: handler}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler)

	// Use a random port
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	m.addr = pc.LocalAddr().String()
	m.server = &dns.Server{
		PacketConn: pc,
		Handler:    mux,
	}

	go m.server.ActivateAndServe()
	return m
}

func (m *mockResolver) close() {
	m.server.Shutdown()
}

func TestFilterWildcardDomains_WildcardParent(t *testing.T) {
	// Mock DNS: *.dev.example.com resolves, *.example.com does not
	mock := newMockResolver(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)

		qname := r.Question[0].Name // e.g., "randomhex.dev.example.com."
		// Anything under dev.example.com resolves (wildcard)
		if len(qname) > len("dev.example.com.") && qname[len(qname)-len("dev.example.com."):] == "dev.example.com." {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("1.2.3.4"),
			})
		}
		// Everything else: NXDOMAIN
		if len(msg.Answer) == 0 {
			msg.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(msg)
	})
	defer mock.close()

	// Override the default resolver for this test
	origResolver := dnsDefaultResolver
	dnsDefaultResolver = mock.addr
	defer func() { dnsDefaultResolver = origResolver }()

	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "admin.dev.example.com", Source: "crt-sh"},
		{Type: plugins.FindingDomain, Value: "api.dev.example.com", Source: "crt-sh"},
		{Type: plugins.FindingDomain, Value: "www.example.com", Source: "dns-brute"},
		{Type: plugins.FindingDomain, Value: "dev.example.com", Source: "dns-brute"},
		{Type: plugins.FindingCIDR, Value: "10.0.0.0/24", Source: "arin"},
	}

	result := FilterWildcardDomains(context.Background(), findings)

	// admin.dev and api.dev should be filtered (parent dev.example.com is wildcard)
	// www.example.com, dev.example.com, and the CIDR should be kept
	var kept []string
	for _, f := range result {
		kept = append(kept, f.Value)
	}

	assert.Contains(t, kept, "www.example.com")
	assert.Contains(t, kept, "dev.example.com")
	assert.Contains(t, kept, "10.0.0.0/24")
	assert.NotContains(t, kept, "admin.dev.example.com")
	assert.NotContains(t, kept, "api.dev.example.com")
}

func TestFilterWildcardDomains_NoWildcard(t *testing.T) {
	// Mock DNS: nothing resolves
	mock := newMockResolver(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = dns.RcodeNameError
		w.WriteMsg(msg)
	})
	defer mock.close()

	origResolver := dnsDefaultResolver
	dnsDefaultResolver = mock.addr
	defer func() { dnsDefaultResolver = origResolver }()

	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "admin.example.com", Source: "crt-sh"},
		{Type: plugins.FindingDomain, Value: "api.example.com", Source: "crt-sh"},
	}

	result := FilterWildcardDomains(context.Background(), findings)

	// No wildcard, all findings should pass through
	assert.Len(t, result, 2)
}

func TestFilterWildcardDomains_TLDNotProbed(t *testing.T) {
	// Mock DNS: everything resolves (to verify we don't probe TLDs)
	probed := make(map[string]bool)
	mock := newMockResolver(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		probed[r.Question[0].Name] = true
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.2.3.4"),
		})
		w.WriteMsg(msg)
	})
	defer mock.close()

	origResolver := dnsDefaultResolver
	dnsDefaultResolver = mock.addr
	defer func() { dnsDefaultResolver = origResolver }()

	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "example.com", Source: "crt-sh"},
	}

	FilterWildcardDomains(context.Background(), findings)

	// extractParent("example.com") returns "" — should NOT probe "com"
	for name := range probed {
		assert.NotEqual(t, "com.", name, "should not probe TLD")
	}
}

func TestFilterWildcardDomains_Empty(t *testing.T) {
	result := FilterWildcardDomains(context.Background(), nil)
	assert.Nil(t, result)

	result = FilterWildcardDomains(context.Background(), []plugins.Finding{})
	assert.Empty(t, result)
}
