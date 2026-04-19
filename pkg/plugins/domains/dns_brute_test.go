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

func TestDNSBrutePlugin_Interface(t *testing.T) {
	p := &DNSBrutePlugin{}
	assert.Equal(t, "dns-brute", p.Name())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, plugins.ModeActive, p.Mode())
}

func TestDNSBrutePlugin_Accepts(t *testing.T) {
	p := &DNSBrutePlugin{}

	// Requires Domain
	assert.True(t, p.Accepts(plugins.Input{Domain: "example.com"}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Example Inc"}))
	assert.False(t, p.Accepts(plugins.Input{}))
}

func TestParseWordlist(t *testing.T) {
	raw := "www\n  mail  \n\n# comment\napi\n"
	words := parseWordlist(raw)
	assert.Equal(t, []string{"www", "mail", "api"}, words)
}

func TestDNSBrutePlugin_Run_NoMatch(t *testing.T) {
	// Start a local DNS server that returns NXDOMAIN for all queries
	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError // NXDOMAIN
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{
		Addr:    "127.0.0.1:0",
		Net:     "udp",
		Handler: serveMux,
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }

	go func() { _ = server.ListenAndServe() }()
	defer func() { _ = server.Shutdown() }()
	<-started

	p := &DNSBrutePlugin{
		resolver: server.PacketConn.LocalAddr().String(),
		wordlist: []string{"www", "mail", "api"},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "nonexistent.example.com",
	})

	require.NoError(t, err)
	assert.Empty(t, findings, "should return empty findings when no subdomains resolve")
}

func TestDNSBrutePlugin_Run_WildcardSkip(t *testing.T) {
	// DNS server that resolves EVERYTHING to 1.2.3.4 (wildcard domain)
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

	p := &DNSBrutePlugin{
		resolver: server.PacketConn.LocalAddr().String(),
		wordlist: []string{"www", "mail", "api"},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "wildcard.example.com",
	})
	require.NoError(t, err)
	assert.Empty(t, findings, "wildcard domain should produce no findings")
}

func TestDNSBrutePlugin_Run(t *testing.T) {
	// Start a local DNS server that responds only to specific known subdomains
	// (not a wildcard — the random hex probe will return NXDOMAIN).
	known := map[string]bool{
		"www.example.com.":  true,
		"mail.example.com.": true,
		"api.example.com.":  true,
	}
	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA && known[q.Name] {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("93.184.216.34"),
				})
			} else {
				m.Rcode = dns.RcodeNameError
			}
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{
		Addr:    "127.0.0.1:0",
		Net:     "udp",
		Handler: serveMux,
	}

	// Use a channel to get the actual listening address
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }

	go func() { _ = server.ListenAndServe() }()
	defer func() { _ = server.Shutdown() }()
	<-started

	p := &DNSBrutePlugin{
		resolver: server.PacketConn.LocalAddr().String(),
		wordlist: []string{"www", "mail", "api"},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "example.com",
	})

	require.NoError(t, err)
	assert.Len(t, findings, 3, "should find www, mail, api subdomains")

	names := make(map[string]bool)
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "dns-brute", f.Source)
		names[f.Value] = true
	}
	assert.True(t, names["www.example.com"])
	assert.True(t, names["mail.example.com"])
	assert.True(t, names["api.example.com"])
}
