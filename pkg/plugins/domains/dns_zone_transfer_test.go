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

func TestDNSZoneTransferPlugin_Interface(t *testing.T) {
	p := &DNSZoneTransferPlugin{}
	assert.Equal(t, "dns-zone-transfer", p.Name())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, plugins.ModeActive, p.Mode())
}

func TestDNSZoneTransferPlugin_Accepts(t *testing.T) {
	p := &DNSZoneTransferPlugin{}
	assert.True(t, p.Accepts(plugins.Input{Domain: "example.com"}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Example Inc"}))
	assert.False(t, p.Accepts(plugins.Input{}))
}

func TestDNSZoneTransferPlugin_Run_Success(t *testing.T) {
	// Start a mock DNS server that accepts AXFR
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serveMux := dns.NewServeMux()
	serveMux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Qtype == dns.TypeAXFR {
			// Send SOA, then records, then SOA (AXFR envelope)
			soa := &dns.SOA{
				Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
				Ns:      "ns1.example.com.",
				Mbox:    "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600,
				Retry:   900,
				Expire:  604800,
				Minttl:  86400,
			}

			records := []dns.RR{
				soa,
				&dns.A{
					Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
					A:   net.ParseIP("93.184.216.34"),
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "mail.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
					A:   net.ParseIP("93.184.216.35"),
				},
				&dns.NS{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
					Ns:  "ns1.example.com.",
				},
				soa, // closing SOA
			}

			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = records
			w.WriteMsg(m)
		}
	})

	// Also handle NS lookup for example.com (to discover nameservers)
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeNS {
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  "ns1.example.com.",
			})
		}
		w.WriteMsg(m)
	})

	server := &dns.Server{
		Listener: listener,
		Net:      "tcp",
		Handler:  serveMux,
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go server.ActivateAndServe()
	defer server.Shutdown()
	<-started

	addr := listener.Addr().String()
	p := &DNSZoneTransferPlugin{
		// Override nameserver discovery to point at our mock
		nameservers: []string{addr},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "example.com",
	})

	require.NoError(t, err)
	// Should find www.example.com and mail.example.com (A records)
	// Should NOT include SOA, NS, or the base domain itself
	require.GreaterOrEqual(t, len(findings), 2, "should find at least www and mail subdomains")

	names := make(map[string]bool)
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "dns-zone-transfer", f.Source)
		names[f.Value] = true
	}
	assert.True(t, names["www.example.com"])
	assert.True(t, names["mail.example.com"])
}

func TestExtractHostname_AllRecordTypes(t *testing.T) {
	tests := []struct {
		name     string
		rr       dns.RR
		expected string
	}{
		{"A record", &dns.A{Hdr: dns.RR_Header{Name: "a.example.com."}}, "a.example.com."},
		{"AAAA record", &dns.AAAA{Hdr: dns.RR_Header{Name: "aaaa.example.com."}}, "aaaa.example.com."},
		{"CNAME record", &dns.CNAME{Hdr: dns.RR_Header{Name: "cname.example.com."}}, "cname.example.com."},
		{"MX record", &dns.MX{Hdr: dns.RR_Header{Name: "mx.example.com."}}, "mx.example.com."},
		{"SRV record", &dns.SRV{Hdr: dns.RR_Header{Name: "srv.example.com."}}, "srv.example.com."},
		{"TXT record (unsupported)", &dns.TXT{Hdr: dns.RR_Header{Name: "txt.example.com."}}, ""},
		{"SOA record (unsupported)", &dns.SOA{Hdr: dns.RR_Header{Name: "example.com."}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractHostname(tt.rr))
		})
	}
}

func TestDNSZoneTransferPlugin_Run_Refused(t *testing.T) {
	// Start a mock DNS server that refuses AXFR
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
	})

	server := &dns.Server{
		Listener: listener,
		Net:      "tcp",
		Handler:  serveMux,
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go server.ActivateAndServe()
	defer server.Shutdown()
	<-started

	addr := listener.Addr().String()
	p := &DNSZoneTransferPlugin{
		nameservers: []string{addr},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "example.com",
	})

	// Should return nil, nil (refused is not an error -- just no results)
	assert.NoError(t, err)
	assert.Empty(t, findings)
}
