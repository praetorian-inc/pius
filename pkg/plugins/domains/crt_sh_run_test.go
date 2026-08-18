package domains

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockCRTShServer(entries []map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
}

func newCRTShTestPlugin(t *testing.T, entries []map[string]string, handler func(dns.ResponseWriter, *dns.Msg)) *CRTShPlugin {
	t.Helper()

	crtShServer := mockCRTShServer(entries)
	t.Cleanup(crtShServer.Close)

	resolver := newMockResolver(handler)
	t.Cleanup(resolver.close)

	return &CRTShPlugin{
		client:   client.New(),
		baseURL:  crtShServer.URL,
		resolver: resolver.addr,
	}
}

func answerARecord(w dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)
	if request.Question[0].Qtype == dns.TypeA {
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		})
	}
	_ = w.WriteMsg(response)
}

func TestCRTShPlugin_ParsesDomains(t *testing.T) {
	p := newCRTShTestPlugin(t, []map[string]string{
		{"name_value": "api.example.com"},
		{"name_value": "www.example.com"},
		{"name_value": "mail.example.com"},
	}, answerARecord)

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 3)
	var values []string
	for _, finding := range findings {
		assert.Equal(t, plugins.FindingDomain, finding.Type)
		assert.Equal(t, "crt-sh", finding.Source)
		require.Len(t, finding.Confidences, 2)
		assert.Equal(t, confCRTShCertificateTransparencyObservation, finding.Confidences[0].Score)
		assert.Equal(t, confCRTShDNSPresenceObservation, finding.Confidences[1].Score)
		assert.Equal(t, 70, plugins.TotalConfidence(finding))
		assert.Contains(t, finding.Confidences[0].Justification, finding.Value)
		assert.Contains(t, finding.Confidences[0].Justification, "example.com")
		assert.Contains(t, finding.Confidences[0].Justification, "Certificate Transparency")
		assert.Contains(t, finding.Confidences[0].Justification, p.baseURL+"/?q=example.com&output=json")
		assert.Contains(t, finding.Confidences[1].Justification, finding.Value)
		assert.Contains(t, finding.Confidences[1].Justification, "DNS presence")
		assert.Contains(t, finding.Confidences[1].Justification, "A record")
		assert.NotContains(t, finding.Data, "confidence")
		assert.NotContains(t, finding.Data, "confidences")
		values = append(values, finding.Value)
	}
	assert.ElementsMatch(t, []string{"api.example.com", "www.example.com", "mail.example.com"}, values)
}

func TestCRTShPlugin_RecoversWildcardParent(t *testing.T) {
	p := newCRTShTestPlugin(t, []map[string]string{
		{"name_value": "*.foo.example.com"},
	}, answerARecord)

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "foo.example.com", findings[0].Value)
}

func TestCRTShPlugin_DeduplicatesAfterWildcardNormalization(t *testing.T) {
	var aQueries atomic.Int32
	p := newCRTShTestPlugin(t, []map[string]string{
		{"name_value": "*.foo.example.com\nfoo.example.com"},
		{"name_value": "*.foo.example.com"},
	}, func(w dns.ResponseWriter, request *dns.Msg) {
		if request.Question[0].Qtype == dns.TypeA {
			aQueries.Add(1)
		}
		answerARecord(w, request)
	})

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "foo.example.com", findings[0].Value)
	assert.Equal(t, int32(1), aQueries.Load(), "the normalized candidate should be queried once")
}

func TestCRTShPlugin_RejectsBareWildcard(t *testing.T) {
	var queries atomic.Int32
	p := newCRTShTestPlugin(t, []map[string]string{
		{"name_value": "*"},
	}, func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		answerARecord(w, request)
	})

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Zero(t, queries.Load())
}

func TestCRTShPlugin_AcceptsSupportedDNSEvidence(t *testing.T) {
	tests := []struct {
		name       string
		recordType uint16
		record     func(string) dns.RR
	}{
		{name: "A", recordType: dns.TypeA, record: func(name string) dns.RR {
			return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.1")}
		}},
		{name: "AAAA", recordType: dns.TypeAAAA, record: func(name string) dns.RR {
			return &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::1")}
		}},
		{name: "CNAME", recordType: dns.TypeCNAME, record: func(name string) dns.RR {
			return &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "target.example.com."}
		}},
		{name: "MX", recordType: dns.TypeMX, record: func(name string) dns.RR {
			return &dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET}, Preference: 10, Mx: "mail.example.com."}
		}},
		{name: "SRV", recordType: dns.TypeSRV, record: func(name string) dns.RR {
			return &dns.SRV{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET}, Priority: 10, Weight: 5, Port: 443, Target: "service.example.com."}
		}},
		{name: "SVCB", recordType: dns.TypeSVCB, record: func(name string) dns.RR {
			return &dns.SVCB{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET}, Priority: 1, Target: "service.example.com."}
		}},
		{name: "HTTPS", recordType: dns.TypeHTTPS, record: func(name string) dns.RR {
			return &dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}, Priority: 1, Target: "service.example.com."}}
		}},
		{name: "NS", recordType: dns.TypeNS, record: func(name string) dns.RR {
			return &dns.NS{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.example.com."}
		}},
		{name: "SOA", recordType: dns.TypeSOA, record: func(name string) dns.RR {
			return &dns.SOA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "ns1.example.com.", Mbox: "hostmaster.example.com.", Serial: 1}
		}},
		{name: "NAPTR", recordType: dns.TypeNAPTR, record: func(name string) dns.RR {
			return &dns.NAPTR{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNAPTR, Class: dns.ClassINET}, Order: 10, Preference: 10, Flags: "S", Service: "SIP+D2U", Replacement: "_sip._udp.example.com."}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := newCRTShTestPlugin(t, []map[string]string{{"name_value": "service.example.com"}}, func(w dns.ResponseWriter, request *dns.Msg) {
				response := new(dns.Msg)
				response.SetReply(request)
				if request.Question[0].Qtype == test.recordType {
					response.Answer = append(response.Answer, test.record(request.Question[0].Name))
				}
				_ = w.WriteMsg(response)
			})

			findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

			require.NoError(t, err)
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0].Confidences[1].Justification, test.name+" record")
		})
	}
}

func TestCRTShPlugin_OmitsCandidatesWithoutQualifyingDNS(t *testing.T) {
	p := newCRTShTestPlugin(t, []map[string]string{
		{"name_value": "missing.example.com"},
		{"name_value": "empty.example.com"},
	}, func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		switch request.Question[0].Name {
		case "missing.example.com.":
			response.Rcode = dns.RcodeNameError
		case "empty.example.com.":
			response.Answer = append(response.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
				Txt: []string{"not qualifying evidence"},
			})
		}
		_ = w.WriteMsg(response)
	})

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCRTShPlugin_NormalizesDomains(t *testing.T) {
	p := newCRTShTestPlugin(t, []map[string]string{
		{"name_value": "EXAMPLE.COM"},
		{"name_value": "api.example.com."},
		{"name_value": "  mail.example.com  "},
	}, answerARecord)

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	values := make(map[string]bool)
	for _, finding := range findings {
		values[finding.Value] = true
		assert.Equal(t, strings.ToLower(strings.TrimSpace(finding.Value)), finding.Value)
	}
	assert.True(t, values["example.com"])
	assert.True(t, values["api.example.com"])
	assert.True(t, values["mail.example.com"])
}

func TestCRTShPlugin_MultipleDomainsInNameValue(t *testing.T) {
	p := newCRTShTestPlugin(t, []map[string]string{
		{"name_value": "api.example.com\nwww.example.com\nmail.example.com"},
	}, answerARecord)

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Len(t, findings, 3)
}

func TestCRTShPlugin_PrefersDomainOverOrgName(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		receivedQuery = request.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: server.URL}
	_, _ = p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp", Domain: "acme.com"})
	assert.Equal(t, "acme.com", receivedQuery)
}

func TestCRTShPlugin_GracefulOnInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: server.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCRTShPlugin_GracefulOnHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: server.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCRTShPlugin_GracefulOnNetworkError(t *testing.T) {
	p := &CRTShPlugin{client: client.NewNoRetry(), baseURL: "http://127.0.0.1:1"}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}
