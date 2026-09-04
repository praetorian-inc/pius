package domains

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseICANNSuffixes(t *testing.T) {
	raw := `
// outside
private.example
// ===BEGIN ICANN DOMAINS===
com
co.uk
nesna.no
0.bg
公司
xn--55qx5d

// comment
*.wild.example
!exception.example
-invalid.example
// ===END ICANN DOMAINS===
private.example
`

	suffixes := parseICANNSuffixes(raw)
	assert.Equal(t, map[string]struct{}{
		"com": {}, "co.uk": {}, "nesna.no": {}, "0.bg": {}, "xn--55qx5d": {},
	}, suffixes)
}

func TestEmbeddedICANNSuffixes(t *testing.T) {
	suffixes := loadICANNSuffixes()
	for _, suffix := range []string{"com", "co.uk", "nesna.no", "0.bg", "xn--55qx5d"} {
		assert.Contains(t, suffixes, suffix)
	}
	assert.NotContains(t, suffixes, "blogspot.com", "private suffixes must not be loaded")
	assert.Equal(t, fmt.Sprintf("%p", suffixes), fmt.Sprintf("%p", loadICANNSuffixes()))
}

func TestDNSICANNBrutePluginDescriptor(t *testing.T) {
	registered, ok := plugins.Get("dns-icann-brute")
	require.True(t, ok)
	assert.IsType(t, &DNSICANNBrutePlugin{}, registered)

	plugin := NewDNSICANNBrutePlugin(nil)
	assert.Equal(t, "dns-icann-brute", plugin.Name())
	assert.Equal(t, "domain", plugin.Category())
	assert.Equal(t, 0, plugin.Phase())
	assert.Equal(t, plugins.ModeActive, plugin.Mode())
	assert.True(t, plugin.Accepts(plugins.Input{Domain: "www.customer.co.uk"}))
	assert.False(t, plugin.Accepts(plugins.Input{Domain: "co.uk"}))
}

func TestRegistrableLabel(t *testing.T) {
	for domain, expected := range map[string]string{
		"customer.com":       "customer",
		"www.customer.co.uk": "customer",
		"食狮.公司.cn":           "xn--85x722f",
	} {
		actual, err := getRegistrableLabel(domain)
		require.NoError(t, err)
		assert.Equal(t, expected, actual)
	}
}

func TestGenerateICANNCandidatesExcludesOriginal(t *testing.T) {
	candidates := generateICANNCandidates("customer", "customer.com", map[string]struct{}{
		"com": {}, "org": {}, "co.uk": {},
	})
	assert.ElementsMatch(t, []icannCandidate{
		{domain: "customer.org", suffix: "org"},
		{domain: "customer.co.uk", suffix: "co.uk"},
	}, candidates)
}

func TestDNSICANNBrutePluginRun(t *testing.T) {
	resolver := &icannTestResolver{resolve: func(domain string) []string {
		switch domain {
		case "customer.org":
			return []string{"192.0.2.1"}
		case "customer.xn--55qx5d":
			return []string{"2001:db8::1"}
		default:
			return nil
		}
	}}
	plugin := &DNSICANNBrutePlugin{
		lookup: resolver,
		suffixes: map[string]struct{}{
			"com": {}, "org": {}, "net": {}, "xn--55qx5d": {},
		},
	}

	findings, err := plugin.Run(context.Background(), plugins.Input{Domain: "Customer.com"})
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, []string{"customer.org", "customer.xn--55qx5d"}, []string{findings[0].Value, findings[1].Value})
	assert.NotContains(t, resolver.calls(), "customer.com")

	unicodeFinding := findings[1]
	assert.Equal(t, plugins.FindingDomain, unicodeFinding.Type)
	assert.Equal(t, "dns-icann-brute", unicodeFinding.Source)
	assert.Equal(t, "dns-icann-brute", unicodeFinding.Data["method"])
	assert.Equal(t, "Customer.com", unicodeFinding.Data["original_domain"])
	assert.Equal(t, "xn--55qx5d", unicodeFinding.Data["icann_suffix"])
	assert.Equal(t, "公司", unicodeFinding.Data["unicode_suffix"])
	require.Len(t, unicodeFinding.Confidences, 1)
	assert.Equal(t, confDNSICANNBruteResolved, unicodeFinding.Confidences[0].Score)
	assert.Contains(t, unicodeFinding.Confidences[0].Justification, "registrable label")
}

func TestDNSICANNBruteRejectsWildcardSuffixes(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	resolver := &icannTestResolver{resolve: func(domain string) []string {
		if domain == "customer.org" || strings.HasSuffix(domain, ".org") {
			return []string{"192.0.2.1"}
		}
		return nil
	}}
	plugin := &DNSICANNBrutePlugin{
		lookup:   resolver,
		suffixes: map[string]struct{}{"org": {}},
	}

	findings, err := plugin.Run(context.Background(), plugins.Input{Domain: "customer.com"})
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Contains(t, logs.String(), "dns-icann-brute: wildcard detected")
	assert.Contains(t, logs.String(), "suffix=org")
}

func TestDNSICANNBruteResolvesAOrAAAA(t *testing.T) {
	for _, recordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		t.Run(dns.TypeToString[recordType], func(t *testing.T) {
			resolver := newMockResolver(answerDNSQuery(recordType))
			defer resolver.close()

			plugin := &DNSICANNBrutePlugin{resolver: resolver.addr}
			assert.NotEmpty(t, plugin.resolveAddresses(context.Background(), "customer.org"))
		})
	}
}

func TestDNSICANNBruteConcurrencyIsConfigurableAndBounded(t *testing.T) {
	resolver := &icannTestResolver{resolve: func(string) []string {
		time.Sleep(5 * time.Millisecond)
		return nil
	}}
	suffixes := make(map[string]struct{})
	for i := 0; i < 30; i++ {
		suffixes[fmt.Sprintf("suffix%d", i)] = struct{}{}
	}
	plugin := &DNSICANNBrutePlugin{lookup: resolver, suffixes: suffixes}

	_, err := plugin.Run(context.Background(), plugins.Input{
		Domain: "customer.com",
		Meta:   map[string]string{"dns_icann_brute_concurrency": "3"},
	})
	require.NoError(t, err)
	assert.LessOrEqual(t, resolver.maximumConcurrency(), 3)
	assert.Greater(t, resolver.maximumConcurrency(), 1)
}

func TestDNSICANNBruteContextCancellationStopsScheduling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	resolver := &icannTestResolver{resolve: func(string) []string {
		cancel()
		return nil
	}}
	suffixes := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		suffixes[fmt.Sprintf("suffix%d", i)] = struct{}{}
	}
	plugin := &DNSICANNBrutePlugin{lookup: resolver, suffixes: suffixes}

	_, err := plugin.Run(ctx, plugins.Input{
		Domain: "customer.com",
		Meta:   map[string]string{"dns_icann_brute_concurrency": "1"},
	})
	require.NoError(t, err)
	assert.Less(t, len(resolver.calls()), len(suffixes))
}

func answerDNSQuery(recordType uint16) func(dns.ResponseWriter, *dns.Msg) {
	return func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		if request.Question[0].Qtype == recordType {
			response.Answer = []dns.RR{dnsAnswer(recordType)}
		}
		_ = writer.WriteMsg(response)
	}
}

func dnsAnswer(recordType uint16) dns.RR {
	if recordType == dns.TypeA {
		record, _ := dns.NewRR("customer.org. 60 IN A 192.0.2.1")
		return record
	}
	record, _ := dns.NewRR("customer.org. 60 IN AAAA 2001:db8::1")
	return record
}

type icannTestResolver struct {
	resolve func(string) []string

	mu        sync.Mutex
	hosts     []string
	active    int
	maxActive int
}

func (r *icannTestResolver) Resolve(host string) []string {
	r.mu.Lock()
	r.hosts = append(r.hosts, host)
	r.active++
	if r.active > r.maxActive {
		r.maxActive = r.active
	}
	r.mu.Unlock()

	addresses := r.resolve(host)

	r.mu.Lock()
	r.active--
	r.mu.Unlock()
	return addresses
}

func (r *icannTestResolver) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.hosts...)
}

func (r *icannTestResolver) maximumConcurrency() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxActive
}
