package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	piuscache "github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCensysPlugin creates a CensysOrgPlugin with a temp-dir APICache for isolated testing.
func newTestCensysPlugin(t *testing.T, baseURL string) *CensysOrgPlugin {
	t.Helper()
	c, err := piuscache.NewAPI(t.TempDir(), "censys-org")
	require.NoError(t, err)
	return &CensysOrgPlugin{
		client:   client.New(),
		baseURL:  baseURL,
		apiCache: c,
	}
}

// ── Accepts ───────────────────────────────────────────────────────────────────

func TestCensysOrgPlugin_Accepts_RequiresOrgNameAndToken(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "test-token")
	p := &CensysOrgPlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp", Domain: "acme.com"}))
}

func TestCensysOrgPlugin_Accepts_RejectsWithoutOrgName(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "test-token")
	p := &CensysOrgPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

func TestCensysOrgPlugin_Accepts_RejectsWithoutToken(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "")
	p := &CensysOrgPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestCensysOrgPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("censys-org")
	require.True(t, ok, "censys-org plugin must be registered")

	assert.Equal(t, "censys-org", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModeActive, p.Mode())
	assert.Contains(t, p.Description(), "Censys")
	assert.Contains(t, p.Description(), "CENSYS_API_TOKEN")
}

// ── normalizeCensysDomain ─────────────────────────────────────────────────────

func TestNormalizeCensysDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"*.example.com", "example.com"},
		{"*.sub.example.com", "sub.example.com"},
		{"  example.com  ", "example.com"},
		{"", ""},
		{"*", ""},
		{"*.", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeCensysDomain(tt.input))
		})
	}
}

// ── buildCensysQuery ──────────────────────────────────────────────────────────

func TestBuildCensysQuery_OrgOnly(t *testing.T) {
	q := buildCensysQuery("Acme Corp", "")
	assert.Contains(t, q, "host.services.cert.parsed.subject_dn:")
	assert.Contains(t, q, "Acme Corp")
	assert.NotContains(t, q, "names:")
}

func TestBuildCensysQuery_OrgAndDomain(t *testing.T) {
	q := buildCensysQuery("Acme Corp", "acme.com")
	assert.Contains(t, q, "host.services.cert.parsed.subject_dn:")
	assert.Contains(t, q, "host.services.cert.names:")
	assert.Contains(t, q, "acme.com")
}

// ── extractFindings ────────────────────────────────────────────────────────────

type hitOpts struct {
	ip           string
	certNames    []string
	cnNames      []string
	certOrgNames []string
	reverseDNS   []string
	whoisCIDRs   []string
	bgpPrefix    string
}

func makeHit(certNames []string, cnNames []string, reverseDNS []string) censysSearchHit {
	return makeHitFull(hitOpts{certNames: certNames, cnNames: cnNames, reverseDNS: reverseDNS})
}

func makeHitFull(opts hitOpts) censysSearchHit {
	ip := opts.ip
	if ip == "" {
		ip = "1.2.3.4"
	}

	var services []censysHostService
	if len(opts.certNames) > 0 || len(opts.cnNames) > 0 || len(opts.certOrgNames) > 0 {
		cert := &censysServiceCert{Names: opts.certNames}
		if len(opts.cnNames) > 0 || len(opts.certOrgNames) > 0 {
			cert.Parsed = &censysCertParsed{
				Subject: &censysCertSubject{
					CommonName:   opts.cnNames,
					Organization: opts.certOrgNames,
				},
			}
		}
		services = append(services, censysHostService{Cert: cert})
	}

	var dns *censysHostDNS
	if len(opts.reverseDNS) > 0 {
		dns = &censysHostDNS{
			ReverseDNS: &censysReverseDNS{Names: opts.reverseDNS},
		}
	}

	var whois *censysWhois
	if len(opts.whoisCIDRs) > 0 {
		whois = &censysWhois{
			Network: &censysWhoisNetwork{CIDRs: opts.whoisCIDRs},
		}
	}

	var as *censysAutonomousSystem
	if opts.bgpPrefix != "" {
		as = &censysAutonomousSystem{BGPPrefix: opts.bgpPrefix}
	}

	return censysSearchHit{
		Host: &censysHostHit{
			Resource: &censysHostResource{
				IP:               ip,
				Services:         services,
				DNS:              dns,
				Whois:            whois,
				AutonomousSystem: as,
			},
		},
	}
}

func TestCensysOrgPlugin_ExtractDomains_FromCertNames(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHit([]string{"acme.com", "www.acme.com", "*.acme.com"}, nil, nil),
	}

	findings := p.extractFindings("Acme Corp", hits)

	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "censys-org", f.Source)
		assert.Equal(t, "Acme Corp", f.Data["org"])
		values = append(values, f.Value)
	}

	assert.Contains(t, values, "acme.com")
	assert.Contains(t, values, "www.acme.com")
}

func TestCensysOrgPlugin_ExtractDomains_FromAllSources(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHit(
			[]string{"acme.com"},
			[]string{"mail.acme.com"},
			[]string{"host.acme.com"},
		),
	}

	findings := p.extractFindings("Acme Corp", hits)

	var values []string
	for _, f := range findings {
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "acme.com")
	assert.Contains(t, values, "mail.acme.com")
	assert.Contains(t, values, "host.acme.com")
}

func TestCensysOrgPlugin_ExtractDomains_DeduplicatesDomains(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHit([]string{"acme.com", "acme.com", "*.acme.com"}, nil, nil),
		makeHit([]string{"acme.com"}, nil, nil),
	}

	findings := p.extractFindings("Acme Corp", hits)

	count := 0
	for _, f := range findings {
		if f.Value == "acme.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "acme.com should appear exactly once")
}

func TestCensysOrgPlugin_ExtractDomains_EmptyHits(t *testing.T) {
	p := &CensysOrgPlugin{}
	assert.Empty(t, p.extractFindings("Acme", nil))
}

func TestCensysOrgPlugin_ExtractDomains_NilHostSkipped(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{{Host: nil}}
	assert.Empty(t, p.extractFindings("Acme", hits))
}

func TestCensysOrgPlugin_ExtractDomains_FieldLabels(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHit(
			[]string{"cert.acme.com"},
			[]string{"cn.acme.com"},
			[]string{"rdns.acme.com"},
		),
	}

	findings := p.extractFindings("Acme", hits)
	fieldMap := make(map[string]string)
	for _, f := range findings {
		fieldMap[f.Value] = f.Data["field"].(string)
	}

	assert.Equal(t, "certificate_names", fieldMap["cert.acme.com"])
	assert.Equal(t, "subject_cn", fieldMap["cn.acme.com"])
	assert.Equal(t, "reverse_dns", fieldMap["rdns.acme.com"])
}

// ── extractFindings — CIDRs ───────────────────────────────────────────────────

func TestCensysOrgPlugin_ExtractCIDRs_FromWhoisNetwork(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{whoisCIDRs: []string{"203.0.113.0/24", "198.51.100.0/22"}}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	var cidrs []string
	for _, f := range findings {
		if f.Type == plugins.FindingCIDR {
			assert.Equal(t, "censys-org", f.Source)
			assert.Equal(t, "Acme Corp", f.Data["org"])
			assert.Equal(t, "whois_network", f.Data["field"])
			cidrs = append(cidrs, f.Value)
		}
	}
	assert.Contains(t, cidrs, "203.0.113.0/24")
	assert.Contains(t, cidrs, "198.51.100.0/22")
}

func TestCensysOrgPlugin_ExtractCIDRs_FromBGPPrefix(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{bgpPrefix: "8.8.8.0/24"}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	require.Len(t, findings, 1)
	assert.Equal(t, plugins.FindingCIDR, findings[0].Type)
	assert.Equal(t, "8.8.8.0/24", findings[0].Value)
	assert.Equal(t, "bgp_prefix", findings[0].Data["field"])
}

func TestCensysOrgPlugin_ExtractCIDRs_DeduplicatesAcrossHits(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{whoisCIDRs: []string{"10.0.0.0/8"}, bgpPrefix: "10.0.0.0/8"}),
		makeHitFull(hitOpts{whoisCIDRs: []string{"10.0.0.0/8"}}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	count := 0
	for _, f := range findings {
		if f.Value == "10.0.0.0/8" {
			count++
		}
	}
	assert.Equal(t, 1, count, "10.0.0.0/8 should appear exactly once")
}

func TestCensysOrgPlugin_ExtractFindings_MixedDomainsAndCIDRs(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{
			certNames:  []string{"acme.com", "www.acme.com"},
			whoisCIDRs: []string{"203.0.113.0/24"},
			bgpPrefix:  "198.51.100.0/22",
		}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	var domains, cidrs []string
	for _, f := range findings {
		switch f.Type {
		case plugins.FindingDomain:
			domains = append(domains, f.Value)
		case plugins.FindingCIDR:
			cidrs = append(cidrs, f.Value)
		}
	}
	assert.Contains(t, domains, "acme.com")
	assert.Contains(t, domains, "www.acme.com")
	assert.Contains(t, cidrs, "203.0.113.0/24")
	assert.Contains(t, cidrs, "198.51.100.0/22")
}

// ── extractFindings — Preseeds from TLS cert Subject Organization ──────────────

// TestCensysOrgPlugin_ExtractPreseeds_MultiHostEmitsPreseed verifies that when
// the same Organization name appears in TLS cert subject fields across 2+ distinct
// host IPs, a single FindingPreseed is emitted.
func TestCensysOrgPlugin_ExtractPreseeds_MultiHostEmitsPreseed(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{ip: "1.2.3.4", certOrgNames: []string{"Contoso Ltd"}}),
		makeHitFull(hitOpts{ip: "5.6.7.8", certOrgNames: []string{"Contoso Ltd"}}),
		makeHitFull(hitOpts{ip: "9.10.11.12", certOrgNames: []string{"Contoso Ltd"}}),
		makeHitFull(hitOpts{ip: "13.14.15.16", certOrgNames: []string{"Contoso Ltd"}}),
		makeHitFull(hitOpts{ip: "17.18.19.20", certOrgNames: []string{"Contoso Ltd"}}),
		makeHitFull(hitOpts{ip: "21.22.23.24", certOrgNames: []string{"Different Corp"}}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	var preseeds []plugins.Finding
	for _, f := range findings {
		if f.Type == plugins.FindingPreseed {
			preseeds = append(preseeds, f)
		}
	}

	require.Len(t, preseeds, 1, "only 'Contoso Ltd' appears on 5+ hosts")
	assert.Equal(t, "Contoso Ltd", preseeds[0].Value)
	assert.Equal(t, "censys-org", preseeds[0].Source)
}

// TestCensysOrgPlugin_ExtractPreseeds_SingleHostNoPreseed verifies that an
// Organization appearing on only one host does not emit a preseed.
func TestCensysOrgPlugin_ExtractPreseeds_SingleHostNoPreseed(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{ip: "1.2.3.4", certOrgNames: []string{"Lonely Corp"}}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	for _, f := range findings {
		assert.NotEqual(t, plugins.FindingPreseed, f.Type, "single-host org must not emit preseed")
	}
}

// TestCensysOrgPlugin_ExtractPreseeds_SelfMatchExcluded verifies that the searched
// orgName itself is not emitted as a preseed even when it appears on multiple hosts.
func TestCensysOrgPlugin_ExtractPreseeds_SelfMatchExcluded(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{ip: "1.2.3.4", certOrgNames: []string{"Acme Corp"}}),
		makeHitFull(hitOpts{ip: "5.6.7.8", certOrgNames: []string{"Acme Corp"}}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	for _, f := range findings {
		assert.NotEqual(t, plugins.FindingPreseed, f.Type, "orgName itself must not be emitted as preseed")
	}
}

// TestCensysOrgPlugin_ExtractPreseeds_DataFields verifies that preseed findings
// contain the required metadata fields.
func TestCensysOrgPlugin_ExtractPreseeds_DataFields(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{ip: "1.2.3.4", certOrgNames: []string{"Subsidiary Inc"}}),
		makeHitFull(hitOpts{ip: "5.6.7.8", certOrgNames: []string{"Subsidiary Inc"}}),
		makeHitFull(hitOpts{ip: "9.10.11.12", certOrgNames: []string{"Subsidiary Inc"}}),
		makeHitFull(hitOpts{ip: "13.14.15.16", certOrgNames: []string{"Subsidiary Inc"}}),
		makeHitFull(hitOpts{ip: "17.18.19.20", certOrgNames: []string{"Subsidiary Inc"}}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	var preseed *plugins.Finding
	for i := range findings {
		if findings[i].Type == plugins.FindingPreseed && findings[i].Value == "Subsidiary Inc" {
			preseed = &findings[i]
			break
		}
	}
	require.NotNil(t, preseed, "preseed for 'Subsidiary Inc' must be emitted")

	assert.Equal(t, "whois+company", preseed.Data["preseed_type"])
	assert.Equal(t, "Subsidiary Inc", preseed.Data["preseed_title"])
	assert.Equal(t, 5, preseed.Data["host_count"])
	assert.Equal(t, "subject_organization", preseed.Data["field"])
	assert.Equal(t, "Acme Corp", preseed.Data["org"])
}

// ── Cache integration ─────────────────────────────────────────────────────────

func TestCensysOrgPlugin_Cache_WriteAndRead(t *testing.T) {
	c, err := piuscache.NewAPI(t.TempDir(), "censys-org")
	require.NoError(t, err)

	key := "censys-org|acme corp|acme.com"
	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "acme.com", Source: "censys-org",
			Data: map[string]any{"org": "Acme Corp", "field": "certificate_names"}},
	}

	c.Set(key, findings)

	var cached []plugins.Finding
	ok := c.Get(key, &cached)
	require.True(t, ok, "cache should hit after Set")
	require.Len(t, cached, 1)
	assert.Equal(t, "acme.com", cached[0].Value)
}

func TestCensysOrgPlugin_Cache_MissForUnknownKey(t *testing.T) {
	c, err := piuscache.NewAPI(t.TempDir(), "censys-org")
	require.NoError(t, err)

	var v []plugins.Finding
	assert.False(t, c.Get("never-written-key", &v))
}

// ── Run with mock server ──────────────────────────────────────────────────────

func mockCensysSearchResponse(hits []censysSearchHit) []byte {
	resp := censysSearchResponse{
		Result: &censysSearchResult{
			Hits:      hits,
			TotalHits: float64(len(hits)),
		},
	}
	data, _ := json.Marshal(resp)
	return data
}

func TestCensysOrgPlugin_Run_ExtractsDomains(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "test-token")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify bearer auth
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		// Verify it's a POST to the search endpoint
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/v3/global/search/query")

		// Verify request body
		var req censysSearchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Contains(t, req.Query, "Acme Corp")
		assert.Equal(t, 100, req.PageSize)

		w.Header().Set("Content-Type", "application/json")
		hits := []censysSearchHit{
			makeHitFull(hitOpts{
				certNames:  []string{"acme.com", "www.acme.com", "api.acme.com", "*.acme.com"},
				whoisCIDRs: []string{"203.0.113.0/24"},
				bgpPrefix:  "198.51.100.0/22",
			}),
		}
		_, _ = w.Write(mockCensysSearchResponse(hits))
	}))
	defer srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})

	require.NoError(t, err)
	require.NotEmpty(t, findings)

	var domains, cidrs []string
	for _, f := range findings {
		assert.Equal(t, "censys-org", f.Source)
		switch f.Type {
		case plugins.FindingDomain:
			domains = append(domains, f.Value)
		case plugins.FindingCIDR:
			cidrs = append(cidrs, f.Value)
		}
	}
	assert.Contains(t, domains, "acme.com")
	assert.Contains(t, domains, "www.acme.com")
	assert.Contains(t, domains, "api.acme.com")
	assert.Contains(t, cidrs, "203.0.113.0/24")
	assert.Contains(t, cidrs, "198.51.100.0/22")
}

func TestCensysOrgPlugin_Run_IncludesDomainInQuery(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "test-token")

	var receivedBody censysSearchRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockCensysSearchResponse(nil))
	}))
	defer srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	_, _ = p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp", Domain: "acme.com"})

	assert.Contains(t, receivedBody.Query, "names:")
	assert.Contains(t, receivedBody.Query, "acme.com")
}

func TestCensysOrgPlugin_Run_GracefulOnForbidden(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "bad-token")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"title":"Forbidden","status":403,"detail":"requires organization ID"}`))
	}))
	defer srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCensysOrgPlugin_Run_GracefulOnUnauthorized(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "expired-token")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"title":"Unauthorized","status":401}`))
	}))
	defer srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCensysOrgPlugin_Run_UsesCacheOnSecondCall(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "test-token")

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		hits := []censysSearchHit{makeHit([]string{"acme.com"}, nil, nil)}
		_, _ = w.Write(mockCensysSearchResponse(hits))
	}))
	defer srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	input := plugins.Input{OrgName: "Acme Corp"}

	f1, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	f2, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "second call must use cache, not hit API")
	assert.Equal(t, len(f1), len(f2))
}

func TestCensysOrgPlugin_Run_EmptyResponseNoFindings(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "test-token")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockCensysSearchResponse(nil))
	}))
	defer srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Unknown Corp"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCensysOrgPlugin_Run_GracefulOnNetworkError(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "test-token")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCensysOrgPlugin_Run_GracefulOnMalformedJSON(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "test-token")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCensysOrgPlugin_Run_GracefulOnNilResult(t *testing.T) {
	t.Setenv("CENSYS_API_TOKEN", "test-token")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":422,"title":"Unprocessable Entity"}`))
	}))
	defer srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}


// ── Deny list tests ────────────────────────────────────────────────────────────

// TestCensysOrgPlugin_ExtractPreseeds_DenyListBlocksCDN verifies that an org
// name in the infrastructure deny list is never emitted as a preseed, even when
// it appears on 10+ distinct hosts.
func TestCensysOrgPlugin_ExtractPreseeds_DenyListBlocksCDN(t *testing.T) {
	p := &CensysOrgPlugin{}
	// Build 10 hits with Cloudflare as the Subject Organization.
	var hits []censysSearchHit
	for i := 0; i < 10; i++ {
		hits = append(hits, makeHitFull(hitOpts{
			ip:           fmt.Sprintf("1.2.3.%d", i+1),
			certOrgNames: []string{"Cloudflare, Inc."},
		}))
	}

	findings := p.extractFindings("Acme Corp", hits)

	for _, f := range findings {
		assert.NotEqual(t, plugins.FindingPreseed, f.Type,
			"infrastructure org 'Cloudflare, Inc.' must never emit preseed")
	}
}

// TestCensysOrgPlugin_ExtractPreseeds_DenyListCaseInsensitive verifies that
// deny-list matching is case-insensitive (e.g., "CLOUDFLARE, INC." is blocked).
func TestCensysOrgPlugin_ExtractPreseeds_DenyListCaseInsensitive(t *testing.T) {
	p := &CensysOrgPlugin{}
	var hits []censysSearchHit
	for i := 0; i < 10; i++ {
		hits = append(hits, makeHitFull(hitOpts{
			ip:           fmt.Sprintf("2.3.4.%d", i+1),
			certOrgNames: []string{"CLOUDFLARE, INC."},
		}))
	}

	findings := p.extractFindings("Acme Corp", hits)

	for _, f := range findings {
		assert.NotEqual(t, plugins.FindingPreseed, f.Type,
			"deny-list check must be case-insensitive: 'CLOUDFLARE, INC.' must be blocked")
	}
}

// TestCensysOrgPlugin_ExtractPreseeds_ThresholdBelowFiveNoPreseed verifies that
// an org appearing on exactly 3 hosts does not emit a preseed (below the 5-host
// threshold).
func TestCensysOrgPlugin_ExtractPreseeds_ThresholdBelowFiveNoPreseed(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{ip: "10.0.0.1", certOrgNames: []string{"Widget LLC"}}),
		makeHitFull(hitOpts{ip: "10.0.0.2", certOrgNames: []string{"Widget LLC"}}),
		makeHitFull(hitOpts{ip: "10.0.0.3", certOrgNames: []string{"Widget LLC"}}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	for _, f := range findings {
		assert.NotEqual(t, plugins.FindingPreseed, f.Type,
			"org on 3 hosts must not emit preseed (threshold is 5)")
	}
}

// TestCensysOrgPlugin_ExtractPreseeds_ThresholdAtFiveEmitsPreseed verifies that
// an org appearing on exactly 5 hosts does emit a preseed (meets threshold).
func TestCensysOrgPlugin_ExtractPreseeds_ThresholdAtFiveEmitsPreseed(t *testing.T) {
	p := &CensysOrgPlugin{}
	hits := []censysSearchHit{
		makeHitFull(hitOpts{ip: "10.1.0.1", certOrgNames: []string{"Threshold Corp"}}),
		makeHitFull(hitOpts{ip: "10.1.0.2", certOrgNames: []string{"Threshold Corp"}}),
		makeHitFull(hitOpts{ip: "10.1.0.3", certOrgNames: []string{"Threshold Corp"}}),
		makeHitFull(hitOpts{ip: "10.1.0.4", certOrgNames: []string{"Threshold Corp"}}),
		makeHitFull(hitOpts{ip: "10.1.0.5", certOrgNames: []string{"Threshold Corp"}}),
	}

	findings := p.extractFindings("Acme Corp", hits)

	var preseeds []plugins.Finding
	for _, f := range findings {
		if f.Type == plugins.FindingPreseed {
			preseeds = append(preseeds, f)
		}
	}

	require.Len(t, preseeds, 1, "org on exactly 5 hosts must emit preseed")
	assert.Equal(t, "Threshold Corp", preseeds[0].Value)
}

// ── Registry ──────────────────────────────────────────────────────────────────

func TestCensysOrgPlugin_IsRegistered(t *testing.T) {
	_, ok := plugins.Get("censys-org")
	assert.True(t, ok)
}

func TestCensysOrgPlugin_AppearsInList(t *testing.T) {
	found := false
	for _, n := range plugins.List() {
		if n == "censys-org" {
			found = true
			break
		}
	}
	assert.True(t, found)
}
