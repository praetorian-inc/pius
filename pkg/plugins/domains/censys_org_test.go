package domains

import (
	"context"
	"encoding/json"
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
	certNames []string
	cnNames   []string
	reverseDNS []string
	whoisCIDRs []string
	bgpPrefix  string
}

func makeHit(certNames []string, cnNames []string, reverseDNS []string) censysSearchHit {
	return makeHitFull(hitOpts{certNames: certNames, cnNames: cnNames, reverseDNS: reverseDNS})
}

func makeHitFull(opts hitOpts) censysSearchHit {
	var services []censysHostService
	if len(opts.certNames) > 0 || len(opts.cnNames) > 0 {
		cert := &censysServiceCert{Names: opts.certNames}
		if len(opts.cnNames) > 0 {
			cert.Parsed = &censysCertParsed{
				Subject: &censysCertSubject{CommonName: opts.cnNames},
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
				IP:               "1.2.3.4",
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
		json.NewDecoder(r.Body).Decode(&req)
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
		w.Write(mockCensysSearchResponse(hits))
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
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(mockCensysSearchResponse(nil))
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
		w.Write([]byte(`{"title":"Forbidden","status":403,"detail":"requires organization ID"}`))
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
		w.Write([]byte(`{"title":"Unauthorized","status":401}`))
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
		w.Write(mockCensysSearchResponse(hits))
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
		w.Write(mockCensysSearchResponse(nil))
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
		w.Write([]byte(`{invalid json`))
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
		w.Write([]byte(`{"status":422,"title":"Unprocessable Entity"}`))
	}))
	defer srv.Close()

	p := newTestCensysPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
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
