package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Accepts ───────────────────────────────────────────────────────────────────

func TestFaviconHashPlugin_Accepts_RequiresDomainAndShodanKey(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	p := &FaviconHashPlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{Domain: "example.com"}))
	assert.True(t, p.Accepts(plugins.Input{Domain: "example.com", OrgName: "Acme"}))
}

func TestFaviconHashPlugin_Accepts_RejectsWithoutDomain(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	p := &FaviconHashPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme"}))
	assert.False(t, p.Accepts(plugins.Input{}))
}

func TestFaviconHashPlugin_Accepts_RejectsWithoutShodanKey(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "")
	p := &FaviconHashPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{Domain: "example.com"}))
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestFaviconHashPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("favicon-hash")
	require.True(t, ok, "favicon-hash plugin must be registered")

	assert.Equal(t, "favicon-hash", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModeActive, p.Mode())
	assert.Contains(t, p.Description(), "Favicon Hash")
	assert.Contains(t, p.Description(), "SHODAN_API_KEY")
}

// ── base64RFC2045 ─────────────────────────────────────────────────────────────

func TestBase64RFC2045_WrapsAt76Chars(t *testing.T) {
	// Use data long enough to produce multiple lines
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	encoded := base64RFC2045(data)
	lines := splitLines(encoded)
	for i, line := range lines {
		if i < len(lines)-1 {
			assert.LessOrEqual(t, len(line), 76, "line %d exceeds 76 chars", i)
		}
	}
	assert.NotEmpty(t, encoded)
}

func TestBase64RFC2045_ShortInput(t *testing.T) {
	encoded := base64RFC2045([]byte("hello"))
	assert.Contains(t, encoded, "aGVsbG8=")
	assert.True(t, encoded[len(encoded)-1] == '\n', "should end with newline")
}

func TestBase64RFC2045_EmptyInput(t *testing.T) {
	encoded := base64RFC2045([]byte{})
	assert.Equal(t, "", encoded)
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// ── faviconHash ───────────────────────────────────────────────────────────────

func TestFaviconHash_Deterministic(t *testing.T) {
	body := []byte("fake-favicon-data")
	h1 := faviconHash(body)
	h2 := faviconHash(body)
	assert.Equal(t, h1, h2, "same input must produce same hash")
}

func TestFaviconHash_DifferentInputDifferentHash(t *testing.T) {
	h1 := faviconHash([]byte("favicon-a"))
	h2 := faviconHash([]byte("favicon-b"))
	assert.NotEqual(t, h1, h2, "different favicons should produce different hashes")
}

// ── parseShodanResponse ───────────────────────────────────────────────────────

func TestParseShodanResponse_ExtractsIPsAndHostnames(t *testing.T) {
	resp := shodanResponse{
		Matches: []shodanMatch{
			{IPStr: "1.2.3.4", Hostnames: []string{"origin.example.com"}},
			{IPStr: "5.6.7.8", Hostnames: []string{"staging.example.com", "INTERNAL.example.COM."}},
			{IPStr: "2001:db8::1", Hostnames: []string{"ipv6.example.com"}},
		},
	}
	body, _ := json.Marshal(resp)
	input := plugins.Input{OrgName: "Acme", Domain: "example.com"}

	accumulator := make(faviconFindingMap)
	err := parseShodanResponse(body, -12345, input, accumulator)
	require.NoError(t, err)
	findings := sortedFaviconFindings(accumulator)

	var domains, cidrs []string
	for _, f := range findings {
		switch f.Type {
		case plugins.FindingDomain:
			domains = append(domains, f.Value)
		case plugins.FindingCIDR:
			cidrs = append(cidrs, f.Value)
		}
		assert.Equal(t, "favicon-hash", f.Source)
		assert.Equal(t, int32(-12345), f.Data["favicon_hash"])
		assert.Equal(t, "Acme", f.Data["org"])
		assert.Equal(t, "example.com", f.Data["source_domain"])
		assert.Equal(t, []string{"shodan"}, f.Data["scanners"])
		assert.NotContains(t, f.Data, "confidence")
		assert.NotContains(t, f.Data, "confidences")
		require.Len(t, f.Confidences, 1)
		assert.Equal(t, confFaviconScannerObservation, f.Confidences[0].Score)
		assert.NotEmpty(t, f.Confidences[0].Justification)
		assert.Contains(t, f.Confidences[0].Justification, f.Value[:strings.Index(f.Value+"/", "/")])
	}

	assert.Contains(t, cidrs, "1.2.3.4/32")
	assert.Contains(t, cidrs, "5.6.7.8/32")
	assert.Contains(t, cidrs, "2001:db8::1/128")
	assert.Contains(t, domains, "origin.example.com")
	assert.Contains(t, domains, "staging.example.com")
	assert.Contains(t, domains, "internal.example.com") // normalized
}

func TestParseShodanResponse_EmptyMatches(t *testing.T) {
	body := []byte(`{"matches":[]}`)
	findings := make(faviconFindingMap)
	err := parseShodanResponse(body, 0, plugins.Input{}, findings)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParseShodanResponse_InvalidJSON(t *testing.T) {
	findings := make(faviconFindingMap)
	err := parseShodanResponse([]byte("not-json"), 0, plugins.Input{}, findings)
	assert.Error(t, err)
	assert.Empty(t, findings)
}

// ── parseFOFAResponse ─────────────────────────────────────────────────────────

func TestParseFOFAResponse_ExtractsHostsAndIPs(t *testing.T) {
	resp := fofaResponse{
		Results: [][]string{
			{"origin.example.com", "10.0.0.1"},
			{"https://staging.example.com", "10.0.0.2"},
			{"ipv6.example.com", "2001:db8::2"},
		},
	}
	body, _ := json.Marshal(resp)
	input := plugins.Input{OrgName: "Acme", Domain: "example.com"}

	accumulator := make(faviconFindingMap)
	err := parseFOFAResponse(body, -99999, input, accumulator)
	require.NoError(t, err)
	findings := sortedFaviconFindings(accumulator)

	var domains, cidrs []string
	for _, f := range findings {
		switch f.Type {
		case plugins.FindingDomain:
			domains = append(domains, f.Value)
		case plugins.FindingCIDR:
			cidrs = append(cidrs, f.Value)
		}
		assert.Equal(t, "favicon-hash", f.Source)
		assert.Equal(t, int32(-99999), f.Data["favicon_hash"])
		assert.Equal(t, "Acme", f.Data["org"])
		assert.Equal(t, "example.com", f.Data["source_domain"])
		assert.Equal(t, []string{"fofa"}, f.Data["scanners"])
		assert.NotContains(t, f.Data, "confidence")
		assert.NotContains(t, f.Data, "confidences")
		require.Len(t, f.Confidences, 1)
		assert.Equal(t, confFaviconScannerObservation, f.Confidences[0].Score)
		assert.NotEmpty(t, f.Confidences[0].Justification)
		assert.Contains(t, f.Confidences[0].Justification, f.Value[:strings.Index(f.Value+"/", "/")])
	}

	assert.Contains(t, cidrs, "10.0.0.1/32")
	assert.Contains(t, cidrs, "10.0.0.2/32")
	assert.Contains(t, cidrs, "2001:db8::2/128")
	assert.Contains(t, domains, "origin.example.com")
	assert.Contains(t, domains, "staging.example.com")
}

func TestParseFOFAResponse_ShortResult(t *testing.T) {
	body := []byte(`{"results":[["only-host"]]}`)
	findings := make(faviconFindingMap)
	err := parseFOFAResponse(body, 0, plugins.Input{}, findings)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParseFOFAResponse_EmptyResults(t *testing.T) {
	body := []byte(`{"results":[]}`)
	findings := make(faviconFindingMap)
	err := parseFOFAResponse(body, 0, plugins.Input{}, findings)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// ── finding aggregation ───────────────────────────────────────────────────────

func TestFaviconFindingAggregation_DeduplicatesIdenticalScannerRows(t *testing.T) {
	body := []byte(`{"matches":[
		{"ip_str":"1.2.3.4","hostnames":["same.example.com"]},
		{"ip_str":"1.2.3.4","hostnames":["same.example.com"]}
	]}`)
	findings := make(faviconFindingMap)
	require.NoError(t, parseShodanResponse(body, -12345, plugins.Input{Domain: "example.com"}, findings))

	require.Len(t, findings, 2)
	for _, finding := range findings {
		require.Len(t, finding.Confidences, 1)
		assert.Equal(t, confFaviconScannerObservation, plugins.TotalConfidence(finding))
	}
}

func TestFaviconFindingAggregation_CorroboratesAcrossScanners(t *testing.T) {
	findings := make(faviconFindingMap)
	input := plugins.Input{OrgName: "Acme", Domain: "example.com"}
	require.NoError(t, parseShodanResponse(
		[]byte(`{"matches":[{"ip_str":"1.2.3.4","hostnames":["same.example.com"]}]}`),
		-12345, input, findings))
	require.NoError(t, parseFOFAResponse(
		[]byte(`{"results":[["same.example.com","1.2.3.4"]]}`),
		-12345, input, findings))

	require.Len(t, findings, 2, "domain and CIDR findings must remain distinct")
	for _, finding := range findings {
		assert.Equal(t, []string{"fofa", "shodan"}, finding.Data["scanners"])
		require.Len(t, finding.Confidences, 2)
		assert.Equal(t, 100, plugins.TotalConfidence(finding))
		assert.Contains(t, finding.Confidences[0].Justification, "Shodan")
		assert.Contains(t, finding.Confidences[1].Justification, "FOFA")
	}
}

func TestFaviconFindingAggregation_KeepsSameValueForDifferentTypes(t *testing.T) {
	findings := make(faviconFindingMap)
	input := plugins.Input{Domain: "example.com"}
	addFaviconEvidence(findings, faviconObservation{
		scanner: "shodan", findingType: plugins.FindingDomain, value: "shared.example",
	}, 1, input)
	addFaviconEvidence(findings, faviconObservation{
		scanner: "shodan", findingType: plugins.FindingCIDR, value: "shared.example",
	}, 1, input)

	assert.Len(t, findings, 2)
}

func TestFaviconFindingAggregation_OmitsUnavailableAssociatedIP(t *testing.T) {
	findings := make(faviconFindingMap)
	require.NoError(t, parseFOFAResponse(
		[]byte(`{"results":[["origin.example.com",""]]}`),
		-12345, plugins.Input{Domain: "example.com"}, findings))

	domain := findings[faviconFindingKey{findingType: plugins.FindingDomain, value: "origin.example.com"}]
	require.Len(t, domain.Confidences, 1)
	assert.Equal(t,
		`FOFA observed hostname "origin.example.com" with favicon hash -12345 matching the favicon fetched from domain "example.com"`,
		domain.Confidences[0].Justification)
	assert.NotContains(t, domain.Confidences[0].Justification, `IP ""`)
}

func TestFaviconFindingAggregation_PreservesDistinctAssociatedIPs(t *testing.T) {
	body := []byte(`{"results":[
		["origin.example.com","1.2.3.4"],
		["origin.example.com","5.6.7.8"]
	]}`)
	findings := make(faviconFindingMap)
	require.NoError(t, parseFOFAResponse(body, -12345, plugins.Input{Domain: "example.com"}, findings))

	domain := findings[faviconFindingKey{findingType: plugins.FindingDomain, value: "origin.example.com"}]
	require.Len(t, domain.Confidences, 2)
	assert.Contains(t, domain.Confidences[0].Justification, `"1.2.3.4"`)
	assert.Contains(t, domain.Confidences[1].Justification, `"5.6.7.8"`)
}

func TestSortedFaviconFindings_IsDeterministic(t *testing.T) {
	findings := make(faviconFindingMap)
	input := plugins.Input{Domain: "example.com"}
	addFaviconEvidence(findings, faviconObservation{scanner: "shodan", findingType: plugins.FindingDomain, value: "z.example.com"}, 1, input)
	addFaviconEvidence(findings, faviconObservation{scanner: "shodan", findingType: plugins.FindingCIDR, value: "2.2.2.2/32", associatedIP: "2.2.2.2"}, 1, input)
	addFaviconEvidence(findings, faviconObservation{scanner: "shodan", findingType: plugins.FindingDomain, value: "a.example.com"}, 1, input)

	ordered := sortedFaviconFindings(findings)
	require.Len(t, ordered, 3)
	assert.Equal(t, []string{"2.2.2.2/32", "a.example.com", "z.example.com"}, []string{
		ordered[0].Value, ordered[1].Value, ordered[2].Value,
	})
}

// ── normalizeDomain ───────────────────────────────────────────────────────────

func TestNormalizeFaviconHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  example.com  ", "example.com"},
		{"https://www.example.com/path", "www.example.com"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeFaviconHost(tt.input))
		})
	}
}

// ── Run integration (mock servers) ────────────────────────────────────────────

func newFaviconTestPlugin(faviconSrv, shodanSrv, fofaSrv *httptest.Server) *FaviconHashPlugin {
	p := &FaviconHashPlugin{client: client.New()}
	if faviconSrv != nil {
		p.faviconURL = faviconSrv.URL
	}
	if shodanSrv != nil {
		p.shodanURL = shodanSrv.URL
	}
	if fofaSrv != nil {
		p.fofaURL = fofaSrv.URL
	}
	return p
}

func mockFaviconServer(body []byte, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

func mockShodanServer(matches []shodanMatch) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(shodanResponse{Matches: matches})
	}))
}

func mockFOFAServer(results [][]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fofaResponse{Results: results})
	}))
}

func TestFaviconHashPlugin_Run_ShodanOnly(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	t.Setenv("FOFA_API_KEY", "")

	faviconSrv := mockFaviconServer([]byte("fake-favicon"), http.StatusOK)
	defer faviconSrv.Close()

	shodanSrv := mockShodanServer([]shodanMatch{
		{IPStr: "1.2.3.4", Hostnames: []string{"origin.example.com"}},
	})
	defer shodanSrv.Close()

	p := newFaviconTestPlugin(faviconSrv, shodanSrv, nil)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Domain:  "example.com",
	})

	require.NoError(t, err)
	require.NotEmpty(t, findings)

	var domains, cidrs []string
	for _, f := range findings {
		assert.Equal(t, "favicon-hash", f.Source)
		require.Len(t, f.Confidences, 1)
		assert.Equal(t, confFaviconScannerObservation, plugins.TotalConfidence(f))
		assert.True(t, plugins.NeedsReview(f))
		assert.Equal(t, []string{"shodan"}, f.Data["scanners"])
		switch f.Type {
		case plugins.FindingDomain:
			domains = append(domains, f.Value)
		case plugins.FindingCIDR:
			cidrs = append(cidrs, f.Value)
		}
	}
	assert.Contains(t, cidrs, "1.2.3.4/32")
	assert.Contains(t, domains, "origin.example.com")
}

func TestFaviconHashPlugin_Run_ShodanAndFOFA(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	t.Setenv("FOFA_API_KEY", "test-fofa-key")

	faviconSrv := mockFaviconServer([]byte("fake-favicon"), http.StatusOK)
	defer faviconSrv.Close()

	shodanSrv := mockShodanServer([]shodanMatch{
		{IPStr: "1.2.3.4", Hostnames: []string{"cdn.example.com"}},
	})
	defer shodanSrv.Close()

	fofaSrv := mockFOFAServer([][]string{
		{"staging.example.com", "10.0.0.1"},
	})
	defer fofaSrv.Close()

	p := newFaviconTestPlugin(faviconSrv, shodanSrv, fofaSrv)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Domain:  "example.com",
	})

	require.NoError(t, err)

	var domains, cidrs []string
	for _, f := range findings {
		require.Len(t, f.Confidences, 1)
		assert.Equal(t, confFaviconScannerObservation, plugins.TotalConfidence(f))
		switch f.Type {
		case plugins.FindingDomain:
			domains = append(domains, f.Value)
		case plugins.FindingCIDR:
			cidrs = append(cidrs, f.Value)
		}
		if strings.Contains(f.Value, "cdn.example.com") || strings.Contains(f.Value, "1.2.3.4") {
			assert.Equal(t, []string{"shodan"}, f.Data["scanners"])
			assert.Contains(t, f.Confidences[0].Justification, "Shodan")
		} else {
			assert.Equal(t, []string{"fofa"}, f.Data["scanners"])
			assert.Contains(t, f.Confidences[0].Justification, "FOFA")
		}
	}
	assert.Contains(t, cidrs, "1.2.3.4/32")
	assert.Contains(t, cidrs, "10.0.0.1/32")
	assert.Contains(t, domains, "cdn.example.com")
	assert.Contains(t, domains, "staging.example.com")
}

func TestFaviconHashPlugin_Run_DeduplicatesAcrossScanners(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	t.Setenv("FOFA_API_KEY", "test-fofa-key")

	faviconSrv := mockFaviconServer([]byte("fake-favicon"), http.StatusOK)
	defer faviconSrv.Close()

	shodanSrv := mockShodanServer([]shodanMatch{
		{IPStr: "1.2.3.4", Hostnames: []string{"same.example.com"}},
	})
	defer shodanSrv.Close()

	fofaSrv := mockFOFAServer([][]string{
		{"same.example.com", "1.2.3.4"},
	})
	defer fofaSrv.Close()

	p := newFaviconTestPlugin(faviconSrv, shodanSrv, fofaSrv)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Domain:  "example.com",
	})
	require.NoError(t, err)

	domainCount := 0
	cidrCount := 0
	for _, f := range findings {
		if f.Type == plugins.FindingDomain && f.Value == "same.example.com" {
			domainCount++
		}
		if f.Type == plugins.FindingCIDR && f.Value == "1.2.3.4/32" {
			cidrCount++
		}
		assert.Equal(t, []string{"fofa", "shodan"}, f.Data["scanners"])
		require.Len(t, f.Confidences, 2)
		assert.Equal(t, 100, plugins.TotalConfidence(f))
		assert.Contains(t, f.Confidences[0].Justification, "Shodan")
		assert.Contains(t, f.Confidences[1].Justification, "FOFA")
	}
	assert.Equal(t, 1, domainCount, "duplicate domain should be aggregated")
	assert.Equal(t, 1, cidrCount, "duplicate CIDR should be aggregated")
}

func TestFaviconHashPlugin_Run_IPv6ScannerResultsUseHostPrefixes(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	t.Setenv("FOFA_API_KEY", "test-fofa-key")

	faviconSrv := mockFaviconServer([]byte("fake-favicon"), http.StatusOK)
	defer faviconSrv.Close()
	shodanSrv := mockShodanServer([]shodanMatch{
		{IPStr: "2001:db8::1", Hostnames: []string{"ipv6.example.com"}},
	})
	defer shodanSrv.Close()
	fofaSrv := mockFOFAServer([][]string{
		{"ipv6.example.com", "2001:db8::1"},
	})
	defer fofaSrv.Close()

	p := newFaviconTestPlugin(faviconSrv, shodanSrv, fofaSrv)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Domain:  "example.com",
	})
	require.NoError(t, err)

	var ipv6Finding plugins.Finding
	for _, finding := range findings {
		if finding.Type == plugins.FindingCIDR {
			ipv6Finding = finding
		}
		assert.NotEqual(t, "2001:db8::/32", finding.Value)
	}
	require.Equal(t, "2001:db8::1/128", ipv6Finding.Value)
	assert.Equal(t, []string{"fofa", "shodan"}, ipv6Finding.Data["scanners"])
	require.Len(t, ipv6Finding.Confidences, 2)
}

func TestFaviconHashPlugin_Run_GracefulOnFaviconHTTPError(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	t.Setenv("FOFA_API_KEY", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	p := newFaviconTestPlugin(srv, nil, nil)
	p.faviconURL = srv.URL
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Domain:  "example.com",
	})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestFaviconHashPlugin_Run_GracefulOnFaviconNetworkError(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	t.Setenv("FOFA_API_KEY", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	p := newFaviconTestPlugin(srv, nil, nil)
	p.client = client.NewNoRetry()
	p.faviconURL = "http://127.0.0.1:1" // connection refused
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Domain:  "example.com",
	})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestFaviconHashPlugin_Run_EmptyFavicon(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	t.Setenv("FOFA_API_KEY", "")

	faviconSrv := mockFaviconServer([]byte{}, http.StatusOK)
	defer faviconSrv.Close()

	p := newFaviconTestPlugin(faviconSrv, nil, nil)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Domain:  "example.com",
	})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestFaviconHashPlugin_Run_GracefulOnShodanError(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "test-key")
	t.Setenv("FOFA_API_KEY", "")

	faviconSrv := mockFaviconServer([]byte("favicon"), http.StatusOK)
	defer faviconSrv.Close()

	shodanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer shodanSrv.Close()

	p := newFaviconTestPlugin(faviconSrv, shodanSrv, nil)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Domain:  "example.com",
	})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

// ── Registry ──────────────────────────────────────────────────────────────────

func TestFaviconHashPlugin_IsRegistered(t *testing.T) {
	_, ok := plugins.Get("favicon-hash")
	assert.True(t, ok)
}

func TestFaviconHashPlugin_AppearsInList(t *testing.T) {
	found := false
	for _, n := range plugins.List() {
		if n == "favicon-hash" {
			found = true
			break
		}
	}
	assert.True(t, found)
}
