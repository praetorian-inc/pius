package cidrs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handleFinding builds an upstream handle discovery for provenance tests.
func handleFinding(handle, source, registry, org string, score float64, justification string) plugins.Finding {
	f := plugins.Finding{
		Type:   plugins.FindingCIDRHandle,
		Value:  handle,
		Source: source,
		Data:   map[string]any{"registry": registry, "org": org},
	}
	plugins.AddConfidence(&f, score, justification)
	return f
}

// ── handleProvenance ─────────────────────────────────────────────────────────

func TestHandleProvenance_MatchesHandleAndRegistry(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		handleFinding("ACME-1", "reverse-rir", "arin", "Acme Corp", 0.45, "ARIN organization search"),
		handleFinding("OTHER-1", "reverse-rir", "arin", "Acme Corp", 0.45, "ARIN organization search"),
	}}

	matches := handleProvenance(input, "ACME-1", "arin")

	require.Len(t, matches, 1)
	assert.Equal(t, "ACME-1", matches[0].Value)
}

func TestHandleProvenance_HandleMatchIsCaseAndSpaceInsensitive(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		handleFinding("ACME-1", "reverse-rir", "arin", "Acme Corp", 0.45, "ARIN organization search"),
	}}

	assert.Len(t, handleProvenance(input, " acme-1 ", "ARIN"), 1)
}

// TestHandleProvenance_ExcludesOtherRegistries stops RIPE's handle from
// explaining an ARIN netblock.
func TestHandleProvenance_ExcludesOtherRegistries(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		handleFinding("ACME-1", "reverse-rir", "ripe", "Acme Corp", 0.45, "RIPE organisation search"),
	}}

	assert.Empty(t, handleProvenance(input, "ACME-1", "arin"))
}

// TestHandleProvenance_UnknownRegistryMatchesEveryRegistry is the EDGAR case: a
// handle scraped from a filing has no registry, the runner broadcasts it to all
// five, and whichever one resolves it must still be able to cite the filing.
func TestHandleProvenance_UnknownRegistryMatchesEveryRegistry(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		handleFinding("ACME-1", "edgar", "unknown", "Acme Corp", 0.40, "SEC EDGAR filing"),
	}}

	for _, registry := range []string{"arin", "ripe", "apnic", "afrinic", "lacnic"} {
		assert.Len(t, handleProvenance(input, "ACME-1", registry), 1, "registry %s", registry)
	}
}

func TestHandleProvenance_IgnoresNonHandleFindings(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "ACME-1", Source: "arin",
			Data: map[string]any{"registry": "arin"}},
	}}

	assert.Empty(t, handleProvenance(input, "ACME-1", "arin"))
}

func TestHandleProvenance_NoUpstreamFindings(t *testing.T) {
	assert.Empty(t, handleProvenance(plugins.Input{}, "ACME-1", "arin"))
}

// ── composeHandleEvidence ────────────────────────────────────────────────────

// TestComposeHandleEvidence_ComposesRatherThanSums is the central rule. The
// org-name search and the registry mapping are one chain: 0.45 + 0.85 would
// clear the clean threshold outright, asserting near-certainty about what began
// as a substring match on a company name.
func TestComposeHandleEvidence_ComposesRatherThanSums(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		handleFinding("ACME-1", "reverse-rir", "arin", "Acme Corp", 0.45,
			`ARIN organization search for "Acme Corp" returned handle "ACME-1"`),
	}}

	confidences := composeHandleEvidence(handleProvenance(input, "ACME-1", "arin"), registryMapping{
		registry: "arin", handle: "ACME-1", cidr: "203.0.113.0/24",
	})

	require.Len(t, confidences, 1, "a chain is one entry, not two")
	assert.InDelta(t, 0.45, confidences[0].Score, 0.001, "bounded by the weaker leg")

	finding := plugins.Finding{Confidences: confidences}
	assert.InDelta(t, 0.45, plugins.TotalConfidence(finding), 0.001)
	assert.True(t, plugins.NeedsReview(finding), "an org-name guess must not resolve into a clean finding")
}

func TestComposeHandleEvidence_JustificationCarriesBothLegs(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		handleFinding("ACME-1", "reverse-rir", "arin", "Acme Corp", 0.45, "ARIN organization search"),
	}}

	confidences := composeHandleEvidence(handleProvenance(input, "ACME-1", "arin"), registryMapping{
		registry: "arin", handle: "ACME-1", cidr: "203.0.113.0/24",
	})

	require.Len(t, confidences, 1)
	assert.Equal(t,
		`ARIN maps CIDR "203.0.113.0/24" to handle "ACME-1", which reverse-rir identified while searching for "Acme Corp"`,
		confidences[0].Justification)
}

// TestComposeHandleEvidence_IndependentSourcesAddUp is the flip side of
// composition: reverse-rir and EDGAR reaching the same handle by different
// routes corroborates the step that was actually uncertain.
func TestComposeHandleEvidence_IndependentSourcesAddUp(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		handleFinding("ACME-1", "reverse-rir", "arin", "Acme Corp", 0.45, "ARIN organization search"),
		handleFinding("ACME-1", "edgar", "unknown", "Acme Corp", 0.40, "SEC EDGAR filing"),
	}}

	confidences := composeHandleEvidence(handleProvenance(input, "ACME-1", "arin"), registryMapping{
		registry: "arin", handle: "ACME-1", cidr: "203.0.113.0/24",
	})

	require.Len(t, confidences, 2, "one entry per independent discovery")
	assert.Contains(t, confidences[0].Justification, "reverse-rir")
	assert.Contains(t, confidences[1].Justification, "edgar")
	assert.InDelta(t, 0.85, plugins.TotalConfidence(plugins.Finding{Confidences: confidences}), 0.001)
}

// TestComposeHandleEvidence_CeilingIsTheMappingLeg proves the bound runs both
// ways: strong upstream evidence cannot push the chain past what the
// deterministic lookup itself is worth.
func TestComposeHandleEvidence_CeilingIsTheMappingLeg(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		handleFinding("ACME-1", "reverse-rir", "arin", "Acme Corp", 1.0, "certain by construction"),
	}}

	confidences := composeHandleEvidence(handleProvenance(input, "ACME-1", "arin"), registryMapping{
		registry: "arin", handle: "ACME-1", cidr: "203.0.113.0/24",
	})

	require.Len(t, confidences, 1)
	assert.InDelta(t, confRegistryResolution, confidences[0].Score, 0.001)
}

// TestComposeHandleEvidence_DirectCallerGetsMappingScore covers the API caller
// who supplies handles through Meta. There is no inferred leg to bound the
// mapping, because the caller asserted the handle instead of guessing it.
func TestComposeHandleEvidence_DirectCallerGetsMappingScore(t *testing.T) {
	confidences := composeHandleEvidence(nil, registryMapping{
		registry: "arin", handle: "ACME-1", cidr: "203.0.113.0/24",
	})

	require.Len(t, confidences, 1)
	assert.InDelta(t, confRegistryResolution, confidences[0].Score, 0.001)
	assert.Equal(t, `ARIN maps CIDR "203.0.113.0/24" to handle "ACME-1"`, confidences[0].Justification)
	assert.False(t, plugins.NeedsReview(plugins.Finding{Confidences: confidences}))
}

func TestComposeHandleEvidence_NetnameAppearsWhenPresent(t *testing.T) {
	confidences := composeHandleEvidence(nil, registryMapping{
		registry: "apnic", handle: "ORG-AC1-AP", cidr: "203.0.113.0/24", netname: "ACME-AP",
	})

	require.Len(t, confidences, 1)
	assert.Contains(t, confidences[0].Justification, "netname ACME-AP")
	assert.Contains(t, confidences[0].Justification, "APNIC")
}

func TestComposeHandleEvidence_UpstreamWithoutOrgStillAttributes(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		{Type: plugins.FindingCIDRHandle, Value: "ACME-1", Source: "reverse-rir",
			Data:        map[string]any{"registry": "arin"},
			Confidences: []plugins.Confidence{{Score: 0.45, Justification: "search hit"}}},
	}}

	confidences := composeHandleEvidence(handleProvenance(input, "ACME-1", "arin"), registryMapping{
		registry: "arin", handle: "ACME-1", cidr: "203.0.113.0/24",
	})

	require.Len(t, confidences, 1)
	assert.Contains(t, confidences[0].Justification, "which reverse-rir identified")
	assert.NotContains(t, confidences[0].Justification, "searching for")
}

// ── reverse-rir ──────────────────────────────────────────────────────────────

func TestArinMatch_SingleEntitySearch(t *testing.T) {
	match := &arinMatch{handle: "ACME-1", name: "Acme Corporation", entities: []string{"orgs"}}

	finding := match.finding("Acme Corp")

	require.Len(t, finding.Confidences, 1)
	assert.InDelta(t, confReverseRIROrgSearch, finding.Confidences[0].Score, 0.001)
	assert.Equal(t,
		`ARIN organization search for "Acme Corp" returned handle "ACME-1" ("Acme Corporation")`,
		finding.Confidences[0].Justification)
	assert.Equal(t, "orgs", finding.Data["entity_types"])
	assert.Equal(t, "arin", finding.Data["registry"])
}

// TestArinMatch_RepeatedEntityTypesDoNotInflate is rule 3 in miniature: four
// ARIN searches run the same name pattern against four record types, so a
// handle matched by two of them was matched by the same reasoning twice.
func TestArinMatch_RepeatedEntityTypesDoNotInflate(t *testing.T) {
	match := &arinMatch{handle: "ACME-1", entities: []string{"orgs", "nets", "asns"}}

	finding := match.finding("Acme Corp")

	require.Len(t, finding.Confidences, 1, "three searches, one signal")
	assert.InDelta(t, confReverseRIROrgSearch, plugins.TotalConfidence(finding), 0.001)
	assert.Contains(t, finding.Confidences[0].Justification,
		"organization, network and ASN searches", "which searches matched is still on the record")
	assert.Equal(t, "orgs,nets,asns", finding.Data["entity_types"])
}

func TestArinMatch_TwoEntityTypesReadAsProse(t *testing.T) {
	match := &arinMatch{handle: "ACME-1", entities: []string{"orgs", "customers"}}

	finding := match.finding("Acme Corp")

	assert.Contains(t, finding.Confidences[0].Justification, "organization and customer searches")
}

func TestArinMatch_NoNameOmitsDisplayName(t *testing.T) {
	match := &arinMatch{handle: "ACME-1", entities: []string{"orgs"}}

	finding := match.finding("Acme Corp")

	assert.Equal(t, `ARIN organization search for "Acme Corp" returned handle "ACME-1"`,
		finding.Confidences[0].Justification)
	assert.NotContains(t, finding.Data, "name")
}

// TestReverseRIR_AllRegistriesScoreAtReviewLevel pins the calibration decision:
// no name search, at any registry, produces a clean finding on its own.
func TestReverseRIR_AllRegistriesScoreAtReviewLevel(t *testing.T) {
	assert.Less(t, confReverseRIROrgSearch, plugins.ConfidenceHigh)
	assert.GreaterOrEqual(t, confReverseRIROrgSearch, plugins.ConfidenceLow)
}

// ── edgar ────────────────────────────────────────────────────────────────────

func TestEdgarJustification_NamesTheFiling(t *testing.T) {
	justification := edgarJustification("Acme Corp", "ACME-1", edgarSource{
		EntityName: "Acme Corporation", FormType: "10-K", FileNum: "001-12345",
	})

	assert.Equal(t,
		`SEC EDGAR filing for "Acme Corp" contained the RIR-style handle "ACME-1", filed under entity "Acme Corporation" (form 10-K, file 001-12345)`,
		justification)
}

func TestEdgarJustification_OmitsMissingFilingMetadata(t *testing.T) {
	justification := edgarJustification("Acme Corp", "ACME-1", edgarSource{EntityName: "Acme Corp"})

	assert.Equal(t, `SEC EDGAR filing for "Acme Corp" contained the RIR-style handle "ACME-1"`,
		justification)
}

func TestEdgarJustification_FormWithoutFileNum(t *testing.T) {
	justification := edgarJustification("Acme Corp", "ACME-1", edgarSource{FormType: "8-K"})

	assert.Contains(t, justification, "(form 8-K)")
}

// TestEdgarConfidence_IsTheWeakestHandleDiscovery keeps the two handle sources
// ordered: a name-matched filing containing a handle-shaped token is weaker
// evidence than the registry itself returning the handle.
func TestEdgarConfidence_IsTheWeakestHandleDiscovery(t *testing.T) {
	assert.Less(t, confEDGARHandleExtraction, confReverseRIROrgSearch)
	assert.GreaterOrEqual(t, confEDGARHandleExtraction, plugins.ConfidenceLow)
}

// ── rdap Run ─────────────────────────────────────────────────────────────────

func TestRDAPPlugin_Run_ComposesUpstreamEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"handle":"ACME-1","networks":[{"cidr0_cidrs":[{"v4prefix":"203.0.113.0","length":24}]}]}`)
	}))
	defer srv.Close()

	p := &rdapPlugin{
		cfg:  rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		doer: &mockHTTPDoer{server: srv},
	}
	input := plugins.Input{
		OrgName:          "Acme Corp",
		Meta:             map[string]string{"arin_handles": "ACME-1"},
		UpstreamFindings: []plugins.Finding{handleFinding("ACME-1", "reverse-rir", "arin", "Acme Corp", 0.45, "ARIN organization search")},
	}

	findings, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	require.Len(t, findings[0].Confidences, 1)
	assert.InDelta(t, 0.45, findings[0].Confidences[0].Score, 0.001)
	assert.Contains(t, findings[0].Confidences[0].Justification, "reverse-rir")
	assert.True(t, plugins.NeedsReview(findings[0]))
}

func TestRDAPPlugin_Run_ScoresWithoutProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"handle":"ACME-1","networks":[{"cidr0_cidrs":[{"v4prefix":"203.0.113.0","length":24}]}]}`)
	}))
	defer srv.Close()

	p := &rdapPlugin{
		cfg:  rdapConfig{name: "arin", baseURL: srv.URL, metaKey: "arin_handles", registry: "arin"},
		doer: &mockHTTPDoer{server: srv},
	}

	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"arin_handles": "ACME-1"},
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	require.Len(t, findings[0].Confidences, 1, "every emitted CIDR carries evidence")
	assert.InDelta(t, confRegistryResolution, findings[0].Confidences[0].Score, 0.001)
}

// ── asn-bgp ──────────────────────────────────────────────────────────────────

func TestASNBGP_ConfidenceIsSelfContained(t *testing.T) {
	// The ASN is caller-supplied, so there is no inferred leg to bound — the
	// prefix observation stands at full strength and reads clean.
	finding := plugins.Finding{Confidences: []plugins.Confidence{{
		Score:         confASNAnnouncedPrefix,
		Justification: `RIPE RIS reports that ASN AS64500 announces prefix "203.0.113.0/24"`,
	}}}

	assert.False(t, plugins.NeedsReview(finding))
	assert.GreaterOrEqual(t, confASNAnnouncedPrefix, plugins.ConfidenceHigh)
}

// ── shodan per-query aggregation ─────────────────────────────────────────────

// shodanMatchAt builds one Shodan match for aggregation tests.
func shodanMatchAt(ip string, hostnames ...string) ShodanMatch {
	return ShodanMatch{IPStr: ip, Port: 443, Hostnames: hostnames}
}

func TestShodanProcessResults_ScoresByQueryKind(t *testing.T) {
	p := &ShodanPlugin{}
	orgQuery := shodanQuery{kind: shodanQueryOrg, value: "Acme Corp", query: `org:"Acme Corp"`}

	findings := p.processResults([]shodanObservation{
		{query: orgQuery, match: shodanMatchAt("203.0.113.4")},
	}, plugins.Input{OrgName: "Acme Corp"})

	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	assert.InDelta(t, confShodanOrgQuery, findings[0].Confidences[0].Score, 0.001)
	assert.Equal(t, `Shodan returned IP 203.0.113.4 for organization query "Acme Corp"`,
		findings[0].Confidences[0].Justification)
	assert.True(t, plugins.NeedsReview(findings[0]), "an org-name match alone must not read as clean")
}

// TestShodanProcessResults_RepeatedMatchesFromOneQueryDoNotInflate is rule 3:
// one question answered many times is still one answer.
func TestShodanProcessResults_RepeatedMatchesFromOneQueryDoNotInflate(t *testing.T) {
	p := &ShodanPlugin{}
	orgQuery := shodanQuery{kind: shodanQueryOrg, value: "Acme Corp", query: `org:"Acme Corp"`}

	findings := p.processResults([]shodanObservation{
		{query: orgQuery, match: shodanMatchAt("203.0.113.4", "api.acme.com")},
		{query: orgQuery, match: shodanMatchAt("203.0.113.4", "api.acme.com")},
		{query: orgQuery, match: ShodanMatch{IPStr: "203.0.113.5", Port: 80, Hostnames: []string{"api.acme.com"}}},
	}, plugins.Input{OrgName: "Acme Corp"})

	byValue := make(map[string]plugins.Finding)
	for _, f := range findings {
		byValue[f.Value] = f
	}

	require.Len(t, byValue["203.0.113.4/32"].Confidences, 1, "the same host twice is one sighting")
	require.Len(t, byValue["api.acme.com"].Confidences, 1,
		"one hostname on two hosts from one query is one sighting")
	assert.InDelta(t, confShodanOrgQuery, plugins.TotalConfidence(byValue["api.acme.com"]), 0.001)
}

// TestShodanProcessResults_IndependentQueryKindsAdd is the other half: a
// netblock query and an org query reach the same host by unrelated routes.
func TestShodanProcessResults_IndependentQueryKindsAdd(t *testing.T) {
	p := &ShodanPlugin{}
	orgQuery := shodanQuery{kind: shodanQueryOrg, value: "Acme Corp", query: `org:"Acme Corp"`}
	cidrQuery := shodanQuery{kind: shodanQueryCIDR, value: "203.0.113.0/24", query: "net:203.0.113.0/24"}

	findings := p.processResults([]shodanObservation{
		{query: orgQuery, match: shodanMatchAt("203.0.113.4")},
		{query: cidrQuery, match: shodanMatchAt("203.0.113.4")},
	}, plugins.Input{OrgName: "Acme Corp", CIDR: "203.0.113.0/24"})

	require.Len(t, findings, 1, "one value, aggregated")
	require.Len(t, findings[0].Confidences, 2)
	assert.Contains(t, findings[0].Confidences[0].Justification, `organization query "Acme Corp"`)
	assert.Equal(t, `Shodan returned IP 203.0.113.4 within the queried network "203.0.113.0/24"`,
		findings[0].Confidences[1].Justification)
	assert.Equal(t, "org,cidr", findings[0].Data["query_kinds"])
	assert.False(t, plugins.NeedsReview(findings[0]), "the netblock query alone clears the threshold")
}

func TestShodanProcessResults_HostnameEvidenceNamesBothHalves(t *testing.T) {
	p := &ShodanPlugin{}
	hostnameQuery := shodanQuery{kind: shodanQueryHostname, value: "acme.com", query: "hostname:acme.com"}

	findings := p.processResults([]shodanObservation{
		{query: hostnameQuery, match: shodanMatchAt("203.0.113.4", "api.acme.com")},
	}, plugins.Input{Domain: "acme.com"})

	var domain plugins.Finding
	for _, f := range findings {
		if f.Type == plugins.FindingDomain {
			domain = f
		}
	}

	require.Len(t, domain.Confidences, 1)
	assert.Equal(t,
		`Shodan associated hostname "api.acme.com" with IP 203.0.113.4, returned for hostname query "acme.com"`,
		domain.Confidences[0].Justification)
	assert.InDelta(t, confShodanHostnameQuery, domain.Confidences[0].Score, 0.001)
}

// TestShodanQueryKindOrdering pins the calibration ladder: the more of the
// answer the caller supplied, the more the result is worth.
func TestShodanQueryKindOrdering(t *testing.T) {
	assert.Greater(t, shodanQueryCIDR.score(), shodanQueryASN.score())
	assert.Greater(t, shodanQueryASN.score(), shodanQueryHostname.score())
	assert.Greater(t, shodanQueryHostname.score(), shodanQueryOrg.score())

	assert.GreaterOrEqual(t, shodanQueryCIDR.score(), plugins.ConfidenceHigh)
	assert.Less(t, shodanQueryOrg.score(), plugins.ConfidenceHigh)
}

func TestShodanProcessResults_NoObservationsYieldsNoFindings(t *testing.T) {
	p := &ShodanPlugin{}
	assert.Nil(t, p.processResults(nil, plugins.Input{}))
}

// TestShodanProcessResults_RecordsQueryKindsEvenWhenSingle keeps Data uniform, so
// a consumer never has to distinguish "one query kind" from "field absent".
func TestShodanProcessResults_RecordsQueryKindsEvenWhenSingle(t *testing.T) {
	p := &ShodanPlugin{}
	orgQuery := shodanQuery{kind: shodanQueryOrg, value: "Acme Corp", query: `org:"Acme Corp"`}

	findings := p.processResults([]shodanObservation{
		{query: orgQuery, match: shodanMatchAt("203.0.113.4")},
	}, plugins.Input{OrgName: "Acme Corp"})

	require.Len(t, findings, 1)
	assert.Equal(t, "org", findings[0].Data["query_kinds"])
}
