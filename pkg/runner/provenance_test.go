package runner

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upstreamValues returns the values carried in input.UpstreamFindings, for
// assertions that care about the set rather than the evidence.
func upstreamValues(input plugins.Input) []string {
	values := make([]string, 0, len(input.UpstreamFindings))
	for _, f := range input.UpstreamFindings {
		values = append(values, f.Value)
	}
	return values
}

// ── enrichWithHandles provenance ─────────────────────────────────────────────

// TestEnrichWithHandles_CarriesConfidence is the core of the provenance
// contract: a Phase 2 plugin resolving ACME-1 must be able to see that
// reverse-rir found it, and why.
func TestEnrichWithHandles_CarriesConfidence(t *testing.T) {
	handle := scored(plugins.FindingCIDRHandle, "ACME-1", "reverse-rir", 0.45,
		`ARIN organization search for "Acme Corp" returned handle "ACME-1"`,
		map[string]any{"registry": "arin"})

	result := enrichWithHandles(plugins.Input{OrgName: "Acme Corp"}, []plugins.Finding{handle})

	// The value-only view is unchanged.
	assert.Equal(t, "ACME-1", result.Meta["arin_handles"])

	require.Len(t, result.UpstreamFindings, 1)
	carried := result.UpstreamFindings[0]
	assert.Equal(t, "ACME-1", carried.Value)
	assert.Equal(t, "reverse-rir", carried.Source)
	require.Len(t, carried.Confidences, 1, "evidence must survive enrichment")
	assert.Equal(t, `ARIN organization search for "Acme Corp" returned handle "ACME-1"`, carried.Confidences[0].Justification)
	assert.InDelta(t, 0.45, carried.Confidences[0].Score, 0.001)
}

// TestEnrichWithHandles_UnknownRegistryBroadcastKeepsOneProvenance pins the
// asymmetry between the two views: EDGAR's handle goes to all five registries
// in Meta because nobody knows which one will recognize it, but it remains a
// single discovery. Five copies would let whichever registry resolves it claim
// five pieces of evidence for one filing.
func TestEnrichWithHandles_UnknownRegistryBroadcastKeepsOneProvenance(t *testing.T) {
	handle := scored(plugins.FindingCIDRHandle, "EDGAR-HANDLE", "edgar", 0.40,
		`SEC EDGAR filing for "Acme Corp" contained the RIR-style handle "EDGAR-HANDLE"`,
		map[string]any{"registry": plugins.RegistryUnknown, "org": "Acme Corp"})

	result := enrichWithHandles(plugins.Input{OrgName: "Acme Corp"}, []plugins.Finding{handle})

	for _, registry := range []string{"arin", "ripe", "apnic", "afrinic", "lacnic"} {
		assert.Equal(t, "EDGAR-HANDLE", result.Meta[registry+"_handles"], "registry %s", registry)
	}

	require.Len(t, result.UpstreamFindings, 1, "one discovery, one piece of provenance")
	assert.Equal(t, "edgar", result.UpstreamFindings[0].Source)
	require.Len(t, result.UpstreamFindings[0].Confidences, 1)
}

// TestEnrichWithHandles_IndependentDiscoveriesBothSurvive is why Source is part
// of the dedup key. Meta lists the handle twice and the lookup collapses to one
// query, but two plugins finding it independently is corroboration a consumer
// composes into two entries.
func TestEnrichWithHandles_IndependentDiscoveriesBothSurvive(t *testing.T) {
	fromRIR := scored(plugins.FindingCIDRHandle, "ACME-1", "reverse-rir", 0.45,
		"ARIN organization search returned the handle", map[string]any{"registry": "arin"})
	fromEDGAR := scored(plugins.FindingCIDRHandle, "ACME-1", "edgar", 0.40,
		"SEC EDGAR filing contained the handle", map[string]any{"registry": "arin"})

	result := enrichWithHandles(plugins.Input{OrgName: "Acme Corp"}, []plugins.Finding{fromRIR, fromEDGAR})

	require.Len(t, result.UpstreamFindings, 2)
	assert.Equal(t, []string{"reverse-rir", "edgar"}, []string{
		result.UpstreamFindings[0].Source,
		result.UpstreamFindings[1].Source,
	})
}

// TestEnrichWithHandles_RepeatedObservationDeduped is the other half: the same
// plugin reporting the same handle twice is one sighting, not corroboration.
func TestEnrichWithHandles_RepeatedObservationDeduped(t *testing.T) {
	handle := plugins.Finding{
		Type: plugins.FindingCIDRHandle, Value: "ACME-1", Source: "reverse-rir",
		Data: map[string]any{"registry": "arin"},
	}

	result := enrichWithHandles(plugins.Input{}, []plugins.Finding{handle, handle})

	assert.Len(t, result.UpstreamFindings, 1)
}

func TestEnrichWithHandles_IgnoresNonHandleProvenance(t *testing.T) {
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "203.0.113.0/24", Source: "arin"},
		{Type: plugins.FindingDomain, Value: "acme.com", Source: "crt-sh"},
		{Type: plugins.FindingCIDRHandle, Value: "ACME-1", Source: "reverse-rir",
			Data: map[string]any{"registry": "arin"}},
	}

	result := enrichWithHandles(plugins.Input{}, findings)

	assert.Equal(t, []string{"ACME-1"}, upstreamValues(result))
}

// ── enrichWithDomains provenance ─────────────────────────────────────────────

func TestEnrichWithDomains_CarriesConfidence(t *testing.T) {
	domain := scored(plugins.FindingDomain, "api.acme.com", "crt-sh", 0.70,
		`Certificate Transparency logs contain "api.acme.com" in results for known domain "acme.com"`, nil)

	result := enrichWithDomains(plugins.Input{Domain: "acme.com"}, []plugins.Finding{domain})

	assert.Equal(t, "api.acme.com", result.Meta["discovered_domains"])
	require.Len(t, result.UpstreamFindings, 1)
	require.Len(t, result.UpstreamFindings[0].Confidences, 1)
	assert.Equal(t, "crt-sh", result.UpstreamFindings[0].Source)
}

// TestEnrichWithDomains_JunkDomainsCarryNoProvenance keeps the two views
// consistent: a domain the junk filter removed from Meta must not be
// attributable through UpstreamFindings either, or a consumer could credit work
// to a seed the pipeline deliberately refused to hand it.
func TestEnrichWithDomains_JunkDomainsCarryNoProvenance(t *testing.T) {
	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "api.acme.com", Source: "crt-sh"},
		{Type: plugins.FindingDomain, Value: "a7f3c9e1b4d28f6a0c5e3b9d7f1a4c8e.acme.com", Source: "crt-sh"},
	}

	result := enrichWithDomains(plugins.Input{Domain: "acme.com"}, findings)

	// The filter must actually have fired, or this test proves nothing.
	require.Equal(t, "api.acme.com", result.Meta["discovered_domains"],
		"the high-entropy domain should have been filtered out of Meta")

	assert.Equal(t, []string{"api.acme.com"}, upstreamValues(result),
		"provenance must cover exactly the domains that survived the filter")
}

func TestEnrichWithDomains_SameDomainFromTwoSourcesBothSurvive(t *testing.T) {
	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "api.acme.com", Source: "crt-sh"},
		{Type: plugins.FindingDomain, Value: "api.acme.com", Source: "passive-dns"},
	}

	result := enrichWithDomains(plugins.Input{}, findings)

	assert.Equal(t, "api.acme.com", result.Meta["discovered_domains"], "Meta dedupes by value")
	assert.Len(t, result.UpstreamFindings, 2, "two independent observations both count")
}

// ── enrichWithCIDRs provenance ───────────────────────────────────────────────

func TestEnrichWithCIDRs_CarriesConfidence(t *testing.T) {
	cidr := scored(plugins.FindingCIDR, "203.0.113.0/24", "arin", 0.45,
		`ARIN maps CIDR "203.0.113.0/24" to handle "ACME-1"`, nil)

	result := enrichWithCIDRs(plugins.Input{}, []plugins.Finding{cidr})

	assert.Equal(t, "203.0.113.0/24", result.Meta["cidrs"])
	require.Len(t, result.UpstreamFindings, 1)
	require.Len(t, result.UpstreamFindings[0].Confidences, 1)
}

// ── accumulation across enrichment passes ────────────────────────────────────

// TestEnrichment_AccumulatesAcrossPasses mirrors the real Phase 3 input, which
// is enriched with CIDRs and then with domains. The second pass must not
// discard or overwrite the first pass's provenance.
func TestEnrichment_AccumulatesAcrossPasses(t *testing.T) {
	handles := []plugins.Finding{
		{Type: plugins.FindingCIDRHandle, Value: "ACME-1", Source: "reverse-rir",
			Data: map[string]any{"registry": "arin"}},
	}
	cidrs := []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "203.0.113.0/24", Source: "arin"},
	}
	domains := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "api.acme.com", Source: "crt-sh"},
	}

	input := enrichWithHandles(plugins.Input{OrgName: "Acme Corp"}, handles)
	input = enrichWithCIDRs(input, cidrs)
	input = enrichWithDomains(input, domains)

	assert.Equal(t, []string{"ACME-1", "203.0.113.0/24", "api.acme.com"}, upstreamValues(input))
	assert.Equal(t, "ACME-1", input.Meta["arin_handles"])
	assert.Equal(t, "203.0.113.0/24", input.Meta["cidrs"])
	assert.Equal(t, "api.acme.com", input.Meta["discovered_domains"])
}

// TestEnrichment_DoesNotMutateCallerInput guards the aliasing bug: enrichment
// returns a copy, so a second enrichment of the same base input cannot be seen
// by the first result.
func TestEnrichment_DoesNotMutateCallerInput(t *testing.T) {
	base := enrichWithHandles(
		plugins.Input{OrgName: "Acme Corp"},
		[]plugins.Finding{{Type: plugins.FindingCIDRHandle, Value: "ACME-1", Source: "reverse-rir",
			Data: map[string]any{"registry": "arin"}}},
	)
	require.Len(t, base.UpstreamFindings, 1)

	first := enrichWithCIDRs(base, []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "203.0.113.0/24", Source: "arin"},
	})
	second := enrichWithCIDRs(base, []plugins.Finding{
		{Type: plugins.FindingCIDR, Value: "198.51.100.0/24", Source: "ripe"},
	})

	assert.Len(t, base.UpstreamFindings, 1, "the base input must be untouched")
	assert.Equal(t, []string{"ACME-1", "203.0.113.0/24"}, upstreamValues(first))
	assert.Equal(t, []string{"ACME-1", "198.51.100.0/24"}, upstreamValues(second))
	assert.Equal(t, "203.0.113.0/24", first.Meta["cidrs"])
	assert.Equal(t, "198.51.100.0/24", second.Meta["cidrs"])
}

// TestEnrichment_MetaCompatibilityUnchanged is the regression guard for readers
// that predate UpstreamFindings: adding the structured view must not alter a
// single Meta key.
func TestEnrichment_MetaCompatibilityUnchanged(t *testing.T) {
	input := plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"arin_handles": "EXISTING-1", "doh_servers": "https://dns.example"},
	}
	findings := []plugins.Finding{
		{Type: plugins.FindingCIDRHandle, Value: "NEW-1", Source: "reverse-rir",
			Data: map[string]any{"registry": "arin"}},
	}

	result := enrichWithHandles(input, findings)

	assert.Equal(t, "EXISTING-1,NEW-1", result.Meta["arin_handles"])
	assert.Equal(t, "https://dns.example", result.Meta["doh_servers"], "unrelated meta survives")
}
