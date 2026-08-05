package domains

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// domainFinding builds an upstream domain discovery for provenance tests.
func domainFinding(domain, source string, score float64, justification string) plugins.Finding {
	f := plugins.Finding{Type: plugins.FindingDomain, Value: domain, Source: source}
	plugins.AddConfidence(&f, score, justification)
	return f
}

// ── domainProvenance ─────────────────────────────────────────────────────────

func TestDomainProvenance_MatchesNormalizedDomain(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		domainFinding("API.Acme.com.", "crt-sh", 0.70, "CT logs"),
	}}

	assert.Len(t, newDomainProvenance(input).find("api.acme.com"), 1)
}

func TestDomainProvenance_ReturnsEveryIndependentObservation(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		domainFinding("api.acme.com", "crt-sh", 0.70, "CT logs"),
		domainFinding("api.acme.com", "passive-dns", 0.60, "historical records"),
		domainFinding("other.acme.com", "crt-sh", 0.70, "CT logs"),
	}}

	matches := newDomainProvenance(input).find("api.acme.com")

	require.Len(t, matches, 2)
	assert.Equal(t, "crt-sh", matches[0].Source)
	assert.Equal(t, "passive-dns", matches[1].Source)
}

func TestDomainProvenance_IgnoresNonDomainFindings(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		{Type: plugins.FindingPreseed, Value: "api.acme.com", Source: "whois"},
	}}

	assert.Empty(t, newDomainProvenance(input).find("api.acme.com"))
}

// ── dns-brute / doh-enum resolution evidence ─────────────────────────────────

func TestDescribeDNSResolution_NamesWildcardRuleOut(t *testing.T) {
	assert.Equal(t,
		`DNS resolution confirmed "api.acme.com" beneath the known domain "acme.com"; wildcard DNS was not detected`,
		describeDNSResolution("api.acme.com", "acme.com", ""))
}

// TestDescribeDNSResolution_NamesTheResolverThatAnswered: the DoH leg names the
// endpoint that actually answered, so the observation can be reproduced against
// the same vantage point.
func TestDescribeDNSResolution_NamesTheResolverThatAnswered(t *testing.T) {
	assert.Equal(t,
		`DNS-over-HTTPS resolver "cloudflare" confirmed "api.acme.com" beneath the known domain "acme.com"; wildcard DNS was not detected`,
		describeDNSResolution("api.acme.com", "acme.com", "cloudflare"))
}

// TestDNSResolutionReadsClean pins the calibration: a live, non-wildcard
// resolution beneath a known domain is strong enough not to need review, and the
// transport it was observed over is not evidence either way.
func TestDNSResolutionReadsClean(t *testing.T) {
	assert.GreaterOrEqual(t, confDNSResolvedNonWildcard, plugins.ConfidenceHigh)
}

// ── AXFR evidence ────────────────────────────────────────────────────────────

func TestDescribeAXFRDisclosure_SingleNameserver(t *testing.T) {
	assert.Equal(t,
		`Authoritative nameserver "ns1.acme.com" included "api.acme.com" in a successful AXFR response for "acme.com"`,
		describeAXFRDisclosure("api.acme.com", "acme.com", []string{"ns1.acme.com:53"}))
}

// TestDescribeAXFRDisclosure_MultipleNameserversGroupIntoOneEntry is rule 3: a
// zone's servers all serve the same zone, so three of them returning a record is
// the same disclosure three times.
func TestDescribeAXFRDisclosure_MultipleNameserversGroupIntoOneEntry(t *testing.T) {
	described := describeAXFRDisclosure("api.acme.com", "acme.com",
		[]string{"ns1.acme.com:53", "ns2.acme.com:53", "ns3.acme.com:53"})

	assert.Equal(t,
		`Authoritative nameservers "ns1.acme.com", "ns2.acme.com" and "ns3.acme.com" included "api.acme.com" in a successful AXFR response for "acme.com"`,
		described)
}

func TestStripDNSPort(t *testing.T) {
	assert.Equal(t, "ns1.acme.com", stripDNSPort("ns1.acme.com:53"))
	assert.Equal(t, "ns1.acme.com", stripDNSPort("ns1.acme.com"))
	assert.Equal(t, "2001:db8::1", stripDNSPort("[2001:db8::1]:53"))
}

// TestAXFRIsTheStrongestDomainEvidence pins the ordering: the zone's own
// authoritative server beats any third-party index or resolution guess.
func TestAXFRIsTheStrongestDomainEvidence(t *testing.T) {
	assert.Greater(t, confAXFRRecord, confDNSResolvedNonWildcard)
	assert.Greater(t, confAXFRRecord, plugins.ConfidenceHigh)
	assert.Less(t, confAXFRRecord, 1.0, "registry-perfect is still not certainty")
}

// ── dns-permutation composition ──────────────────────────────────────────────

// TestComposeSeedEvidence_ComposesWithSeedProvenance is the chain rule for
// permutations: a guess derived from an uncertain seed cannot outrank the seed.
func TestComposeSeedEvidence_ComposesWithSeedProvenance(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		domainFinding("api.acme.com", "crt-sh", 0.45, "organization-name CT query"),
	}}
	candidate := permutationCandidate{fqdn: "api-dev.acme.com", seeds: []string{"api.acme.com"}}

	confidences := composeSeedEvidence(newDomainProvenance(input), candidate)

	require.Len(t, confidences, 1)
	assert.InDelta(t, 0.45, confidences[0].Score, 0.001, "bounded by the weaker leg")
	assert.Equal(t,
		`Permutation of seed "api.acme.com", originally observed by crt-sh, produced "api-dev.acme.com", which resolved in DNS and did not match wildcard DNS`,
		confidences[0].Justification)
}

func TestComposeSeedEvidence_CeilingIsThePermutationLeg(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		domainFinding("api.acme.com", "dns-zone-transfer", 0.90, "AXFR disclosed the record"),
	}}
	candidate := permutationCandidate{fqdn: "api-dev.acme.com", seeds: []string{"api.acme.com"}}

	confidences := composeSeedEvidence(newDomainProvenance(input), candidate)

	require.Len(t, confidences, 1)
	assert.InDelta(t, confPermutationResolvedNonWildcard, confidences[0].Score, 0.001,
		"a strong seed cannot make a guessed name better than the guess itself")
}

// TestComposeSeedEvidence_OneEntryPerIndependentSeedObservation: crt-sh and
// passive-dns both finding the seed is real corroboration of the step in doubt.
func TestComposeSeedEvidence_OneEntryPerIndependentSeedObservation(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		domainFinding("api.acme.com", "crt-sh", 0.40, "organization-name CT query"),
		domainFinding("api.acme.com", "passive-dns", 0.30, "historical records"),
	}}
	candidate := permutationCandidate{fqdn: "api-dev.acme.com", seeds: []string{"api.acme.com"}}

	confidences := composeSeedEvidence(newDomainProvenance(input), candidate)

	require.Len(t, confidences, 2)
	assert.Contains(t, confidences[0].Justification, "crt-sh")
	assert.Contains(t, confidences[1].Justification, "passive-dns")
	assert.InDelta(t, 0.70, plugins.TotalConfidence(plugins.Finding{Confidences: confidences}), 0.001)
}

// TestComposeSeedEvidence_ConvergentSeedsEachContribute mirrors two distinct
// seeds mutating into the same live host.
func TestComposeSeedEvidence_ConvergentSeedsEachContribute(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		domainFinding("api.acme.com", "crt-sh", 0.30, "CT logs"),
		domainFinding("dev.acme.com", "urlscan", 0.30, "scan history"),
	}}
	candidate := permutationCandidate{
		fqdn:  "dev.api.acme.com",
		seeds: []string{"api.acme.com", "dev.acme.com"},
	}

	confidences := composeSeedEvidence(newDomainProvenance(input), candidate)

	require.Len(t, confidences, 2)
	assert.Contains(t, confidences[0].Justification, `seed "api.acme.com"`)
	assert.Contains(t, confidences[1].Justification, `seed "dev.acme.com"`)
}

// TestComposeSeedEvidence_UnscoredSeedStillYieldsEvidence covers a seed that
// arrived without provenance — a --domain passed straight through, or a plugin
// that does not score. The resolution still happened.
func TestComposeSeedEvidence_UnscoredSeedStillYieldsEvidence(t *testing.T) {
	candidate := permutationCandidate{fqdn: "api-dev.acme.com", seeds: []string{"api.acme.com"}}

	confidences := composeSeedEvidence(newDomainProvenance(plugins.Input{}), candidate)

	require.Len(t, confidences, 1)
	assert.InDelta(t, confPermutationResolvedNonWildcard, confidences[0].Score, 0.001)
	assert.Equal(t,
		`Permutation of seed "api.acme.com" produced "api-dev.acme.com", which resolved in DNS and did not match wildcard DNS`,
		confidences[0].Justification)
	assert.NotContains(t, confidences[0].Justification, "originally observed by")
}

// TestComposeSeedEvidence_ZeroScoreSeedDoesNotVouch is the floor of the chain
// rule: an upstream finding whose evidence totals zero cannot lend standing to
// anything derived from it.
func TestComposeSeedEvidence_ZeroScoreSeedDoesNotVouch(t *testing.T) {
	input := plugins.Input{UpstreamFindings: []plugins.Finding{
		domainFinding("api.acme.com", "crt-sh", 0.0, "nothing substantiated this name"),
	}}
	candidate := permutationCandidate{fqdn: "api-dev.acme.com", seeds: []string{"api.acme.com"}}

	confidences := composeSeedEvidence(newDomainProvenance(input), candidate)

	require.Len(t, confidences, 1)
	assert.InDelta(t, 0.0, confidences[0].Score, 0.001)
	assert.True(t, plugins.NeedsReview(plugins.Finding{Confidences: confidences}))
}
