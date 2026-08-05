package domains

import (
	"fmt"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// confDNSResolvedNonWildcard is the evidence weight of a name that resolves in
// DNS beneath a domain already known to belong to the target.
//
// It is strong: the name was not guessed at from a third-party index, it was
// observed to exist right now, and the wildcard probe rules out the zone
// answering for everything. It stops short of certainty because a subdomain of a
// target's zone is not always a target asset — CNAMEs point at SaaS tenants, CDN
// edges, and status pages the target does not operate.
//
// It lives here rather than inside either enumeration plugin because both read
// it: dns-brute over plain DNS and doh-enum over DNS-over-HTTPS make the same
// observation, and the transport is not evidence. Scoring DoH lower would
// penalize the resolver choice; scoring it higher would claim the transport adds
// ownership evidence. Neither is true.
const confDNSResolvedNonWildcard = 0.70

// describeDNSResolution explains a resolved name.
//
// Both enumeration plugins phrase it the same way and both state that wildcard
// DNS was ruled out, because without that clause a reader cannot tell a real
// host from a zone that answers for every label. resolver names the DoH endpoint
// that actually answered, and is empty for a plain DNS lookup.
func describeDNSResolution(fqdn, domain, resolver string) string {
	if resolver != "" {
		return fmt.Sprintf("DNS-over-HTTPS resolver %q confirmed %q beneath the known domain %q; wildcard DNS was not detected",
			resolver, fqdn, domain)
	}
	return fmt.Sprintf("DNS resolution confirmed %q beneath the known domain %q; wildcard DNS was not detected",
		fqdn, domain)
}

// domainProvenance indexes upstream domain findings by normalized name.
//
// It is built once per Run rather than scanned per lookup. dns-permutation is
// the consumer that forces this: it resolves thousands of generated candidates
// concurrently, and a linear scan per candidate over an UpstreamFindings slice
// that can hold tens of thousands of domain findings turns provenance lookup
// into seconds of CPU inside the resolver goroutines.
type domainProvenance map[string][]plugins.Finding

// newDomainProvenance indexes every upstream domain finding in input.
func newDomainProvenance(input plugins.Input) domainProvenance {
	index := make(domainProvenance)
	for _, f := range input.UpstreamFindings {
		if f.Type != plugins.FindingDomain {
			continue
		}
		key := normalizeDomain(f.Value)
		index[key] = append(index[key], f)
	}
	return index
}

// find returns every upstream finding that discovered domain.
//
// All matches are returned rather than the first: crt-sh and passive-dns both
// surfacing a seed are two independent observations, and plugins.Compose turns
// each into its own entry.
func (p domainProvenance) find(domain string) []plugins.Finding {
	return p[normalizeDomain(domain)]
}
