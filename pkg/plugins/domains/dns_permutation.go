package domains

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

//go:embed wordlists/permutations.txt
var defaultPermutationWordlist string

const (
	permutationConcurrency = 50
)

func init() {
	plugins.Register("dns-permutation", func() plugins.Plugin {
		return &DNSPermutationPlugin{
			resolver: dnsDefaultResolver,
			wordlist: parseWordlist(defaultPermutationWordlist),
		}
	})
}

// DNSPermutationPlugin generates intelligent subdomain variations from known
// subdomains (discovered by Phase 0 plugins like crt-sh, passive-dns, dns-brute)
// and resolves them via DNS. This is a Go implementation of the altdns technique.
type DNSPermutationPlugin struct {
	resolver string   // DNS resolver address (host:port)
	wordlist []string // alteration words for permutations
}

func (p *DNSPermutationPlugin) Name() string { return "dns-permutation" }
func (p *DNSPermutationPlugin) Description() string {
	return "Active subdomain permutation via DNS resolution (altdns-style)"
}
func (p *DNSPermutationPlugin) Category() string { return "domain" }
func (p *DNSPermutationPlugin) Phase() int       { return 3 }
func (p *DNSPermutationPlugin) Mode() string     { return plugins.ModeActive }

// Accepts requires discovered domains from Phase 0 plugins, passed via Meta enrichment.
func (p *DNSPermutationPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta["discovered_domains"] != ""
}

// Run generates permutations of discovered subdomains, resolves them via DNS,
// filters wildcards, and returns findings for resolving candidates.
func (p *DNSPermutationPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	seeds := splitDomains(input.Meta["discovered_domains"])
	if len(seeds) == 0 {
		return nil, nil
	}

	// Filter out high-entropy and OOB/canary domains before permutation.
	// These generate thousands of bogus assets that cause scanning storms.
	seeds = FilterJunkDomains(seeds)
	if len(seeds) == 0 {
		return nil, nil
	}

	// Group seeds by base domain for wildcard detection.
	byBase := groupByBaseDomain(seeds)

	// Index seed provenance once, before the fan-out: every resolved candidate
	// needs it, and rescanning UpstreamFindings per candidate inside the
	// resolver goroutines costs seconds of CPU on a broad scan.
	provenance := newDomainProvenance(input)

	var (
		mu       sync.Mutex
		findings []plugins.Finding
	)

	sem := make(chan struct{}, permutationConcurrency)

	for base, subs := range byBase {
		// Detect wildcard DNS for this base domain.
		wildcardIPs := detectWildcard(ctx, base, p.resolver)

		// Generate all permutation candidates for this base domain, keeping the
		// seed each one came from.
		candidates := p.generateCandidates(subs, base)

		// Resolve each candidate concurrently.
		var wg sync.WaitGroup
		for _, candidate := range candidates {
			if ctx.Err() != nil {
				break
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(candidate permutationCandidate) {
				defer wg.Done()
				defer func() { <-sem }()

				ips, err := resolveIPs(ctx, candidate.fqdn, p.resolver)
				if err != nil {
					slog.Debug("dns-permutation: resolve failed", "fqdn", candidate.fqdn, "error", err)
					return
				}
				if len(ips) == 0 {
					return
				}

				// Filter wildcard matches.
				if isWildcardMatch(ips, wildcardIPs) {
					return
				}

				confidences := composeSeedEvidence(provenance, candidate)

				mu.Lock()
				findings = append(findings, plugins.Finding{
					Type:        plugins.FindingDomain,
					Value:       candidate.fqdn,
					Source:      "dns-permutation",
					Confidences: confidences,
					Data: map[string]any{
						"method": "dns-permutation",
						"domain": base,
						"seeds":  strings.Join(candidate.seeds, ","),
					},
				})
				mu.Unlock()
			}(candidate)
		}
		wg.Wait()
	}

	return findings, nil
}

// permutationCandidate is one generated name together with the seeds that
// generated it.
//
// The lineage is what makes a permutation attributable. The name itself was
// invented by this plugin — nothing observed it anywhere — so the only reason to
// believe it belongs to the target is that a domain the target owns was mutated
// into it. Losing the seed loses the entire argument.
type permutationCandidate struct {
	fqdn  string
	seeds []string
}

// generateCandidates produces all permutation candidates for a set of subdomains
// sharing the same base domain. Implements four altdns-style strategies.
//
// Candidates are deduplicated by name, and seeds already known are dropped: a
// permutation that reproduces a seed adds nothing, and the plugin that found the
// seed already scored it. Two seeds converging on the same candidate keep both
// lineages — that convergence is corroboration, and the caller turns each seed
// into its own evidence entry.
func (p *DNSPermutationPlugin) generateCandidates(seeds []string, base string) []permutationCandidate {
	seedSet := make(map[string]bool, len(seeds))
	for _, seed := range seeds {
		seedSet[normalizeDomain(seed)] = true
	}

	var order []string
	byFQDN := make(map[string]*permutationCandidate)

	for _, seed := range seeds {
		seed = normalizeDomain(seed)
		labels := extractLabels(seed, base)
		if len(labels) == 0 {
			continue
		}

		var generated []string
		generated = append(generated, p.dashConcat(labels, base)...)
		generated = append(generated, p.directConcat(labels, base)...)
		generated = append(generated, p.insertWord(labels, base)...)
		generated = append(generated, numberSuffix(labels, base)...)

		seenForSeed := make(map[string]bool, len(generated))
		for _, fqdn := range generated {
			fqdn = normalizeDomain(fqdn)
			if fqdn == "" || seedSet[fqdn] || seenForSeed[fqdn] {
				continue
			}
			seenForSeed[fqdn] = true

			candidate, ok := byFQDN[fqdn]
			if !ok {
				candidate = &permutationCandidate{fqdn: fqdn}
				byFQDN[fqdn] = candidate
				order = append(order, fqdn)
			}
			candidate.seeds = append(candidate.seeds, seed)
		}
	}

	candidates := make([]permutationCandidate, 0, len(order))
	for _, fqdn := range order {
		candidates = append(candidates, *byFQDN[fqdn])
	}
	return candidates
}

// confPermutationResolvedNonWildcard is the weight of the permutation leg: a
// generated name that resolves in DNS and is not a wildcard artifact.
//
// The resolution is a real observation — the host exists — which is why this
// sits alongside direct DNS resolution rather than below it. It is a ceiling on
// the chain, not an independent signal: what the leg cannot establish is that
// the host belongs to the target, since resolving proves only that somebody
// registered the name the guess happened to hit.
const confPermutationResolvedNonWildcard = 0.70

// composeSeedEvidence builds the evidence for one resolved permutation.
//
// Seed provenance and permutation resolution are a chain, composed rather than
// summed (see plugins.Compose). The seed's own confidence is whatever the plugin
// that discovered it could establish, and a name derived from that seed cannot be
// better supported than the seed itself — permuting an uncertain domain does not
// produce a certain one.
//
// Distinct seeds do contribute separate entries. Two independently discovered
// domains mutating into the same live host is genuine corroboration: it is
// unlikely twice over that the name belongs to someone else.
//
// A seed with no upstream provenance still yields an entry for the resolution
// itself. Inside the pipeline every seed arrives with provenance, because
// enrichWithDomains carries both views together — but a plugin invoked directly,
// with seeds handed straight to Meta, has none, and the permutation resolving is
// a fact worth recording even when the seed's own standing is unstated.
func composeSeedEvidence(provenance domainProvenance, candidate permutationCandidate) []plugins.Confidence {
	var confidences []plugins.Confidence

	for _, seed := range candidate.seeds {
		confidences = append(confidences,
			plugins.Compose(provenance.find(seed), confPermutationResolvedNonWildcard,
				func(upstream *plugins.Finding) string {
					if upstream == nil {
						return describePermutation(seed, candidate.fqdn, "")
					}
					return describePermutation(seed, candidate.fqdn, upstream.Source)
				})...)
	}

	return confidences
}

// describePermutation explains one generated name: what it was derived from, who
// observed that seed, and what happened when the guess was resolved.
func describePermutation(seed, fqdn, seedSource string) string {
	origin := fmt.Sprintf("Permutation of seed %q", seed)
	if seedSource != "" {
		origin = fmt.Sprintf("Permutation of seed %q, originally observed by %s,", seed, seedSource)
	}

	return fmt.Sprintf("%s produced %q, which resolved in DNS and did not match wildcard DNS",
		origin, fqdn)
}

// dashConcat generates label-word and word-label variations for each label.
// e.g., for labels ["api","v1"] and word "dev": api-dev.v1.base, dev-api.v1.base
func (p *DNSPermutationPlugin) dashConcat(labels []string, base string) []string {
	var out []string
	for _, word := range p.wordlist {
		for i, label := range labels {
			// label-word
			mutated := make([]string, len(labels))
			copy(mutated, labels)
			mutated[i] = label + "-" + word
			if fqdn := joinFQDN(mutated, base); fqdn != "" {
				out = append(out, fqdn)
			}

			// word-label
			mutated[i] = word + "-" + label
			if fqdn := joinFQDN(mutated, base); fqdn != "" {
				out = append(out, fqdn)
			}
		}
	}
	return out
}

// directConcat generates labelword and wordlabel variations for each label.
// e.g., for labels ["api","v1"] and word "dev": apidev.v1.base, devapi.v1.base
func (p *DNSPermutationPlugin) directConcat(labels []string, base string) []string {
	var out []string
	for _, word := range p.wordlist {
		for i, label := range labels {
			mutated := make([]string, len(labels))
			copy(mutated, labels)

			// labelword
			mutated[i] = label + word
			if fqdn := joinFQDN(mutated, base); fqdn != "" {
				out = append(out, fqdn)
			}

			// wordlabel
			mutated[i] = word + label
			if fqdn := joinFQDN(mutated, base); fqdn != "" {
				out = append(out, fqdn)
			}
		}
	}
	return out
}

// insertWord inserts a word as a new label at each position in the labels list.
// e.g., for labels ["api","v1"] and word "dev":
//
//	dev.api.v1.base, api.dev.v1.base, api.v1.dev.base
func (p *DNSPermutationPlugin) insertWord(labels []string, base string) []string {
	var out []string
	for _, word := range p.wordlist {
		for i := 0; i <= len(labels); i++ {
			newLabels := make([]string, 0, len(labels)+1)
			newLabels = append(newLabels, labels[:i]...)
			newLabels = append(newLabels, word)
			newLabels = append(newLabels, labels[i:]...)
			if fqdn := joinFQDN(newLabels, base); fqdn != "" {
				out = append(out, fqdn)
			}
		}
	}
	return out
}

// numberSuffix appends digits 0-9 with and without dash to each label.
// e.g., for labels ["api"] and digit 1: api-1.base, api1.base
func numberSuffix(labels []string, base string) []string {
	var out []string
	for digit := 0; digit <= 9; digit++ {
		d := string(rune('0' + digit))
		for i, label := range labels {
			mutated := make([]string, len(labels))
			copy(mutated, labels)

			// label-digit
			mutated[i] = label + "-" + d
			if fqdn := joinFQDN(mutated, base); fqdn != "" {
				out = append(out, fqdn)
			}

			// labeldigit
			mutated[i] = label + d
			if fqdn := joinFQDN(mutated, base); fqdn != "" {
				out = append(out, fqdn)
			}
		}
	}
	return out
}

// extractLabels returns the subdomain labels for a FQDN relative to its base domain.
// e.g., extractLabels("api.v1.example.com", "example.com") → ["api", "v1"]
func extractLabels(fqdn, base string) []string {
	fqdn = normalizeDomain(fqdn)
	base = normalizeDomain(base)

	if !strings.HasSuffix(fqdn, "."+base) {
		return nil
	}
	sub := strings.TrimSuffix(fqdn, "."+base)
	if sub == "" {
		return nil
	}
	return strings.Split(sub, ".")
}

// groupByBaseDomain groups FQDNs by their base domain (eTLD+1 approximation).
// It finds the shortest common suffix that is shared by at least two subdomains,
// or falls back to the last two labels.
func groupByBaseDomain(domains []string) map[string][]string {
	groups := make(map[string][]string)
	for _, d := range domains {
		d = normalizeDomain(d)
		base := guessBaseDomain(d)
		groups[base] = append(groups[base], d)
	}
	return groups
}

// guessBaseDomain extracts the base domain from a FQDN by taking the last two labels.
// e.g., "api.staging.example.com" → "example.com"
func guessBaseDomain(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	if len(parts) <= 2 {
		return fqdn
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// joinFQDN joins subdomain labels with a base domain.
// Returns empty string if any label is empty or starts/ends with a dash.
func joinFQDN(labels []string, base string) string {
	for _, l := range labels {
		if l == "" || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return ""
		}
	}
	return strings.Join(labels, ".") + "." + base
}

// splitDomains splits a comma-separated list of domains.
func splitDomains(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}


