package domains

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

//go:embed wordlists/permutations.txt
var defaultPermutationWordlist string

const (
	permutationConcurrency     = 50
	confDNSPermutationResolved = 0.70
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

	var (
		mu       sync.Mutex
		findings []plugins.Finding
	)

	sem := make(chan struct{}, permutationConcurrency)

	for base, subs := range byBase {
		// Detect wildcard DNS for this base domain.
		wildcardIPs := detectWildcard(ctx, base, p.resolver)

		// Generate all permutation candidates for this base domain.
		candidates := p.generateCandidates(subs, base)

		// Exclude existing seed domains. generateCandidates already deduplicates
		// candidates while retaining every seed that produced each one.
		for _, seed := range subs {
			delete(candidates, normalizeDomain(seed))
		}

		// Resolve each candidate concurrently.
		var wg sync.WaitGroup
		for candidate, candidateSeeds := range candidates {
			if ctx.Err() != nil {
				break
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(fqdn string, seeds []string) {
				defer wg.Done()
				defer func() { <-sem }()

				ips, err := resolveIPs(ctx, fqdn, p.resolver)
				if err != nil {
					slog.Debug("dns-permutation: resolve failed", "fqdn", fqdn, "error", err)
					return
				}
				if len(ips) == 0 {
					return
				}

				// Filter wildcard matches.
				if isWildcardMatch(ips, wildcardIPs) {
					return
				}

				justification := dnsPermutationJustification(seeds, fqdn, ips)
				finding := plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  fqdn,
					Source: "dns-permutation",
					Data: map[string]any{
						"method": "dns-permutation",
						"domain": base,
					},
				}
				plugins.AddConfidence(&finding, confDNSPermutationResolved, justification)
				mu.Lock()
				findings = append(findings, finding)
				mu.Unlock()
			}(candidate, candidateSeeds)
		}
		wg.Wait()
	}

	return findings, nil
}

func dnsPermutationJustification(seeds []string, candidate string, ips []string) string {
	quotedSeeds := make([]string, len(seeds))
	for i, seed := range seeds {
		quotedSeeds[i] = fmt.Sprintf("%q", seed)
	}

	sortedIPs := append([]string(nil), ips...)
	sort.Strings(sortedIPs)
	displayedIPs := sortedIPs
	if len(sortedIPs) > 3 {
		displayedIPs = append(append([]string(nil), sortedIPs[:3]...), "...")
	}

	addressNoun := "IP addresses"
	if len(sortedIPs) == 1 {
		addressNoun = "IP address"
	}

	if len(seeds) == 1 {
		return fmt.Sprintf("Starting with discovered domain %s, DNS permutation generated variant domain %q, which resolved to %d %s (%s)",
			quotedSeeds[0], candidate, len(sortedIPs), addressNoun, strings.Join(displayedIPs, ", "))
	}
	return fmt.Sprintf("Starting with discovered domains %s, DNS permutation generated variant domain %q, which resolved to %d %s (%s)",
		strings.Join(quotedSeeds, ", "), candidate, len(sortedIPs), addressNoun, strings.Join(displayedIPs, ", "))
}

// generateCandidates produces permutation candidates keyed by domain, with the
// discovered seed domains that generated each candidate. It implements four
// altdns-style strategies and deduplicates repeated candidate/seed pairs.
func (p *DNSPermutationPlugin) generateCandidates(seeds []string, base string) map[string][]string {
	candidates := make(map[string][]string)

	for _, seed := range seeds {
		normalizedSeed := normalizeDomain(seed)
		labels := extractLabels(normalizedSeed, base)
		if len(labels) == 0 {
			continue
		}

		var generated []string
		generated = append(generated, p.dashConcat(labels, base)...)
		generated = append(generated, p.directConcat(labels, base)...)
		generated = append(generated, p.insertWord(labels, base)...)
		generated = append(generated, numberSuffix(labels, base)...)

		for _, candidate := range generated {
			candidate = normalizeDomain(candidate)
			if candidate != "" {
				candidates[candidate] = append(candidates[candidate], normalizedSeed)
			}
		}
	}

	for candidate, candidateSeeds := range candidates {
		slices.Sort(candidateSeeds)
		candidates[candidate] = slices.Compact(candidateSeeds)
	}
	return candidates
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
