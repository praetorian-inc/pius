package domains

import (
	"context"
	_ "embed"
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

		// Deduplicate candidates and exclude seeds.
		seedSet := make(map[string]bool, len(subs))
		for _, s := range subs {
			seedSet[normalizeDomain(s)] = true
		}

		seen := make(map[string]bool, len(candidates))
		var unique []string
		for _, c := range candidates {
			c = normalizeDomain(c)
			if !seen[c] && !seedSet[c] {
				seen[c] = true
				unique = append(unique, c)
			}
		}

		// Resolve each candidate concurrently.
		var wg sync.WaitGroup
		for _, candidate := range unique {
			if ctx.Err() != nil {
				break
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(fqdn string) {
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

				mu.Lock()
				findings = append(findings, plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  fqdn,
					Source: "dns-permutation",
					Data: map[string]any{
						"method": "dns-permutation",
						"domain": base,
					},
				})
				mu.Unlock()
			}(candidate)
		}
		wg.Wait()
	}

	return findings, nil
}

// generateCandidates produces all permutation candidates for a set of subdomains
// sharing the same base domain. Implements four altdns-style strategies.
func (p *DNSPermutationPlugin) generateCandidates(seeds []string, base string) []string {
	var candidates []string

	for _, seed := range seeds {
		labels := extractLabels(seed, base)
		if len(labels) == 0 {
			continue
		}

		candidates = append(candidates, p.dashConcat(labels, base)...)
		candidates = append(candidates, p.directConcat(labels, base)...)
		candidates = append(candidates, p.insertWord(labels, base)...)
		candidates = append(candidates, numberSuffix(labels, base)...)
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


