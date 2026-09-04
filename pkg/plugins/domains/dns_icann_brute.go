package domains

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

//go:embed wordlists/public_suffix_list.dat
var publicSuffixList string

const (
	dnsICANNBruteConcurrency  = 50
	confDNSICANNBruteResolved = 70
	icannSectionStart         = "// ===BEGIN ICANN DOMAINS==="
	icannSectionEnd           = "// ===END ICANN DOMAINS==="
)

var (
	icannSuffixesOnce sync.Once
	icannSuffixes     map[string]struct{}
)

func init() {
	plugins.Register("dns-icann-brute", func() plugins.Plugin {
		return NewDNSICANNBrutePlugin(nil)
	})
}

// DNSICANNBrutePlugin looks for domains that share the input's registrable label
// under other ICANN-managed public suffixes.
type DNSICANNBrutePlugin struct {
	resolver string
	lookup   Resolver
	suffixes map[string]struct{}
}

func NewDNSICANNBrutePlugin(lookup Resolver) *DNSICANNBrutePlugin {
	return &DNSICANNBrutePlugin{resolver: dnsDefaultResolver, lookup: lookup}
}

func (p *DNSICANNBrutePlugin) Name() string { return "dns-icann-brute" }
func (p *DNSICANNBrutePlugin) Description() string {
	return "Discovers domains sharing a registrable label across ICANN public suffixes"
}
func (p *DNSICANNBrutePlugin) Category() string { return "domain" }
func (p *DNSICANNBrutePlugin) Phase() int       { return 0 }
func (p *DNSICANNBrutePlugin) Mode() string     { return plugins.ModeActive }

func (p *DNSICANNBrutePlugin) Accepts(input plugins.Input) bool {
	if !isDomainName(input.Domain) {
		return false
	}

	_, err := getRegistrableLabel(input.Domain)
	return err == nil
}

func (p *DNSICANNBrutePlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	registrableDomainLabel, err := getRegistrableLabel(input.Domain)
	if err != nil {
		return nil, fmt.Errorf("extract registrable label from %q: %w", input.Domain, err)
	}
	canonicalInputDomain, err := canonicalizeDomain(input.Domain)
	if err != nil {
		return nil, fmt.Errorf("canonicalize domain %q: %w", input.Domain, err)
	}

	candidates := generateICANNCandidates(registrableDomainLabel, canonicalInputDomain, p.icannSuffixes())
	findings := p.resolveCandidates(ctx, input, registrableDomainLabel, candidates, dnsICANNBruteConcurrencyFrom(input.Meta))
	sort.Slice(findings, func(i, j int) bool { return findings[i].Value < findings[j].Value })
	return findings, nil
}

func getRegistrableLabel(domain string) (string, error) {
	canonicalInputDomain, err := canonicalizeDomain(domain)
	if err != nil {
		return "", err
	}
	registrableDomain, err := publicsuffix.EffectiveTLDPlusOne(canonicalInputDomain)
	if err != nil {
		return "", err
	}
	registrableDomainLabel, _, found := strings.Cut(registrableDomain, ".")
	if !found || registrableDomainLabel == "" {
		return "", fmt.Errorf("registrable domain %q has no suffix", registrableDomain)
	}
	return registrableDomainLabel, nil
}

func canonicalizeDomain(domain string) (string, error) {
	domain = normalizeDomain(domain)
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", err
	}
	return strings.ToLower(ascii), nil
}

func (p *DNSICANNBrutePlugin) icannSuffixes() map[string]struct{} {
	if p.suffixes != nil {
		return p.suffixes
	}
	return loadICANNSuffixes()
}

type icannCandidate struct {
	domain string
	suffix string
}

func generateICANNCandidates(registrableDomainLabel, canonicalInputDomain string, suffixes map[string]struct{}) []icannCandidate {
	candidates := make([]icannCandidate, 0, len(suffixes))
	for suffix := range suffixes {
		domain := registrableDomainLabel + "." + suffix
		if domain != canonicalInputDomain {
			candidates = append(candidates, icannCandidate{domain: domain, suffix: suffix})
		}
	}
	return candidates
}

func dnsICANNBruteConcurrencyFrom(metadata map[string]string) int {
	value, ok := metadata["dns_icann_brute_concurrency"]
	if !ok {
		return dnsICANNBruteConcurrency
	}
	configured, err := strconv.Atoi(value)
	if err != nil || configured <= 0 {
		return dnsICANNBruteConcurrency
	}
	return configured
}

func (p *DNSICANNBrutePlugin) resolveCandidates(
	ctx context.Context,
	input plugins.Input,
	registrableDomainLabel string,
	candidates []icannCandidate,
	concurrency int,
) []plugins.Finding {
	jobs := make(chan icannCandidate)
	findings := make(chan plugins.Finding, len(candidates))

	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go p.resolveCandidateJobs(ctx, input.Domain, registrableDomainLabel, jobs, findings, &workers)
	}

	scheduleICANNCandidates(ctx, candidates, jobs)
	workers.Wait()
	close(findings)
	return collectICANNFindings(findings)
}

func (p *DNSICANNBrutePlugin) resolveCandidateJobs(
	ctx context.Context,
	originalDomain, registrableDomainLabel string,
	jobs <-chan icannCandidate,
	findings chan<- plugins.Finding,
	workers *sync.WaitGroup,
) {
	defer workers.Done()
	for candidate := range jobs {
		if ctx.Err() != nil {
			continue
		}

		if p.hasIndependentResolution(ctx, candidate) {
			findings <- newDNSICANNFinding(originalDomain, registrableDomainLabel, candidate)
		}
	}
}

func scheduleICANNCandidates(ctx context.Context, candidates []icannCandidate, jobs chan<- icannCandidate) {
	defer close(jobs)
	for _, candidate := range candidates {
		select {
		case <-ctx.Done():
			return
		case jobs <- candidate:
		}
	}
}

func collectICANNFindings(results <-chan plugins.Finding) []plugins.Finding {
	findings := make([]plugins.Finding, 0, len(results))
	for finding := range results {
		findings = append(findings, finding)
	}
	return findings
}

func (p *DNSICANNBrutePlugin) hasIndependentResolution(ctx context.Context, candidate icannCandidate) bool {
	addresses := p.resolveAddresses(ctx, candidate.domain)
	if len(addresses) == 0 {
		return false
	}
	wildcardAddresses := p.probeWildcardAddresses(ctx, candidate.suffix)

	if isWildcardMatch(addresses, wildcardAddresses) {
		slog.Info("dns-icann-brute: wildcard detected",
			"suffix", candidate.suffix,
			"candidate", candidate.domain,
			"candidate_addresses", addresses,
			"wildcard_addresses", wildcardAddresses,
		)
		return false
	}

	return true
}

func (p *DNSICANNBrutePlugin) resolveAddresses(ctx context.Context, domain string) []string {
	if ctx.Err() != nil {
		return nil
	}
	if p.lookup != nil {
		return p.lookup.Resolve(domain)
	}
	addresses, err := resolveIPs(ctx, domain, p.resolver)
	if err != nil {
		return nil
	}
	return addresses
}

func (p *DNSICANNBrutePlugin) probeWildcardAddresses(ctx context.Context, suffix string) map[string]bool {
	addresses := make(map[string]bool)
	for range wildcardProbeCount {
		for _, address := range p.resolveAddresses(ctx, randomHex(16)+"."+suffix) {
			addresses[address] = true
		}
	}
	return addresses
}

func newDNSICANNFinding(originalDomain, registrableDomainLabel string, candidate icannCandidate) plugins.Finding {
	data := map[string]any{
		"method":          "dns-icann-brute",
		"original_domain": originalDomain,
		"icann_suffix":    candidate.suffix,
	}
	if unicodeSuffix, err := idna.Lookup.ToUnicode(candidate.suffix); err == nil && unicodeSuffix != candidate.suffix {
		data["unicode_suffix"] = unicodeSuffix
	}

	finding := plugins.Finding{
		Type:   plugins.FindingDomain,
		Value:  candidate.domain,
		Source: "dns-icann-brute",
		Data:   data,
	}
	plugins.AddConfidence(&finding, confDNSICANNBruteResolved,
		fmt.Sprintf("The registrable label %q from original domain %q resolved as %q under ICANN public suffix %q",
			registrableDomainLabel, originalDomain, candidate.domain, candidate.suffix))
	return finding
}

func loadICANNSuffixes() map[string]struct{} {
	icannSuffixesOnce.Do(func() {
		icannSuffixes = parseICANNSuffixes(publicSuffixList)
	})
	return icannSuffixes
}

func parseICANNSuffixes(raw string) map[string]struct{} {
	suffixes := make(map[string]struct{})
	inICANNSection := false
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == icannSectionStart {
			inICANNSection = true
			continue
		}

		if line == icannSectionEnd {
			return suffixes
		}

		if !inICANNSection || !isExactICANNSuffixRule(line) {
			continue
		}

		ascii, err := idna.Lookup.ToASCII(line)
		if err != nil {
			continue
		}

		suffixes[strings.ToLower(ascii)] = struct{}{}
	}
	return suffixes
}

func isExactICANNSuffixRule(rule string) bool {
	if rule == "" {
		return false
	}

	return startsWithDomainCharacter(rule)
}

func startsWithDomainCharacter(rule string) bool {
	first, _ := utf8.DecodeRuneInString(rule)
	return first != utf8.RuneError && (unicode.IsLetter(first) || unicode.IsDigit(first))
}
