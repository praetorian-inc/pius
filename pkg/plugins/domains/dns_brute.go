package domains

import (
	"bufio"
	"context"
	_ "embed"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

//go:embed wordlists/subdomains.txt
var defaultWordlist string

const (
	dnsBruteConcurrency = 50
	dnsDefaultResolver  = "8.8.8.8:53"
)

func init() {
	plugins.Register("dns-brute", func() plugins.Plugin {
		return &DNSBrutePlugin{
			resolver: dnsDefaultResolver,
			wordlist: parseWordlist(defaultWordlist),
		}
	})
}

// DNSBrutePlugin performs active subdomain enumeration by resolving
// candidate subdomains from an embedded wordlist against a DNS resolver.
type DNSBrutePlugin struct {
	resolver string   // DNS resolver address (host:port)
	wordlist []string // subdomain prefixes to try
}

func (p *DNSBrutePlugin) Name() string        { return "dns-brute" }
func (p *DNSBrutePlugin) Description() string { return "Active subdomain brute-force via DNS resolution" }
func (p *DNSBrutePlugin) Category() string    { return "domain" }
func (p *DNSBrutePlugin) Phase() int          { return 0 }
func (p *DNSBrutePlugin) Mode() string        { return plugins.ModeActive }

// Accepts requires a Domain input -- brute-forcing needs a base domain.
func (p *DNSBrutePlugin) Accepts(input plugins.Input) bool {
	return isDomainName(input.Domain)
}

// Run resolves each wordlist entry as {word}.{domain} concurrently.
// Returns a Finding for each subdomain that resolves to at least one A or AAAA record.
func (p *DNSBrutePlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	domain := normalizeDomain(input.Domain)

	// Detect wildcard DNS — if the domain resolves everything, skip brute-force.
	wildcardIPs := detectWildcard(ctx, domain, p.resolver)
	if len(wildcardIPs) > 0 {
		slog.Info("dns-brute: wildcard detected, skipping", "domain", domain)
		return nil, nil
	}

	var (
		mu       sync.Mutex
		findings []plugins.Finding
	)

	concurrency := dnsBruteConcurrency
	if v, ok := input.Meta["dns_brute_concurrency"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			concurrency = n
		}
	}

	sem := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
	for _, word := range p.wordlist {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{} // acquire slot
		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-sem }() // release slot

			fqdn := subdomain + "." + domain
			exists, err := p.resolve(ctx, fqdn)
			if err != nil {
				slog.Debug("dns-brute: resolve failed", "fqdn", fqdn, "error", err)
				return
			}
			if exists {
				mu.Lock()
				findings = append(findings, plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  fqdn,
					Source: p.Name(),
					Data: map[string]any{
						"method": "dns-brute",
						"domain": input.Domain,
					},
				})
				mu.Unlock()
			}
		}(word)
	}
	wg.Wait()

	return findings, nil
}

// resolve checks if fqdn has A or AAAA records.
// Returns (exists bool, err error).
// If err != nil, query failed (network/timeout); caller should log/skip.
// If err == nil && exists == false, domain legitimately does not exist.
func (p *DNSBrutePlugin) resolve(ctx context.Context, fqdn string) (bool, error) {
	// Try A record
	r, err := queryDNS(ctx, fqdn, dns.TypeA, p.resolver)
	if err != nil {
		return false, err
	}
	if r != nil && len(r.Answer) > 0 && r.Rcode == dns.RcodeSuccess {
		return true, nil
	}

	// Try AAAA record
	r, err = queryDNS(ctx, fqdn, dns.TypeAAAA, p.resolver)
	if err != nil {
		return false, err
	}
	if r != nil && len(r.Answer) > 0 && r.Rcode == dns.RcodeSuccess {
		return true, nil
	}

	return false, nil
}

// parseWordlist splits the embedded wordlist text into a slice of trimmed, non-empty lines.
func parseWordlist(raw string) []string {
	var words []string
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words
}
