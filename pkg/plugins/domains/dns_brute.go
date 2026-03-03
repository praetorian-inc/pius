package domains

import (
	"bufio"
	"context"
	_ "embed"
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
	return input.Domain != ""
}

// Run resolves each wordlist entry as {word}.{domain} concurrently.
// Returns a Finding for each subdomain that resolves to at least one A or AAAA record.
func (p *DNSBrutePlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	domain := strings.TrimSuffix(input.Domain, ".")

	var (
		mu       sync.Mutex
		findings []plugins.Finding
	)

	sem := make(chan struct{}, dnsBruteConcurrency)

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
			if resolved := p.resolve(ctx, fqdn); resolved {
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
func (p *DNSBrutePlugin) resolve(ctx context.Context, fqdn string) bool {
	c := new(dns.Client)
	// Try A record
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, p.resolver)
	if err == nil && r != nil && len(r.Answer) > 0 && r.Rcode == dns.RcodeSuccess {
		return true
	}

	// Try AAAA record
	m = new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeAAAA)
	m.RecursionDesired = true

	r, _, err = c.ExchangeContext(ctx, m, p.resolver)
	if err == nil && r != nil && len(r.Answer) > 0 && r.Rcode == dns.RcodeSuccess {
		return true
	}

	return false
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
