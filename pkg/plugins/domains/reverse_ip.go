package domains

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("reverse-ip", func() plugins.Plugin {
		return &ReverseIPPlugin{client: client.New()}
	})
}

// ReverseIPPlugin discovers hostnames via reverse IP lookups (PTR records)
// and passive DNS services like HackerTarget.
type ReverseIPPlugin struct {
	client     *client.Client
	baseURL    string // override for testing
	resolver   string // DNS resolver override for testing
	maxResults int    // max hostnames to return (default 500)
}

func (p *ReverseIPPlugin) Name() string { return "reverse-ip" }
func (p *ReverseIPPlugin) Description() string {
	return "Reverse IP: discovers hostnames via PTR records and HackerTarget reverse IP lookup"
}
func (p *ReverseIPPlugin) Category() string { return "domain" }
func (p *ReverseIPPlugin) Phase() int       { return 0 }
func (p *ReverseIPPlugin) Mode() string     { return plugins.ModePassive }

func (p *ReverseIPPlugin) hackerTargetBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.hackertarget.com"
}

func (p *ReverseIPPlugin) dnsResolver() string {
	if p.resolver != "" {
		return p.resolver
	}
	return "8.8.8.8:53"
}

// Accepts if we have a domain to resolve
func (p *ReverseIPPlugin) Accepts(input plugins.Input) bool {
	return input.Domain != ""
}

func (p *ReverseIPPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	maxResults := p.maxResults
	if maxResults == 0 {
		maxResults = 500
	}

	// Resolve domain to IPs
	ips, err := p.resolveToIPs(ctx, input.Domain)
	if err != nil || len(ips) == 0 {
		return nil, nil // Graceful degradation
	}

	seen := make(map[string]bool)
	var findings []plugins.Finding

	for _, ip := range ips {
		if len(findings) >= maxResults {
			break
		}

		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		// PTR lookup
		ptrHosts := p.ptrLookup(ctx, ip)
		for _, host := range ptrHosts {
			host = normalizeDomain(host)
			if host == "" || seen[host] {
				continue
			}
			seen[host] = true
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  host,
				Source: p.Name(),
				Data: map[string]any{
					"org":         input.OrgName,
					"ip":          ip,
					"method":      "ptr",
					"base_domain": input.Domain,
				},
			})
		}

		// HackerTarget reverse IP lookup
		htHosts := p.hackerTargetLookup(ctx, ip)
		for _, host := range htHosts {
			host = normalizeDomain(host)
			if host == "" || seen[host] {
				continue
			}
			seen[host] = true
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  host,
				Source: p.Name(),
				Data: map[string]any{
					"org":         input.OrgName,
					"ip":          ip,
					"method":      "hackertarget",
					"base_domain": input.Domain,
				},
			})
		}
	}

	return findings, nil
}

// resolveToIPs resolves a domain to its A/AAAA records
func (p *ReverseIPPlugin) resolveToIPs(ctx context.Context, domain string) ([]string, error) {
	var ips []string

	// Try A records
	aIPs, err := p.dnsLookup(ctx, domain, dns.TypeA)
	if err == nil {
		ips = append(ips, aIPs...)
	}

	// Try AAAA records
	aaaaIPs, err := p.dnsLookup(ctx, domain, dns.TypeAAAA)
	if err == nil {
		ips = append(ips, aaaaIPs...)
	}

	return ips, nil
}

// dnsLookup performs a DNS query
func (p *ReverseIPPlugin) dnsLookup(ctx context.Context, name string, qtype uint16) ([]string, error) {
	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, p.dnsResolver())
	if err != nil {
		return nil, err
	}

	var results []string
	for _, ans := range r.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			results = append(results, rr.A.String())
		case *dns.AAAA:
			results = append(results, rr.AAAA.String())
		}
	}
	return results, nil
}

// ptrLookup performs reverse DNS lookup for an IP
func (p *ReverseIPPlugin) ptrLookup(ctx context.Context, ip string) []string {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil
	}

	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, p.dnsResolver())
	if err != nil {
		return nil
	}

	var hosts []string
	for _, ans := range r.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			hosts = append(hosts, ptr.Ptr)
		}
	}
	return hosts
}

// hackerTargetLookup queries HackerTarget reverse IP API
func (p *ReverseIPPlugin) hackerTargetLookup(ctx context.Context, ip string) []string {
	// Validate IP
	if net.ParseIP(ip) == nil {
		return nil
	}

	url := p.hackerTargetBase() + "/reverseiplookup/?q=" + ip
	body, err := p.client.Get(ctx, url)
	if err != nil {
		return nil
	}

	// Response is newline-separated hostnames
	// May contain error messages like "API count exceeded"
	lines := strings.Split(string(body), "\n")
	var hosts []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and error messages
		if line == "" || strings.Contains(line, "error") || strings.Contains(line, "API") {
			continue
		}
		// Basic hostname validation
		if strings.Contains(line, ".") && !strings.Contains(line, " ") {
			hosts = append(hosts, line)
		}
	}
	return hosts
}
