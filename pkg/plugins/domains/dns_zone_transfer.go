package domains

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const dnsZoneTransferTimeout = 10 // seconds per nameserver attempt

func init() {
	plugins.Register("dns-zone-transfer", func() plugins.Plugin {
		return &DNSZoneTransferPlugin{}
	})
}

// DNSZoneTransferPlugin attempts AXFR zone transfers against the target domain's
// authoritative nameservers. Most nameservers refuse AXFR, but misconfigured ones
// will return the entire zone -- a significant information disclosure finding.
type DNSZoneTransferPlugin struct {
	// nameservers overrides NS lookup for testing. If nil, discovered via DNS.
	nameservers []string
}

func (p *DNSZoneTransferPlugin) Name() string { return "dns-zone-transfer" }
func (p *DNSZoneTransferPlugin) Description() string {
	return "Active AXFR zone transfer attempt against authoritative nameservers"
}
func (p *DNSZoneTransferPlugin) Category() string { return "domain" }
func (p *DNSZoneTransferPlugin) Phase() int       { return 0 }
func (p *DNSZoneTransferPlugin) Mode() string     { return plugins.ModeActive }

// Accepts requires a Domain input.
func (p *DNSZoneTransferPlugin) Accepts(input plugins.Input) bool {
	return input.Domain != ""
}

// Run attempts AXFR against each authoritative nameserver for the domain.
// Extracts unique hostnames from A, AAAA, CNAME, MX, and SRV records.
func (p *DNSZoneTransferPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	domain := strings.TrimSuffix(input.Domain, ".")

	nameservers := p.nameservers
	if len(nameservers) == 0 {
		var err error
		nameservers, err = lookupNS(ctx, domain)
		if err != nil {
			slog.Debug("dns-zone-transfer: NS lookup failed", "domain", domain, "error", err)
			return nil, nil
		}
	}

	seen := make(map[string]bool)
	var findings []plugins.Finding

	for _, ns := range nameservers {
		records, err := attemptAXFR(ctx, domain, ns)
		if err != nil {
			slog.Debug("dns-zone-transfer: AXFR failed", "ns", ns, "domain", domain, "error", err)
			continue
		}

		for _, hostname := range records {
			hostname = strings.TrimSuffix(hostname, ".")
			hostname = strings.ToLower(hostname)

			// Skip the base domain itself, empty, and already-seen
			if hostname == "" || hostname == domain || seen[hostname] {
				continue
			}
			seen[hostname] = true

			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  hostname,
				Source: "dns-zone-transfer",
				Data: map[string]any{
					"method":     "axfr",
					"nameserver": ns,
					"domain":     input.Domain,
				},
			})
		}
	}

	return findings, nil
}

// lookupNS discovers authoritative nameservers for domain using system resolver.
func lookupNS(ctx context.Context, domain string) ([]string, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, "8.8.8.8:53")
	if err != nil {
		return nil, fmt.Errorf("NS query: %w", err)
	}

	var nameservers []string
	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			// Ensure host:port format for AXFR
			nameservers = append(nameservers, strings.TrimSuffix(ns.Ns, ".")+":53")
		}
	}

	if len(nameservers) == 0 {
		return nil, fmt.Errorf("no NS records found for %s", domain)
	}
	return nameservers, nil
}

// attemptAXFR performs a zone transfer and returns discovered hostnames.
func attemptAXFR(ctx context.Context, domain, nameserver string) ([]string, error) {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	env, err := t.In(m, nameserver)
	if err != nil {
		return nil, fmt.Errorf("AXFR initiation: %w", err)
	}

	var hostnames []string
	for envelope := range env {
		if envelope.Error != nil {
			slog.Debug("dns-zone-transfer: envelope error", "error", envelope.Error)
			continue
		}
		for _, rr := range envelope.RR {
			hostname := extractHostname(rr)
			if hostname != "" {
				hostnames = append(hostnames, hostname)
			}
		}
	}

	return hostnames, nil
}

// extractHostname pulls the relevant hostname from DNS resource records.
func extractHostname(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.Hdr.Name
	case *dns.AAAA:
		return v.Hdr.Name
	case *dns.CNAME:
		return v.Hdr.Name
	case *dns.MX:
		return v.Hdr.Name
	case *dns.SRV:
		return v.Hdr.Name
	default:
		return ""
	}
}
