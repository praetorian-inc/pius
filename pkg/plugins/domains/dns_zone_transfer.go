package domains

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

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
	return isDomainName(input.Domain)
}

// Run attempts AXFR against each authoritative nameserver for the domain.
// Extracts unique hostnames from A, AAAA, CNAME, MX, and SRV records.
func (p *DNSZoneTransferPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	domain := normalizeDomain(input.Domain)

	nameservers := p.nameservers
	if len(nameservers) == 0 {
		var err error
		nameservers, err = lookupNS(ctx, domain)
		if err != nil {
			slog.Debug("dns-zone-transfer: NS lookup failed", "domain", domain, "error", err)
			return nil, nil
		}
	}

	// Group by hostname across nameservers. A zone's servers all serve the same
	// zone, so a record returned by three of them was disclosed three times, not
	// corroborated three times — one entry, naming every server that served it.
	var order []string
	servers := make(map[string][]string)

	for _, ns := range nameservers {
		records, err := attemptAXFR(ctx, domain, ns)
		if err != nil {
			slog.Debug("dns-zone-transfer: AXFR failed", "ns", ns, "domain", domain, "error", err)
			continue
		}

		seenHere := make(map[string]bool)
		for _, hostname := range records {
			hostname = normalizeDomain(hostname)

			// Skip the base domain itself and empties; a hostname repeated
			// within one transfer (an A and an MX for the same name) is one
			// disclosure by one server.
			if hostname == "" || hostname == domain || seenHere[hostname] {
				continue
			}
			seenHere[hostname] = true

			if _, ok := servers[hostname]; !ok {
				order = append(order, hostname)
			}
			servers[hostname] = append(servers[hostname], ns)
		}
	}

	findings := make([]plugins.Finding, 0, len(order))
	for _, hostname := range order {
		responders := servers[hostname]
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  hostname,
			Source: "dns-zone-transfer",
			Confidences: []plugins.Confidence{{
				Score:         confAXFRRecord,
				Justification: describeAXFRDisclosure(hostname, domain, responders),
			}},
			Data: map[string]any{
				"method":      "axfr",
				"nameserver":  responders[0],
				"nameservers": strings.Join(responders, ","),
				"domain":      input.Domain,
			},
		})
	}

	return findings, nil
}

// confAXFRRecord is the evidence weight of a hostname read out of a successful
// zone transfer.
//
// It is the strongest domain evidence in the pipeline. The record came from the
// zone's own authoritative server, which is the definitive statement of what the
// zone contains — not a third-party index, not an inference from a certificate,
// and not a guess that happened to resolve. It stays below certainty for the
// same reason DNS resolution does: a zone can hold records pointing at
// infrastructure the target does not operate.
const confAXFRRecord = 0.90

// describeAXFRDisclosure explains one hostname, naming every nameserver that
// served it so a reviewer knows which servers are misconfigured.
func describeAXFRDisclosure(hostname, domain string, nameservers []string) string {
	named := make([]string, 0, len(nameservers))
	for _, ns := range nameservers {
		named = append(named, fmt.Sprintf("%q", stripDNSPort(ns)))
	}

	noun := "nameserver"
	if len(named) > 1 {
		noun = "nameservers"
	}

	return fmt.Sprintf("Authoritative %s %s included %q in a successful AXFR response for %q",
		noun, plugins.JoinPhrase(named), hostname, domain)
}

// stripDNSPort renders a nameserver the way a reader knows it. Transfers are
// addressed as host:port; the port is transport detail, not identity.
func stripDNSPort(nameserver string) string {
	if host, _, err := net.SplitHostPort(nameserver); err == nil {
		return host
	}
	return nameserver
}

const defaultDNSResolver = "8.8.8.8:53"

// lookupNS discovers authoritative nameservers for domain using system resolver.
func lookupNS(ctx context.Context, domain string) ([]string, error) {
	r, err := queryDNS(ctx, domain, dns.TypeNS, defaultDNSResolver)
	if err != nil {
		return nil, err
	}

	var nameservers []string
	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			// Ensure host:port format for AXFR
			nameservers = append(nameservers, strings.TrimSuffix(ns.Ns, ".")+":53")
		}
	}

	if len(nameservers) == 0 {
		return nil, fmt.Errorf("dns-zone-transfer: no NS records for %s", domain)
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
		return nil, fmt.Errorf("dns-zone-transfer: AXFR initiation: %w", err)
	}

	var hostnames []string
	var firstError error

	for envelope := range env {
		if envelope.Error != nil {
			slog.Debug("dns-zone-transfer: envelope error", "error", envelope.Error)
			if firstError == nil {
				firstError = envelope.Error
			}
			continue
		}
		for _, rr := range envelope.RR {
			hostname := extractHostname(rr)
			if hostname != "" {
				hostnames = append(hostnames, hostname)
			}
		}
	}

	// If we got records but also errors, return partial success (suppress error)
	if len(hostnames) > 0 && firstError != nil {
		slog.Warn("dns-zone-transfer: partial AXFR", "nameserver", nameserver,
			"records", len(hostnames), "error", firstError)
		return hostnames, nil
	}

	// If zero records and error occurred, propagate error
	if len(hostnames) == 0 && firstError != nil {
		return nil, fmt.Errorf("dns-zone-transfer: AXFR failed: %w", firstError)
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
