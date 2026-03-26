package domains

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// queryDNS performs a DNS query of the specified type against the resolver.
// Returns the response or error. Caller must check r.Rcode and r.Answer.
func queryDNS(ctx context.Context, fqdn string, qtype uint16, resolver string) (*dns.Msg, error) {
	c := &dns.Client{
		Timeout: 5 * time.Second,
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, resolver)
	if err != nil {
		return nil, fmt.Errorf("DNS query %s %s: %w", dns.TypeToString[qtype], fqdn, err)
	}
	return r, nil
}

// normalizeDomain ensures domain is in canonical form:
// - No trailing dot
// - Lowercase
func normalizeDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)
	return domain
}

// resolveIPs returns the A and AAAA record IPs for an FQDN, or empty if NXDOMAIN.
func resolveIPs(ctx context.Context, fqdn string, resolver string) ([]string, error) {
	var ips []string

	r, err := queryDNS(ctx, fqdn, dns.TypeA, resolver)
	if err != nil {
		return nil, err
	}
	if r != nil && r.Rcode == dns.RcodeSuccess {
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
	}

	r, err = queryDNS(ctx, fqdn, dns.TypeAAAA, resolver)
	if err != nil {
		return nil, err
	}
	if r != nil && r.Rcode == dns.RcodeSuccess {
		for _, ans := range r.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, aaaa.AAAA.String())
			}
		}
	}

	return ips, nil
}

// detectWildcard queries a random non-existent subdomain to detect wildcard DNS.
// Returns the set of IPs the wildcard resolves to (empty if no wildcard).
func detectWildcard(ctx context.Context, base string, resolver string) map[string]bool {
	randomLabel := randomHex(16)
	fqdn := randomLabel + "." + base

	ips, err := resolveIPs(ctx, fqdn, resolver)
	if err != nil || len(ips) == 0 {
		return nil
	}

	slog.Info("wildcard detected", "base", base, "ips", ips)
	wildcardSet := make(map[string]bool, len(ips))
	for _, ip := range ips {
		wildcardSet[ip] = true
	}
	return wildcardSet
}

// isWildcardMatch returns true if all resolved IPs match the wildcard IP set.
func isWildcardMatch(ips []string, wildcardIPs map[string]bool) bool {
	if len(wildcardIPs) == 0 || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !wildcardIPs[ip] {
			return false
		}
	}
	return true
}

// randomHex returns a random hex string of the specified byte length.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// FilterWildcardDomains removes domain findings whose parent zone has wildcard
// DNS. It extracts the unique parent domain of each finding, probes each parent
// once with a random subdomain, and drops all findings under wildcard parents.
//
// For example, given findings [admin.dev.example.com, api.dev.example.com,
// www.example.com], it probes <random>.dev.example.com and <random>.example.com.
// If dev.example.com is a wildcard, both admin and api findings are dropped,
// but www.example.com is kept.
func FilterWildcardDomains(ctx context.Context, findings []plugins.Finding) []plugins.Finding {
	// Extract unique parent domains from all domain findings.
	parents := make(map[string]bool)
	for _, f := range findings {
		if f.Type != plugins.FindingDomain {
			continue
		}
		parent := extractParent(normalizeDomain(f.Value))
		if parent != "" {
			parents[parent] = false // false = not yet checked
		}
	}

	if len(parents) == 0 {
		return findings
	}

	// Probe each unique parent once for wildcard DNS.
	wildcardParents := make(map[string]bool)
	for parent := range parents {
		if ips := detectWildcard(ctx, parent, dnsDefaultResolver); len(ips) > 0 {
			slog.Info("wildcard detected, filtering subdomains", "parent", parent)
			wildcardParents[parent] = true
		}
	}

	if len(wildcardParents) == 0 {
		return findings
	}

	// Filter findings whose parent is a wildcard zone.
	result := make([]plugins.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Type != plugins.FindingDomain {
			result = append(result, f)
			continue
		}
		parent := extractParent(normalizeDomain(f.Value))
		if wildcardParents[parent] {
			slog.Debug("filtered wildcard domain", "domain", f.Value, "parent", parent)
			continue
		}
		result = append(result, f)
	}

	return result
}

// extractParent returns the parent domain of an FQDN by stripping the leftmost label.
// e.g., "admin.dev.example.com" → "dev.example.com", "example.com" → ""
func extractParent(fqdn string) string {
	idx := strings.Index(fqdn, ".")
	if idx < 0 || idx == len(fqdn)-1 {
		return ""
	}
	return fqdn[idx+1:]
}

// isDomainName returns true when s looks like a domain name rather than
// an IP address or CIDR block. It is intentionally lenient — the DNS
// layer will reject truly invalid names.
func isDomainName(s string) bool {
	if s == "" {
		return false
	}
	// Reject CIDR notation (e.g. "10.0.0.0/8")
	if strings.Contains(s, "/") {
		return false
	}
	// Reject plain IPv4/IPv6 (net.ParseIP succeeds)
	if net.ParseIP(s) != nil {
		return false
	}
	// Reject bracketed IPv6 like "[::1]"
	if net.ParseIP(strings.Trim(s, "[]")) != nil {
		return false
	}
	return true
}
