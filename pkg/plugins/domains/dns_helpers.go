package domains

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
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
