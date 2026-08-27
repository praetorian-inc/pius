package whois

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
)

// Option configures a registration lookup.
type Option func(*config)

type config struct {
	httpClient *http.Client
}

// WithHTTPClient sets the HTTP client used for RDAP requests.
func WithHTTPClient(c *http.Client) Option {
	return func(cfg *config) { cfg.httpClient = c }
}

// LookupDomain resolves domain registration data by trying RDAP first (structured,
// standardized dates) then TCP-43 (better email coverage, raw text), and
// merging the best fields from each source.
//
// Both sources are always attempted unless one definitively says the domain is
// unregistered. RDAP provides clean metadata but rarely has email (GDPR),
// while TCP-43 has email but fragile referral chains. The merge gives callers
// the best of both.
func LookupDomain(ctx context.Context, domain string, opts ...Option) (DomainResult, error) {
	cfg := config{}
	for _, o := range opts {
		o(&cfg)
	}

	domain = RootDomain(domain)
	if domain == "" {
		return DomainResult{}, fmt.Errorf("whois: no registrable domain")
	}

	rdapResult, rdapErr := rdapDomainLookup(ctx, cfg.httpClient, domain)
	if rdapErr != nil && isDomainNotFound(rdapErr) {
		return DomainResult{Domain: domain, Unregistered: true}, nil
	}
	if rdapErr != nil {
		slog.Debug("RDAP lookup failed, will rely on TCP-43", "domain", domain, "error", rdapErr)
	}

	tcp43Result, tcp43Err := tcp43DomainLookup(ctx, domain)
	if tcp43Err != nil && isDomainNotFound(tcp43Err) {
		return DomainResult{Domain: domain, Unregistered: true}, nil
	}
	if tcp43Err != nil {
		slog.Debug("TCP-43 lookup failed", "domain", domain, "error", tcp43Err)
	}

	if rdapErr != nil && tcp43Err != nil {
		slog.Error("RDAP error", "err", rdapErr)
		slog.Error("TCP43 error", "err", tcp43Err)
		return DomainResult{}, fmt.Errorf("whois: all methods failed for %s", domain)
	}

	return mergeDomainResults(rdapResult, rdapErr, tcp43Result, tcp43Err), nil
}

// mergeDomainResults combines the best fields from RDAP and TCP-43 results.
// RDAP wins for structured metadata; TCP-43 fills gaps (email, raw text).
func mergeDomainResults(
	rdapR DomainResult,
	rdapErr error,
	tcp43R DomainResult,
	tcp43Err error,
) DomainResult {
	if rdapErr != nil {
		tcp43R.Sources = []string{"whois"}
		return tcp43R
	}
	if tcp43Err != nil {
		rdapR.Sources = []string{"rdap"}
		return rdapR
	}

	// RDAP is the base; TCP-43 fills gaps.
	rdapR.Sources = []string{"rdap"}
	tcp43R.Sources = []string{"whois"}
	rdapR.Merge(tcp43R)
	return rdapR
}

// isDomainNotFound reports whether err definitively means the domain is not
// registered (RDAP 404 or whoisparser "not found" sentinel).
func isDomainNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, whoisparser.ErrNotFoundDomain) {
		return true
	}
	var ce *rdap.ClientError
	if errors.As(err, &ce) {
		return ce.Type == rdap.ObjectDoesNotExist
	}
	return false
}

// ParseExpiration attempts to parse an expiration date string and returns
// how long until the domain expires.
func ParseExpiration(expirationDate string) (time.Duration, bool) {
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, expirationDate); err == nil {
			return time.Until(t), true
		}
	}
	return 0, false
}
