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

// Option configures a Lookup call.
type Option func(*config)

type config struct {
	httpClient *http.Client

	fallbacks    []Resolver
	fallbacksSet bool
}

// WithHTTPClient sets the HTTP client used for RDAP requests.
func WithHTTPClient(c *http.Client) Option {
	return func(cfg *config) { cfg.httpClient = c }
}

// WithFallbackResolvers sets the ordered commercial fallback route, replacing
// DefaultFallbackOrder. Build it from operator configuration with
// ResolversByName.
//
// Calling this with no resolvers disables the commercial fallback entirely,
// leaving RDAP and TCP-43. That is a supported configuration, distinct from not
// calling it at all, which uses the default route.
func WithFallbackResolvers(resolvers ...Resolver) Option {
	return func(cfg *config) {
		cfg.fallbacks = resolvers
		cfg.fallbacksSet = true
	}
}

// resolvers returns the configured route, or the default when the caller did
// not set one.
func (cfg *config) resolvers() []Resolver {
	if cfg.fallbacksSet {
		return cfg.fallbacks
	}
	return defaultResolvers(cfg.httpClient)
}

// Lookup resolves domain registration data by trying RDAP first (structured,
// standardized dates), then TCP-43 (better email coverage, raw text), then an
// operator-configurable route of commercial providers, merging the best fields
// from each source.
//
// RDAP and TCP-43 are a fixed prefix and are always attempted unless one
// definitively says the domain is unregistered. RDAP provides clean metadata
// but rarely has email (GDPR), while TCP-43 has email but fragile referral
// chains. Only the commercial tail is reorderable, which keeps a paid provider
// from ever being consulted ahead of data the free protocols already return.
//
// The commercial route is tried when both prior legs fail, or when their merged
// result lacks registrant identity. Providers are consulted in order until one
// returns a usable record, and the first that answers ends the route — there is
// no "keep going until the record is complete" pass, so at most one commercial
// provider is billed per lookup. See runFallbacks and WithFallbackResolvers.
func Lookup(ctx context.Context, domain string, opts ...Option) (Result, error) {
	cfg := config{}
	for _, o := range opts {
		o(&cfg)
	}

	domain = RootDomain(domain)
	if domain == "" {
		return Result{}, fmt.Errorf("whois: no registrable domain")
	}

	rdapResult, rdapErr := rdapLookup(ctx, cfg.httpClient, domain)
	if rdapErr != nil && isDomainNotFound(rdapErr) {
		return Result{Domain: domain, Unregistered: true}, nil
	}
	if rdapErr != nil {
		slog.Debug("RDAP lookup failed, will rely on TCP-43", "domain", domain, "error", rdapErr)
	}

	tcp43Result, tcp43Raw, tcp43Err := tcp43Lookup(ctx, domain)
	if tcp43Err != nil && isDomainNotFound(tcp43Err) {
		return Result{Domain: domain, Unregistered: true}, nil
	}
	if tcp43Err != nil {
		slog.Debug("TCP-43 lookup failed", "domain", domain, "error", tcp43Err)
	}

	resolvers := cfg.resolvers()

	// If both prior legs failed, walk the fallback route before giving up.
	if rdapErr != nil && tcp43Err != nil {
		fbResult, ok, fbErr := runFallbacks(ctx, resolvers, domain)
		if ok {
			fbResult.ScrubContacts()
			return fbResult, nil
		}
		return Result{}, fmt.Errorf("whois: all methods failed for %s: %w", domain,
			errors.Join(rdapErr, tcp43Err, fbErr))
	}

	result := mergeResults(domain, rdapResult, rdapErr, tcp43Result, tcp43Err)
	applyISOCILFallback(&result, tcp43Raw)
	result.ScrubContacts()

	fillGapsFromFallback(ctx, resolvers, domain, &result)

	return result, nil
}

// mergeResults combines the best fields from RDAP and TCP-43 results.
// RDAP wins for structured metadata; TCP-43 fills gaps (email, raw text).
func mergeResults(domain string, rdapR Result, rdapErr error, tcp43R Result, tcp43Err error) Result {
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
	rdapR.Domain = domain
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
