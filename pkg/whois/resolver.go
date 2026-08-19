package whois

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// Resolver is a commercial WHOIS provider consulted as a fallback after the
// free RDAP and TCP-43 legs.
//
// Implementations report a missing API key as ErrNoCredential rather than as a
// silent empty result: an operator who configured a provider needs to find out
// that it is not actually serving traffic.
type Resolver interface {
	// Name is the provider's config identifier, e.g. "whoxy".
	Name() string
	// Lookup returns registration data for domain. A provider that answered but
	// holds no record returns a zero Result and a nil error.
	Lookup(ctx context.Context, domain string) (Result, error)
}

// ErrNoCredential reports that a provider has no API key configured, so it
// cannot be consulted. It is not a lookup failure: the chain skips the provider
// and moves on.
var ErrNoCredential = errors.New("whois: provider credential not configured")

// Provider identifiers accepted by ResolversByName.
const (
	ProviderWhoxy       = "whoxy"
	ProviderWhoisFreaks = "whoisfreaks"
	ProviderWhoisXML    = "whoisxml"
)

// DefaultFallbackOrder is the route used when the caller configures none.
//
// Whoxy leads deliberately. It is the incumbent, it is already paid for, and it
// mirrors the cascade Guard runs in production today, so the default preserves
// current behaviour instead of silently re-routing spend to another vendor.
// WhoisFreaks is second on marginal price. WhoisXML is last: it is the most
// expensive per query and is reached only when the cheaper providers had no
// answer.
//
// Reordering this is a cost decision, not a tuning tweak.
func DefaultFallbackOrder() []string {
	return []string{ProviderWhoxy, ProviderWhoisFreaks, ProviderWhoisXML}
}

// credentialed is implemented by resolvers that authenticate with an API key,
// so the route builder can report a configured-but-unusable provider.
type credentialed interface{ hasCredential() bool }

// ResolversByName builds a fallback route from an ordered list of provider
// names. Use it to turn operator configuration into resolvers once, at startup.
//
// Order is significant twice over: it is the order providers are tried, and —
// because Result.Merge keeps the first non-empty value for each field — it is
// also field precedence. Reordering the route silently changes which source
// wins per field.
//
// A nil or empty list is valid and means "no commercial fallback".
//
// A named provider with no credential is reported here, at build time, rather
// than doing nothing on every lookup for the rest of the process's life.
func ResolversByName(httpClient *http.Client, names ...string) ([]Resolver, error) {
	resolvers := make([]Resolver, 0, len(names))
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		r, err := newResolver(httpClient, name)
		if err != nil {
			return nil, err
		}
		if c, ok := r.(credentialed); ok && !c.hasCredential() {
			slog.Warn("WHOIS fallback provider is configured but has no API key; it will be skipped on every lookup",
				"provider", name)
		}
		resolvers = append(resolvers, r)
	}
	return resolvers, nil
}

// newResolver constructs a single provider by name without reporting a missing
// credential. The default route uses it because those providers are merely
// available-if-keyed, not operator assertions that they should be in use.
func newResolver(httpClient *http.Client, name string) (Resolver, error) {
	switch name {
	case ProviderWhoxy:
		return NewWhoxyResolver(httpClient, ""), nil
	case ProviderWhoisFreaks:
		return NewWhoisFreaksResolver(httpClient, ""), nil
	case ProviderWhoisXML:
		return NewWhoisXMLResolver(httpClient, ""), nil
	default:
		return nil, fmt.Errorf("whois: unknown fallback provider %q (want %s, %s or %s)",
			name, ProviderWhoxy, ProviderWhoisFreaks, ProviderWhoisXML)
	}
}

// defaultResolvers builds DefaultFallbackOrder. The names are compile-time
// constants, so construction cannot fail.
func defaultResolvers(httpClient *http.Client) []Resolver {
	names := DefaultFallbackOrder()
	resolvers := make([]Resolver, 0, len(names))
	for _, name := range names {
		r, err := newResolver(httpClient, name)
		if err != nil {
			continue
		}
		resolvers = append(resolvers, r)
	}
	return resolvers
}

// resolveViaFallbackOnly walks the route when neither free protocol produced
// anything, so the answer has to come from a commercial provider or not at all.
//
// Unlike fillGapsFromFallback this does believe an Unregistered verdict: nothing
// else resolved the domain, so there is no better evidence to contradict.
func resolveViaFallbackOnly(ctx context.Context, resolvers []Resolver, domain string) (Result, bool, error) {
	res, ok, err := runFallbacks(ctx, resolvers, domain)
	if !ok {
		return Result{}, false, err
	}
	res.ScrubContacts()
	return res, true, nil
}

// fillGapsFromFallback consults the route when the free-protocol result lacks
// registrant identity, merging in the first usable answer.
//
// An Unregistered verdict is discarded here rather than acted on. RDAP or TCP-43
// already returned a record for this domain, so a provider claiming it does not
// exist is contradicting better evidence — and because Merge would not undo a
// resolved record anyway, acting on it could only mislead. The both-legs-failed
// path in Lookup does believe that verdict, because there nothing else resolved
// the domain at all.
func fillGapsFromFallback(ctx context.Context, resolvers []Resolver, domain string, result *Result) {
	if result.HasRegistrant() {
		return
	}
	fbResult, ok, _ := runFallbacks(ctx, resolvers, domain)
	if !ok || fbResult.Unregistered {
		return
	}
	fbResult.ScrubContacts()
	result.Merge(fbResult)
}

// runFallbacks tries each resolver in order and returns the first usable
// record. "Usable" is deliberately a low bar: returned without an error, and
// naming a domain.
//
// There is no completeness test. A provider that answers ends the chain even if
// its record is partial, and that bound is the cost guarantee — at most one
// commercial provider is billed per lookup, enforced by control flow rather
// than by a predicate that must stay correct as Result grows fields.
//
// A completeness test would also be unreachable in practice: GDPR and
// privacy-proxy redaction strip registrant identity at the registry, so those
// fields are absent from every provider and the chain would call all of them on
// every redacted domain, forever.
//
// Errors are collected rather than returned early so that a caller which
// exhausts the route can report why every provider declined. They are returned
// only when no provider answered: a non-nil error alongside a usable result
// would invite callers to treat a satisfied lookup as a failure.
func runFallbacks(ctx context.Context, resolvers []Resolver, domain string) (Result, bool, error) {
	var errs []error
	for _, r := range resolvers {
		// A cancelled context will fail every remaining provider for the same
		// reason, so stop rather than generating one identical error per provider.
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}

		res, err := r.Lookup(ctx, domain)
		if err != nil {
			if errors.Is(err, ErrNoCredential) {
				slog.Debug("WHOIS fallback skipped: no credential",
					"provider", r.Name(), "domain", domain)
			} else {
				slog.Debug("WHOIS fallback failed",
					"provider", r.Name(), "domain", domain, "error", err)
			}
			errs = append(errs, err)
			continue
		}
		if res.Domain == "" {
			slog.Debug("WHOIS fallback returned no record",
				"provider", r.Name(), "domain", domain)
			continue
		}
		return res, true, nil
	}
	return Result{}, false, errors.Join(errs...)
}
