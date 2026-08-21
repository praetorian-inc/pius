package whois

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
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

// Source identifiers for the two free legs. These are the values that reach
// Result.Sources and are serialized into Guard's whois/<domain> record, so they
// are the existing wire strings and not free to rename: "whois" — not "tcp43" —
// is what port-43 has always reported.
const (
	SourceRDAP  = "rdap"
	SourceTCP43 = "whois"
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

// Lookup outcomes recorded by logLookup. These are the vocabulary the
// per-provider success rate is computed from, so they are deliberately four
// values rather than a pass/fail pair: "the provider is broken" and "the
// registry has nothing to give anyone" are the same event under a binary flag,
// and telling them apart is the whole point of measuring.
const (
	// outcomeFound means the provider returned a definitive answer — either a
	// record carrying registration data, or a credible "not registered"
	// verdict. Both ended the question.
	outcomeFound = "found"
	// outcomeEmpty means the provider acknowledged the query and held no
	// record. Common under GDPR redaction, and not a provider defect.
	outcomeEmpty = "empty"
	// outcomeError means the request, the response or the parse failed.
	outcomeError = "error"
	// outcomeSkipped means no credential was configured, so no request was
	// sent — the one failure mode that costs nothing.
	outcomeSkipped = "skipped"
)

// logLookup emits exactly one record per resolver call, at Info so it survives
// production log levels. CloudWatch aggregates these into per-provider success,
// breakage and unkeyed rates, which is what tells an operator whether a
// configured route is earning its cost and in which order the legs belong.
//
// Called via defer with named returns, so every exit path is counted — an early
// ErrNoCredential included. It never inspects the error text, only its kind, so
// a provider that authenticates with a query parameter cannot leak its key here.
func logLookup(name, domain string, started time.Time, result *Result, err *error) {
	outcome := outcomeFound
	switch {
	case err != nil && errors.Is(*err, ErrNoCredential):
		outcome = outcomeSkipped
	case err != nil && *err != nil:
		outcome = outcomeError
	case result.Unregistered:
		// A definitive not-registered verdict answered the question.
		outcome = outcomeFound
	case !result.hasSubstance():
		outcome = outcomeEmpty
	}

	slog.Info("whois lookup complete",
		"resolver", name,
		"domain", domain,
		"result", outcome,
		"duration_ms", time.Since(started).Milliseconds())
}
