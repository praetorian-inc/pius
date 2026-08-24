package whois

import (
	"net/http"
)

// WHOIS is a configured cascade of resolvers: the two free legs, then an
// ordered commercial tail.
//
// It is plain configuration and carries no behaviour of its own — Lookup reads
// these fields and owns the walk. Every leg is a Resolver, so a test replaces
// the network by passing an option rather than by monkey-patching a
// package-level function.
//
// The free legs are named fields and the commercial ones an ordered slice, and
// that asymmetry is deliberate rather than an oversight:
//
//   - RDAP and TCP-43 are a fixed prefix. They are free, so there is never a
//     reason to put a paid vendor ahead of them, and naming them individually
//     is what makes them individually replaceable in a test.
//   - The commercial tail is operator-configurable, and order is the entire
//     point of the configuration, so it has to be a slice. Named fields cannot
//     express "whoisxml first, then whoxy, and skip whoisfreaks".
type WHOIS struct {
	// RDAPResolver is the structured-metadata leg. Runs first.
	RDAPResolver Resolver
	// TCP43Resolver is the port-43 leg. Runs second, for the email coverage
	// RDAP tends to withhold.
	TCP43Resolver Resolver
	// Fallbacks is the ordered commercial tail, consulted after both free legs.
	// A nil entry is skipped.
	Fallbacks []Resolver

	// httpClient builds whichever default legs the caller did not supply.
	httpClient *http.Client
	// fallbacksSet separates "the operator asked for no commercial tail" from
	// "the operator configured nothing at all". The two take opposite defaults —
	// a free-only cascade and the full default route — and an empty slice alone
	// cannot tell them apart, because a variadic call with no arguments is
	// indistinguishable from an unset field.
	fallbacksSet bool
}

// Option configures a Lookup call.
type Option func(*WHOIS)

// New builds the cascade an Option list describes, filling each leg the caller
// left unset with its default. With no options it is the default cascade: RDAP,
// TCP-43, then Whoxy, WhoisFreaks and WhoisXML.
func New(opts ...Option) *WHOIS {
	w := &WHOIS{}
	for _, o := range opts {
		o(w)
	}

	if w.RDAPResolver == nil {
		w.RDAPResolver = NewRDAPResolver(w.httpClient)
	}
	if w.TCP43Resolver == nil {
		w.TCP43Resolver = NewTCP43Resolver()
	}
	if !w.fallbacksSet {
		w.Fallbacks = defaultFallbacks(w.httpClient)
	}
	return w
}

// WithHTTPClient sets the HTTP client used for RDAP and the commercial legs.
func WithHTTPClient(c *http.Client) Option {
	return func(w *WHOIS) { w.httpClient = c }
}

// WithRDAPResolver replaces the RDAP leg, which is how a test runs the cascade
// without touching the network. A nil resolver leaves the default in place.
func WithRDAPResolver(r Resolver) Option {
	return func(w *WHOIS) { w.RDAPResolver = r }
}

// WithTCP43Resolver replaces the port-43 leg. A nil resolver leaves the default
// in place.
func WithTCP43Resolver(r Resolver) Option {
	return func(w *WHOIS) { w.TCP43Resolver = r }
}

// WithFallbackResolvers sets the ordered commercial tail, replacing the default
// route.
//
// Order is significant twice over: it is the order providers are tried, and —
// because Result.Merge keeps the first non-empty value for each field — it is
// also field precedence. Reordering the route silently changes which source
// wins per field.
//
// Calling this with no resolvers disables the commercial tail entirely, leaving
// RDAP and TCP-43. That is a supported configuration, distinct from not calling
// it at all, which uses the default route.
func WithFallbackResolvers(resolvers ...Resolver) Option {
	return func(w *WHOIS) {
		w.Fallbacks = resolvers
		w.fallbacksSet = true
	}
}
