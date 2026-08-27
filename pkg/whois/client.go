package whois

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// WHOISDomainOnlyClient is one source of domain registration data.
type WHOISDomainOnlyClient interface {
	Name() string
	LookupDomain(ctx context.Context, domain string) (Result, error)
}

// WHOISClient supports both domain and network registration lookups.
type WHOISClient interface {
	WHOISDomainOnlyClient
	LookupNetwork(ctx context.Context, query string) (NetworkResult, error)
}

// WHOIS is a configured sequence of WHOIS lookups. Lookup consults each named
// source in this fixed order: RDAP, TCP-43, Whoxy, WhoisFreaks, then WhoisXML.
// Naming every source makes both the order and the cost of an incomplete lookup
// explicit.
type WHOIS struct {
	RDAPClient        WHOISClient
	TCP43Client       WHOISClient
	WhoxyClient       WHOISDomainOnlyClient
	WhoisFreaksClient WHOISDomainOnlyClient
	WhoisXMLClient    WHOISDomainOnlyClient

	// httpClient builds whichever default lookups the caller did not supply.
	httpClient *http.Client
}

// Option configures WHOIS lookups.
type Option = func(*WHOIS)

// New builds the WHOIS sequence, filling each lookup the caller left unset
// with its default implementation. Callers may pass ad hoc configuration
// functions when direct field assignment is not convenient.
func New(opts ...Option) *WHOIS {
	w := &WHOIS{}
	for _, o := range opts {
		o(w)
	}

	if w.RDAPClient == nil {
		w.RDAPClient = NewRDAPClient(w.httpClient)
	}
	if w.TCP43Client == nil {
		w.TCP43Client = NewTCP43Client()
	}
	if w.WhoxyClient == nil {
		w.WhoxyClient = NewWhoxyClient(w.httpClient, "")
	}
	if w.WhoisFreaksClient == nil {
		w.WhoisFreaksClient = NewWhoisFreaksClient(w.httpClient, "")
	}
	if w.WhoisXMLClient == nil {
		w.WhoisXMLClient = NewWhoisXMLClient(w.httpClient, "")
	}
	return w
}

// WithHTTPClient sets the HTTP client used by the HTTP-based lookups.
func WithHTTPClient(c *http.Client) Option {
	return func(w *WHOIS) { w.httpClient = c }
}

// ErrNoCredential reports that a provider has no API key configured, so it
// cannot be consulted. It is not a lookup failure: the chain skips the provider
// and moves on.
var ErrNoCredential = errors.New("whois: provider credential not configured")

// The commercial providers' config identifiers, as reported by WHOISDomainClient.Name().
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

// Lookup outcomes recorded by logLookup. These are the vocabulary the
// per-provider success rate is computed from, so they are deliberately four
// values rather than a pass/fail pair: "the provider is broken" and "the
// registry has nothing to give anyone" are the same event under a binary flag,
// and telling them apart is the whole point of measuring.
const (
	outcomeFound = "found"
	outcomeEmpty = "empty"
	outcomeError = "error"
	outcomeSkipped = "skipped"
)

// logLookup emits exactly one record per lookup call, at Info so it survives
// production log levels. CloudWatch aggregates these into per-provider success,
// breakage and unkeyed rates, which is what tells an operator whether a
// configured providers are earning their cost.
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
