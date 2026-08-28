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
	LookupDomain(ctx context.Context, domain string) (DomainResult, error)
}

type WHOISDomainHistoryClient interface {
	WHOISDomainOnlyClient
	LookupDomainHistory(ctx context.Context, domain string) ([]DomainHistoryRecord, error)
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

	httpClient        *http.Client
	whoxyAPIKey       string
	whoisXMLAPIKey    string
	whoisFreaksAPIKey string
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
		w.WhoxyClient = NewWhoxyClient(w.httpClient, w.whoxyAPIKey)
	}
	if w.WhoisFreaksClient == nil {
		w.WhoisFreaksClient = NewWhoisFreaksClient(w.httpClient, w.whoisFreaksAPIKey)
	}
	if w.WhoisXMLClient == nil {
		w.WhoisXMLClient = NewWhoisXMLClient(w.httpClient, w.whoisXMLAPIKey)
	}
	return w
}

// WithHTTPClient sets the HTTP client used by the HTTP-based lookups.
func WithHTTPClient(c *http.Client) Option {
	return func(w *WHOIS) { w.httpClient = c }
}

// WithWhoxyAPIKey sets the Whoxy API key used by the default client.
func WithWhoxyAPIKey(apiKey string) Option {
	return func(w *WHOIS) { w.whoxyAPIKey = apiKey }
}

// WithWhoisXMLAPIKey sets the WhoisXML API key used by the default client.
func WithWhoisXMLAPIKey(apiKey string) Option {
	return func(w *WHOIS) { w.whoisXMLAPIKey = apiKey }
}

// WithWhoisFreaksAPIKey sets the WhoisFreaks API key used by the default client.
func WithWhoisFreaksAPIKey(apiKey string) Option {
	return func(w *WHOIS) { w.whoisFreaksAPIKey = apiKey }
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
	outcomeFound   = "found"
	outcomeEmpty   = "empty"
	outcomeError   = "error"
	outcomeSkipped = "skipped"
)

// logLookup records one provider outcome without logging error text that may
// contain a provider API key.
func logLookup(name, domain string, started time.Time, result DomainResult, err error) {
	outcome := outcomeFound
	switch {
	case errors.Is(err, ErrNoCredential):
		outcome = outcomeSkipped
	case err != nil:
		outcome = outcomeError
	case result.Unregistered:
		// A definitive not-registered verdict answered the question.
		outcome = outcomeFound
	case !result.hasRegistrationData():
		outcome = outcomeEmpty
	}

	slog.Info("whois lookup complete",
		"resolver", name,
		"domain", domain,
		"result", outcome,
		"duration_ms", time.Since(started).Milliseconds())
}
