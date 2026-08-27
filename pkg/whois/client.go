package whois

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Client is one source of domain registration data.
//
// Commercial implementations report a missing API key as ErrNoCredential
// rather than as a silent empty result: an operator who configured a provider
// needs to know that it is not actually serving traffic.
type Client interface {
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

// The commercial providers' config identifiers, as reported by WHOISLookup.Name().
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
