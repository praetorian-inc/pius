package whois

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// WHOIS is a configured cascade of resolvers. Every leg is a Resolver, so a
// test substitutes a fake by assigning a field rather than by monkey-patching a
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
//
// A nil field is skipped, so the zero value with only Fallbacks set is a valid
// commercial-only cascade, and an empty Fallbacks is a valid free-only one.
type WHOIS struct {
	// RDAPResolver is the structured-metadata leg. Runs first.
	RDAPResolver Resolver
	// TCP43Resolver is the port-43 leg. Runs second, for the email coverage
	// RDAP tends to withhold.
	TCP43Resolver Resolver
	// Fallbacks is the ordered commercial tail, consulted after both free legs.
	Fallbacks []Resolver
}

// New builds a WHOIS from options. With no options it is the default cascade:
// RDAP, TCP-43, then DefaultFallbackOrder.
func New(opts ...Option) *WHOIS {
	cfg := config{}
	for _, o := range opts {
		o(&cfg)
	}
	return newFromConfig(&cfg)
}

func newFromConfig(cfg *config) *WHOIS {
	return &WHOIS{
		RDAPResolver:  NewRDAPResolver(cfg.httpClient),
		TCP43Resolver: NewTCP43Resolver(),
		Fallbacks:     cfg.resolvers(),
	}
}

// cascade flattens the struct into the order legs are consulted. Nil legs are
// dropped here so Lookup does not have to test each one.
func (w *WHOIS) cascade() []Resolver {
	legs := make([]Resolver, 0, 2+len(w.Fallbacks))
	for _, r := range append([]Resolver{w.RDAPResolver, w.TCP43Resolver}, w.Fallbacks...) {
		if r != nil {
			legs = append(legs, r)
		}
	}
	return legs
}

// Lookup resolves domain registration data by walking the cascade and merging
// each leg's answer into a single record, stopping as soon as the record is
// complete.
//
// Per leg: run it, skip it on error, merge its fields into the primary result,
// and advance if the result is still missing anything. Merge is
// first-non-empty-wins, so cascade order is also field precedence — RDAP's
// structured dates beat TCP-43's parsed ones because RDAP runs first, not
// because anything special-cases it.
//
// # Cost
//
// Continuing while the record is incomplete means a lookup that never reaches
// completeness consults every configured provider. Under GDPR and privacy-proxy
// redaction, registrant identity is stripped at the registry and is therefore
// absent from every provider, so redacted domains — the common case, not the
// edge case — walk the full route and bill each paid leg on the way. That is
// the accepted cost of gap-filling across providers; isComplete names the exact
// field set that stops it, and the per-leg slog.Info records what it actually
// costs in practice so the decision can be revisited against data rather than
// argued from first principles.
//
// Keeping the default route short is the mitigation. ErrNoCredential is the one
// failure mode that costs nothing, because no request is sent.
func (w *WHOIS) Lookup(ctx context.Context, domain string) (Result, error) {
	domain = RootDomain(domain)
	if domain == "" {
		return Result{}, fmt.Errorf("whois: no registrable domain")
	}

	var (
		result Result
		errs   []error
		// resolved: some leg contributed actual registration data. It decides
		// two things — whether the lookup succeeded at all, and whether a later
		// Unregistered verdict has better evidence to contradict.
		resolved bool
	)

	for _, r := range w.cascade() {
		// A cancelled context fails every remaining leg for the same reason, so
		// stop rather than generating one identical error per provider.
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}

		res, err := r.Lookup(ctx, domain)

		// Step 3: an error advances to the next leg — except a definitive
		// not-registered verdict, which is an answer and ends the cascade
		// before any further provider is billed to re-confirm it.
		if err != nil {
			if isDomainNotFound(err) {
				return Result{Domain: domain, Unregistered: true}, nil
			}
			if errors.Is(err, ErrNoCredential) {
				slog.Debug("WHOIS leg skipped: no credential",
					"resolver", r.Name(), "domain", domain)
			} else {
				slog.Debug("WHOIS leg failed",
					"resolver", r.Name(), "domain", domain, "error", err)
			}
			errs = append(errs, err)
			continue
		}

		if res.Unregistered {
			// Believed only when nothing has resolved the domain yet. Once a
			// leg has returned a record, a later provider claiming the domain
			// does not exist is contradicting better evidence.
			if !resolved {
				return Result{Domain: domain, Unregistered: true}, nil
			}
			continue
		}

		if !res.hasSubstance() {
			// Acknowledged the query and held nothing.
			continue
		}

		// Scrubbed before merging, not after. A privacy placeholder that
		// reaches Merge first would occupy the field, block the real value a
		// later leg carries, and then be scrubbed to empty at the end — losing
		// data that was available. Scrubbing per leg means only real values
		// ever take precedence, and it is what makes isComplete meaningful:
		// "REDACTED FOR PRIVACY" must not count as a registrant.
		res.ScrubContacts()

		// Step 4.
		result.Merge(res)
		result.Domain = domain
		resolved = true

		// Step 5.
		if result.isComplete() {
			break
		}
	}

	// Success requires that some leg actually contributed data. A cascade where
	// every leg either failed or held nothing is a failed lookup, not a record
	// that happens to be empty — returning Result{Domain: domain} with nil
	// error there would hand the caller a finding carrying only the name it
	// already had.
	if !resolved {
		if joined := errors.Join(errs...); joined != nil {
			return Result{}, fmt.Errorf("whois: all methods failed for %s: %w", domain, joined)
		}
		return Result{}, fmt.Errorf("whois: no source had a record for %s", domain)
	}

	result.Domain = domain
	return result, nil
}

// Option configures a Lookup call.
type Option func(*config)

type config struct {
	httpClient *http.Client

	fallbacks    []Resolver
	fallbacksSet bool
}

// WithHTTPClient sets the HTTP client used for RDAP and the commercial legs.
func WithHTTPClient(c *http.Client) Option {
	return func(cfg *config) { cfg.httpClient = c }
}

// WithFallbackResolvers sets the ordered commercial tail, replacing
// DefaultFallbackOrder. Build it from operator configuration with
// ResolversByName.
//
// Calling this with no resolvers disables the commercial tail entirely, leaving
// RDAP and TCP-43. That is a supported configuration, distinct from not calling
// it at all, which uses the default route.
func WithFallbackResolvers(resolvers ...Resolver) Option {
	return func(cfg *config) {
		cfg.fallbacks = resolvers
		cfg.fallbacksSet = true
	}
}

// resolvers returns the configured tail, or the default when the caller did not
// set one.
func (cfg *config) resolvers() []Resolver {
	if cfg.fallbacksSet {
		return cfg.fallbacks
	}
	return defaultResolvers(cfg.httpClient)
}
