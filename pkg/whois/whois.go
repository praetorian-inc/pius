package whois

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
)

// lookupState holds the mutable state for one cascade walk. Keeping it local to
// Lookup allows a configured WHOIS to be reused safely by concurrent callers.
type lookupState struct {
	result       DomainResult
	errs         []error
	unregistered bool
}

// LookupDomain resolves domain registration data by walking w's configured cascade
// and merging each leg's answer into a single record, stopping as soon as the
// record is complete.
func (w *WHOIS) LookupDomain(ctx context.Context, domain string) (DomainResult, error) {
	domain = RootDomain(domain)
	if domain == "" {
		return DomainResult{}, fmt.Errorf("whois: no registrable domain")
	}

	state := lookupState{}

	if w.doDomainLookup(ctx, domain, w.RDAPClient, strictCompletion, &state) {
		return state.finish(domain)
	}
	if w.doDomainLookup(ctx, domain, w.TCP43Client, relaxedCompletion, &state) {
		return state.finish(domain)
	}
	if w.doDomainLookup(ctx, domain, w.WhoxyClient, relaxedCompletion, &state) {
		return state.finish(domain)
	}
	if w.doDomainLookup(ctx, domain, w.WhoisFreaksClient, relaxedCompletion, &state) {
		return state.finish(domain)
	}
	if w.doDomainLookup(ctx, domain, w.WhoisXMLClient, relaxedCompletion, &state) {
		return state.finish(domain)
	}

	return state.finish(domain)
}

// doDomainLookup runs one leg and folds its answer into state, reporting whether the
// cascade should stop. Normalization, logging, merging, and completion remain ordered
// here rather than repeated for each provider.
func (w *WHOIS) doDomainLookup(ctx context.Context, domain string, r WHOISDomainOnlyClient, strict bool, state *lookupState) (stop bool) {
	if err := ctx.Err(); err != nil {
		state.errs = append(state.errs, err)
		return true
	}

	started := time.Now()
	res, err := r.LookupDomain(ctx, domain)
	res.Normalize()
	logLookup(r.Name(), domain, started, res, err)

	if err != nil {
		if isDomainNotFound(err) {
			state.unregistered = true
			return true
		}

		if errors.Is(err, ErrNoCredential) {
			slog.Info("WHOIS leg skipped: no credential",
				"resolver", r.Name(), "domain", domain)
		} else {
			slog.Info("WHOIS leg failed",
				"resolver", r.Name(), "domain", domain, "error", err)
		}

		state.errs = append(state.errs, err)
		return false
	}

	if res.Unregistered {
		if !state.result.hasRegistrationData() {
			state.unregistered = true
			return true
		}
		return false
	}

	state.result.Merge(res)
	state.result.Domain = domain
	return state.result.isComplete(strict)
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

func (state *lookupState) finish(domain string) (DomainResult, error) {
	if state.unregistered {
		return DomainResult{Domain: domain, Unregistered: true}, nil
	}

	// Success requires that some lookup actually contributed data. A sequence
	// where every lookup either failed or held nothing is a failed lookup, not a
	// record that happens to be empty.
	if !state.result.hasRegistrationData() {
		if joined := errors.Join(state.errs...); joined != nil {
			return DomainResult{}, fmt.Errorf("whois: all methods failed for %s: %w", domain, joined)
		}
		return DomainResult{}, fmt.Errorf("whois: no source had a record for %s", domain)
	}

	state.result.Domain = domain
	return state.result, nil
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
