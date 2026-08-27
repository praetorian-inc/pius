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
	result       Result
	errs         []error
	resolved     bool
	unregistered bool
}

// LookupDomain resolves domain registration data by walking w's configured cascade
// and merging each leg's answer into a single record, stopping as soon as the
// record is complete.
func (w *WHOIS) LookupDomain(ctx context.Context, domain string) (Result, error) {
	domain = RootDomain(domain)
	if domain == "" {
		return Result{}, fmt.Errorf("whois: no registrable domain")
	}

	state := lookupState{}

	if w.doDomainLookup(ctx, domain, w.RDAPClient, &state) {
		return state.finish(domain)
	}
	if w.doDomainLookup(ctx, domain, w.TCP43Client, &state) {
		return state.finish(domain)
	}
	if w.doDomainLookup(ctx, domain, w.WhoxyClient, &state) {
		return state.finish(domain)
	}
	if w.doDomainLookup(ctx, domain, w.WhoisFreaksClient, &state) {
		return state.finish(domain)
	}
	if w.doDomainLookup(ctx, domain, w.WhoisXMLClient, &state) {
		return state.finish(domain)
	}

	return state.finish(domain)
}

// doDomainLookup runs one leg and folds its answer into state, reporting whether the
// cascade should stop. Scrub-then-merge-then-check is order-sensitive, so the
// operation is kept in one method rather than repeated for each kind of leg.
func (w *WHOIS) doDomainLookup(ctx context.Context, domain string, r WHOISDomainOnlyClient, state *lookupState) (stop bool) {
	if err := ctx.Err(); err != nil {
		state.errs = append(state.errs, err)
		return true
	}

	res, err := r.LookupDomain(ctx, domain)
	if err != nil {
		if isDomainNotFound(err) {
			state.unregistered = true
			return true
		}

		if errors.Is(err, ErrNoCredential) {
			slog.Debug("WHOIS leg skipped: no credential",
				"resolver", r.Name(), "domain", domain)
		} else {
			slog.Debug("WHOIS leg failed",
				"resolver", r.Name(), "domain", domain, "error", err)
		}

		state.errs = append(state.errs, err)
		return false
	}

	if res.Unregistered {
		if !state.resolved {
			state.unregistered = true
			return true
		}
		return false
	}

	if !res.hasSubstance() {
		return false
	}

	res.ScrubContacts()

	state.result.Merge(res)
	state.result.Domain = domain
	state.resolved = true

	return state.result.isComplete()
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

func (state *lookupState) finish(domain string) (Result, error) {
	if state.unregistered {
		return Result{Domain: domain, Unregistered: true}, nil
	}

	// Success requires that some lookup actually contributed data. A sequence
	// where every lookup either failed or held nothing is a failed lookup, not a
	// record that happens to be empty.
	if !state.resolved {
		if joined := errors.Join(state.errs...); joined != nil {
			return Result{}, fmt.Errorf("whois: all methods failed for %s: %w", domain, joined)
		}
		return Result{}, fmt.Errorf("whois: no source had a record for %s", domain)
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
