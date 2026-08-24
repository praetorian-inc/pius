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

// Lookup resolves domain registration data by walking the cascade the options
// describe and merging each leg's answer into a single record, stopping as soon
// as the record is complete.
//
// The legs run RDAP first (structured, standardized dates), then TCP-43 (for
// the email coverage RDAP tends to withhold), then the operator-ordered
// commercial tail. With no options that is the default cascade; pass
// WithRDAPResolver, WithTCP43Resolver or WithFallbackResolvers to replace any
// leg, which is how a test keeps the network out of it.
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
func Lookup(ctx context.Context, domain string, opts ...Option) (Result, error) {
	domain = RootDomain(domain)
	if domain == "" {
		return Result{}, fmt.Errorf("whois: no registrable domain")
	}

	w := New(opts...)

	var (
		result Result
		errs   []error
		// resolved: some leg contributed actual registration data. It decides
		// two things — whether the lookup succeeded at all, and whether a later
		// Unregistered verdict has better evidence to contradict.
		resolved bool
		// unregistered: a leg returned a definitive not-registered verdict,
		// which is an answer and ends the cascade before any further provider
		// is billed to re-confirm it.
		unregistered bool
	)

	// consult runs one leg and folds its answer into result, reporting whether
	// the cascade should stop. It is one closure rather than three copies of the
	// same twenty lines because scrub-then-merge-then-check is order-sensitive:
	// three transcriptions of it would be three chances to get that order wrong.
	consult := func(r Resolver) (stop bool) {
		if r == nil {
			return false
		}
		// A cancelled context fails every remaining leg for the same reason, so
		// stop rather than generating one identical error per provider.
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			return true
		}

		res, err := r.Lookup(ctx, domain)
		if err != nil {
			if isDomainNotFound(err) {
				unregistered = true
				return true
			}
			if errors.Is(err, ErrNoCredential) {
				slog.Debug("WHOIS leg skipped: no credential",
					"resolver", r.Name(), "domain", domain)
			} else {
				slog.Debug("WHOIS leg failed",
					"resolver", r.Name(), "domain", domain, "error", err)
			}
			errs = append(errs, err)
			return false
		}

		if res.Unregistered {
			// Believed only when nothing has resolved the domain yet. Once a
			// leg has returned a record, a later provider claiming the domain
			// does not exist is contradicting better evidence.
			if !resolved {
				unregistered = true
				return true
			}
			return false
		}

		if !res.hasSubstance() {
			// Acknowledged the query and held nothing.
			return false
		}

		// Scrubbed before merging, not after. A privacy placeholder that
		// reaches Merge first would occupy the field, block the real value a
		// later leg carries, and then be scrubbed to empty at the end — losing
		// data that was available. Scrubbing per leg means only real values
		// ever take precedence, and it is what makes isComplete meaningful:
		// "REDACTED FOR PRIVACY" must not count as a registrant.
		res.ScrubContacts()

		result.Merge(res)
		result.Domain = domain
		resolved = true

		return result.isComplete()
	}

	// RDAP first: free and structured.
	stop := consult(w.RDAPResolver)

	// TCP-43 second: free, and carries the email coverage RDAP withholds.
	if !stop {
		stop = consult(w.TCP43Resolver)
	}

	// The commercial tail stays a loop because its order is operator
	// configuration rather than something this function decides: any ordered
	// subset has to work, including none at all.
	for _, r := range w.Fallbacks {
		if stop {
			break
		}
		stop = consult(r)
	}

	if unregistered {
		return Result{Domain: domain, Unregistered: true}, nil
	}

	// Success requires that some leg actually contributed data. A cascade where
	// every leg either failed or held nothing is a failed lookup, not a record
	// that happens to be empty.
	if !resolved {
		if joined := errors.Join(errs...); joined != nil {
			return Result{}, fmt.Errorf("whois: all methods failed for %s: %w", domain, joined)
		}
		return Result{}, fmt.Errorf("whois: no source had a record for %s", domain)
	}

	result.Domain = domain
	return result, nil
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
