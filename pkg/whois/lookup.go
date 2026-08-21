package whois

import (
	"context"
	"errors"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
)

// Lookup resolves domain registration data through the default cascade: RDAP
// first (structured, standardized dates), then TCP-43 (better email coverage),
// then an operator-configurable route of commercial providers, merging each
// leg's fields into one record until the record is complete.
//
// It is a convenience wrapper over New(opts...).Lookup, kept because that is
// the shape callers already use. Construct a WHOIS directly to inject a fake
// leg.
func Lookup(ctx context.Context, domain string, opts ...Option) (Result, error) {
	return New(opts...).Lookup(ctx, domain)
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
