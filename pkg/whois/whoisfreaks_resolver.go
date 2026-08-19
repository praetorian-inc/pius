package whois

import (
	"cmp"
	"context"
	"net/http"
	"os"
)

// WhoisFreaksResolver adapts the WhoisFreaks v2.0 Live WHOIS leg to the
// Resolver interface so it can take part in the configurable fallback route.
//
// It lives in its own file to keep the diff against the upstream WhoisFreaks
// change small: this branch is stacked on that PR, and edits to whoisfreaks.go
// would conflict every time it is revised.
type WhoisFreaksResolver struct {
	httpClient *http.Client
	apiKey     string
}

// NewWhoisFreaksResolver returns a WhoisFreaks resolver. An empty apiKey falls
// back to WHOISFREAKS_API_KEY.
func NewWhoisFreaksResolver(httpClient *http.Client, apiKey string) *WhoisFreaksResolver {
	return &WhoisFreaksResolver{httpClient: httpClient, apiKey: apiKey}
}

func (r *WhoisFreaksResolver) Name() string { return ProviderWhoisFreaks }

func (r *WhoisFreaksResolver) resolveAPIKey() string {
	return cmp.Or(r.apiKey, os.Getenv("WHOISFREAKS_API_KEY"))
}

func (r *WhoisFreaksResolver) hasCredential() bool { return r.resolveAPIKey() != "" }

// Lookup reports a missing credential as ErrNoCredential. The underlying
// whoisFreaksLookup returns an empty result and a nil error in that case, which
// is indistinguishable from "this provider has no record" — a distinction the
// route needs in order to tell an operator that a configured provider is not
// actually serving traffic.
func (r *WhoisFreaksResolver) Lookup(ctx context.Context, domain string) (Result, error) {
	apiKey := r.resolveAPIKey()
	if apiKey == "" {
		return Result{}, ErrNoCredential
	}
	return whoisFreaksLookupWithKey(ctx, r.httpClient, apiKey, domain)
}
