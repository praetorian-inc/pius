package whois

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	whoisparser "github.com/likexian/whois-parser"
)

// whoxyBaseURL is the Whoxy API endpoint. It is a var so tests can point it at
// an httptest.Server.
var whoxyBaseURL = "https://api.whoxy.com/"

// WhoxyResolver looks up live WHOIS through the Whoxy API.
//
// Whoxy returns the registry's raw WHOIS text rather than parsed fields, so the
// response is run through the same whoisparser mapping the TCP-43 leg uses.
// The request shape matches the code running in Guard production today
// (guard-core .../capabilities/whois/whois.go).
type WhoxyResolver struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
}

// NewWhoxyResolver returns a Whoxy resolver. An empty apiKey falls back to
// WHOXY_API_KEY, matching the convention of the existing Whoxy reverse-WHOIS
// plugin.
func NewWhoxyResolver(httpClient *http.Client, apiKey string) *WhoxyResolver {
	return &WhoxyResolver{httpClient: httpClient, apiKey: apiKey}
}

func (r *WhoxyResolver) Name() string { return ProviderWhoxy }

func (r *WhoxyResolver) resolveAPIKey() string {
	return cmp.Or(r.apiKey, os.Getenv("WHOXY_API_KEY"))
}

func (r *WhoxyResolver) hasCredential() bool { return r.resolveAPIKey() != "" }

func (r *WhoxyResolver) apiBase() string { return cmp.Or(r.baseURL, whoxyBaseURL) }

// whoxyLiveResponse is Whoxy's live-WHOIS envelope. status == 1 means success;
// anything else carries the reason in status_reason, including "Zero Account
// Balance" when the credit pool is exhausted. Note that Whoxy reports that
// failure with HTTP 200, so the status field — not the status code — decides.
type whoxyLiveResponse struct {
	Raw          string `json:"raw_whois"`
	Status       int    `json:"status"`
	StatusReason string `json:"status_reason"`
}

func (r *WhoxyResolver) Lookup(ctx context.Context, domain string) (result Result, err error) {
	defer logLookup(r.Name(), domain, time.Now(), &result, &err)

	apiKey := r.resolveAPIKey()
	if apiKey == "" {
		return Result{}, ErrNoCredential
	}

	params := url.Values{}
	params.Set("key", apiKey)
	params.Set("whois", domain)
	reqURL := r.apiBase() + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("whoxy: building request for %s: %w", domain, err)
	}

	httpClient := cmp.Or(r.httpClient, http.DefaultClient)
	resp, err := httpClient.Do(req)
	if err != nil {
		// Unwrap *url.Error before reporting. Whoxy authenticates with a query
		// parameter, so Go renders a transport failure as
		// `Get "<full url>": <cause>` — with the API key embedded in it.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return Result{}, fmt.Errorf("whoxy: request failed for %s: %w", domain, urlErr.Err)
		}
		return Result{}, fmt.Errorf("whoxy: request failed for %s", domain)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("whoxy: API returned HTTP %d for %s", resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return Result{}, fmt.Errorf("whoxy: reading response for %s: %w", domain, err)
	}

	var wr whoxyLiveResponse
	if err := json.Unmarshal(body, &wr); err != nil {
		return Result{}, fmt.Errorf("whoxy: decoding response for %s: %w", domain, err)
	}

	if wr.Status != 1 {
		return Result{}, fmt.Errorf("whoxy: lookup failed for %s: %s", domain, wr.StatusReason)
	}

	if wr.Raw == "" {
		// Answered successfully, but holds nothing for this domain.
		return Result{}, nil
	}

	parsed, err := whoisparser.Parse(wr.Raw)
	if err != nil {
		if errors.Is(err, whoisparser.ErrNotFoundDomain) {
			return Result{Domain: domain, Unregistered: true}, nil
		}
		return Result{}, fmt.Errorf("whoxy: parsing record for %s: %w", domain, err)
	}

	result = mapParsedToResult(domain, parsed)
	result.Sources = []string{ProviderWhoxy}
	return result, nil
}
