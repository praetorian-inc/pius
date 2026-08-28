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
	"slices"
	"strings"

	httpclient "github.com/praetorian-inc/pius/pkg/client"
)

// whoxyBaseURL is the Whoxy API endpoint. It is a var so tests can point it at
// an httptest.Server.
var whoxyBaseURL = "https://api.whoxy.com/"

// WhoxyClient looks up live WHOIS through the Whoxy API.
//
// Whoxy returns the registry's raw WHOIS text rather than parsed fields, so the
// response is run through the same whoisparser mapping the TCP-43 leg uses.
// The request shape matches the code running in Guard production today
// (guard-core .../capabilities/whois/whois.go).
type WhoxyClient struct {
	httpClient        *http.Client
	reverseHTTPClient *httpclient.Client
	apiKey            string
	baseURL           string
}

// NewWhoxyClient returns a Whoxy resolver. An empty apiKey falls back to
// WHOXY_API_KEY, matching the convention of the existing Whoxy reverse-WHOIS
// plugin.
func NewWhoxyClient(httpClient *http.Client, apiKey string) *WhoxyClient {
	reverseHTTPClient := httpclient.New()
	if httpClient != nil {
		reverseHTTPClient = httpclient.NewWithHTTPClient(httpClient)
	}
	return &WhoxyClient{
		httpClient:        httpClient,
		reverseHTTPClient: reverseHTTPClient,
		apiKey:            apiKey,
	}
}

// WithBaseURL overrides the Whoxy API endpoint. It is primarily useful for
// tests and applies to both live and reverse WHOIS requests.
func (r *WhoxyClient) WithBaseURL(baseURL string) *WhoxyClient {
	r.baseURL = baseURL
	return r
}

// WithReverseHTTPClient sets the shared Pius client used for reverse WHOIS.
// Live WHOIS continues to use the regular HTTP client supplied to the
// constructor.
func (r *WhoxyClient) WithReverseHTTPClient(client *httpclient.Client) *WhoxyClient {
	if client != nil {
		r.reverseHTTPClient = client
	}
	return r
}

func (r *WhoxyClient) Name() string { return ProviderWhoxy }

func (r *WhoxyClient) getAPIKey() string {
	return cmp.Or(r.apiKey, os.Getenv("WHOXY_API_KEY"))
}

func (r *WhoxyClient) hasCredential() bool { return r.getAPIKey() != "" }

func (r *WhoxyClient) apiBase() string { return cmp.Or(r.baseURL, whoxyBaseURL) }

// whoxyLiveResponse is Whoxy's live-WHOIS envelope. status == 1 means success;
// anything else carries the reason in status_reason, including "Zero Account
// Balance" when the credit pool is exhausted. Note that Whoxy reports that
// failure with HTTP 200, so the status field — not the status code — decides.
type whoxyLiveResponse struct {
	Raw          string `json:"raw_whois"`
	Status       int    `json:"status"`
	StatusReason string `json:"status_reason"`
}

// WhoxyReverseResponse is one page returned by Whoxy's reverse-WHOIS API.
type WhoxyReverseResponse struct {
	TotalPages   int                  `json:"total_pages"`
	SearchResult []WhoxyReverseResult `json:"search_result"`
}

// WhoxyReverseResult is one domain in a reverse-WHOIS response.
type WhoxyReverseResult struct {
	DomainName string `json:"domain_name"`
	QueryTime  string `json:"query_time"`
}

// ReverseLookup retrieves one page of domains associated with value. Field
// must be "company", "name", or "email".
func (r *WhoxyClient) ReverseLookup(ctx context.Context, field, value string, page int) (WhoxyReverseResponse, error) {
	if !slices.Contains([]string{"company", "name", "email"}, field) {
		return WhoxyReverseResponse{}, fmt.Errorf("whoxy: unsupported reverse-WHOIS field %q", field)
	}
	if page < 1 {
		return WhoxyReverseResponse{}, fmt.Errorf("whoxy: reverse-WHOIS page must be positive")
	}

	apiKey := r.getAPIKey()
	if apiKey == "" {
		return WhoxyReverseResponse{}, ErrNoCredential
	}

	params := url.Values{}
	params.Set("key", apiKey)
	params.Set("reverse", "whois")
	params.Set(field, value)
	params.Set("mode", "micro")
	params.Set("page", fmt.Sprint(page))
	reqURL := strings.TrimRight(r.apiBase(), "/") + "/?" + params.Encode()

	body, err := r.reverseHTTPClient.Get(ctx, reqURL)
	if err != nil {
		// Do not wrap client errors because transport failures may contain the
		// query URL and its API key.
		return WhoxyReverseResponse{}, fmt.Errorf("whoxy: reverse-WHOIS request failed")
	}

	var response WhoxyReverseResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return WhoxyReverseResponse{}, fmt.Errorf("whoxy: decoding reverse-WHOIS response: %w", err)
	}
	return response, nil
}

func (r *WhoxyClient) LookupDomain(ctx context.Context, domain string) (result DomainResult, err error) {
	apiKey := r.getAPIKey()
	if apiKey == "" {
		return DomainResult{}, ErrNoCredential
	}

	params := url.Values{}
	params.Set("key", apiKey)
	params.Set("whois", domain)
	reqURL := r.apiBase() + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return DomainResult{}, fmt.Errorf("whoxy: building request for %s: %w", domain, err)
	}

	httpClient := cmp.Or(r.httpClient, http.DefaultClient)
	resp, err := httpClient.Do(req)
	if err != nil {
		// Unwrap *url.Error before reporting. Whoxy authenticates with a query
		// parameter, so Go renders a transport failure as
		// `Get "<full url>": <cause>` — with the API key embedded in it.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return DomainResult{}, fmt.Errorf("whoxy: request failed for %s: %w", domain, urlErr.Err)
		}
		return DomainResult{}, fmt.Errorf("whoxy: request failed for %s", domain)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return DomainResult{}, fmt.Errorf("whoxy: API returned HTTP %d for %s", resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return DomainResult{}, fmt.Errorf("whoxy: reading response for %s: %w", domain, err)
	}

	var wr whoxyLiveResponse
	if err := json.Unmarshal(body, &wr); err != nil {
		return DomainResult{}, fmt.Errorf("whoxy: decoding response for %s: %w", domain, err)
	}

	if wr.Status != 1 {
		return DomainResult{}, fmt.Errorf("whoxy: lookup failed for %s: %s", domain, wr.StatusReason)
	}

	if wr.Raw == "" {
		// Answered successfully, but holds nothing for this domain.
		return DomainResult{}, nil
	}

	result, err = parseRawDomainResult(domain, wr.Raw)
	if err != nil {
		if isDomainNotFound(err) {
			return DomainResult{Domain: domain, Unregistered: true}, nil
		}
		return DomainResult{}, fmt.Errorf("whoxy: parsing record for %s: %w", domain, err)
	}

	result.Sources = []string{ProviderWhoxy}
	return result, nil
}
