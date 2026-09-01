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
	var response whoxyLiveResponse
	if err := r.lookupDomainJSON(ctx, "whois", domain, &response); err != nil {
		return DomainResult{}, err
	}
	if response.Status != 1 {
		return DomainResult{}, fmt.Errorf("whoxy: lookup failed for %s: %s", domain, response.StatusReason)
	}
	if response.Raw == "" {
		return DomainResult{}, nil
	}

	result, err = parseRawDomainResult(domain, response.Raw)
	if err != nil {
		if isDomainNotFound(err) {
			return DomainResult{Domain: domain, Unregistered: true}, nil
		}
		return DomainResult{}, fmt.Errorf("whoxy: parsing record for %s: %w", domain, err)
	}

	result.Sources = []string{ProviderWhoxy}
	return result, nil
}

// LookupDomainHistory queries Whoxy for up to 30 historical WHOIS records, newest first.
func (r *WhoxyClient) LookupDomainHistory(ctx context.Context, domain string) ([]DomainHistoryRecord, error) {
	var response whoxyHistoryResponse
	if err := r.lookupDomainJSON(ctx, "history", domain, &response); err != nil {
		return nil, err
	}
	if response.Status != 1 {
		return nil, fmt.Errorf("whoxy: history lookup failed for %s: %s", domain, response.StatusReason)
	}

	records := make([]DomainHistoryRecord, 0, len(response.Records))
	for _, record := range response.Records {
		records = append(records, DomainHistoryRecord{
			QueryTime: record.QueryTime,
			DomainResult: DomainResult{
				Domain:      record.Domain,
				Registrar:   record.Registrar.Name,
				Created:     record.Created,
				Updated:     record.Updated,
				Expiration:  record.Expires,
				WhoisServer: record.Registrar.WhoisServer,
				NameServers: record.NameServers,
				Status:      record.Status,
				Registrant:  mapWhoxyHistoryContact(record.Registrant),
				Admin:       mapWhoxyHistoryContact(record.Admin),
				Tech:        mapWhoxyHistoryContact(record.Tech),
				Billing:     mapWhoxyHistoryContact(record.Billing),
			},
		})
	}
	return normalizeDomainHistory(domain, ProviderWhoxy, records), nil
}

func mapWhoxyHistoryContact(contact whoxyHistoryContact) Contact {
	return Contact{
		Organization: contact.Company,
		Name:         contact.Name,
		Email:        contact.Email,
		Country:      cmp.Or(contact.CountryCode, contact.Country),
		Province:     contact.State,
		City:         contact.City,
		Street:       contact.MailingAddress,
		PostalCode:   contact.PostalCode,
		Phone:        contact.Phone,
	}
}

func (r *WhoxyClient) lookupDomainJSON(ctx context.Context, operation, domain string, out any) error {
	apiKey := r.getAPIKey()
	if apiKey == "" {
		return ErrNoCredential
	}

	params := url.Values{}
	params.Set("key", apiKey)
	params.Set(operation, domain)
	reqURL := strings.TrimRight(r.apiBase(), "/") + "/?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("whoxy: building %s request for %s: %w", operation, domain, err)
	}

	httpClient := cmp.Or(r.httpClient, http.DefaultClient)
	resp, err := httpClient.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("whoxy: %s request failed for %s: %w", operation, domain, urlErr.Err)
		}
		return fmt.Errorf("whoxy: %s request failed for %s", operation, domain)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("whoxy: %s API returned HTTP %d for %s", operation, resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("whoxy: reading %s response for %s: %w", operation, domain, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("whoxy: decoding %s response for %s: %w", operation, domain, err)
	}
	return nil
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

// whoxyLiveResponse is Whoxy's live-WHOIS envelope.
type whoxyLiveResponse struct {
	Raw          string `json:"raw_whois"`
	Status       int    `json:"status"`
	StatusReason string `json:"status_reason"`
}

type whoxyHistoryResponse struct {
	Status       int                  `json:"status"`
	StatusReason string               `json:"status_reason"`
	Records      []whoxyHistoryRecord `json:"whois_records"`
}

type whoxyHistoryRecord struct {
	QueryTime   string                `json:"query_time"`
	Domain      string                `json:"domain_name"`
	Created     string                `json:"create_date"`
	Updated     string                `json:"update_date"`
	Expires     string                `json:"expiry_date"`
	Registrar   whoxyHistoryRegistrar `json:"domain_registrar"`
	Registrant  whoxyHistoryContact   `json:"registrant_contact"`
	Admin       whoxyHistoryContact   `json:"administrative_contact"`
	Tech        whoxyHistoryContact   `json:"technical_contact"`
	Billing     whoxyHistoryContact   `json:"billing_contact"`
	NameServers []string              `json:"name_servers"`
	Status      []string              `json:"domain_status"`
}

type whoxyHistoryRegistrar struct {
	Name        string `json:"registrar_name"`
	WhoisServer string `json:"whois_server"`
}

type whoxyHistoryContact struct {
	Name           string `json:"full_name"`
	Company        string `json:"company_name"`
	Email          string `json:"email_address"`
	MailingAddress string `json:"mailing_address"`
	City           string `json:"city_name"`
	State          string `json:"state_name"`
	PostalCode     string `json:"zip_code"`
	Country        string `json:"country_name"`
	CountryCode    string `json:"country_code"`
	Phone          string `json:"phone_number"`
}
