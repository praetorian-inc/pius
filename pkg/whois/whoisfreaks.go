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
)

// whoisFreaksBaseURL is the WhoisFreaks v2.0 Live WHOIS API endpoint.
// It is a var so tests can point it at httptest.Server.
var whoisFreaksBaseURL = "https://api.whoisfreaks.com/v2.0/whois/live"

// WhoisFreaksClient looks up live WHOIS through the WhoisFreaks v2.0 API.
//
// WhoisFreaks has the cheapest marginal live rate of the three commercial legs,
// but GATE 1 measured its free tier throttling at concurrency 1 on a per-minute
// limit shared across its products, so it sits behind the incumbent rather than
// ahead of it.
type WhoisFreaksClient struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
}

// NewWhoisFreaksClient returns a WhoisFreaks resolver. An empty apiKey falls
// back to WHOISFREAKS_API_KEY.
//
// The key is a constructor parameter rather than an environment read at call
// time because Guard injects credentials rather than exporting them, matching
// the fix made on main to WhoxyReverseWHOIS.
func NewWhoisFreaksClient(httpClient *http.Client, apiKey string) *WhoisFreaksClient {
	return &WhoisFreaksClient{httpClient: httpClient, apiKey: apiKey}
}

func (r *WhoisFreaksClient) Name() string { return ProviderWhoisFreaks }

func (r *WhoisFreaksClient) resolveAPIKey() string {
	return cmp.Or(r.apiKey, os.Getenv("WHOISFREAKS_API_KEY"))
}

func (r *WhoisFreaksClient) hasCredential() bool { return r.resolveAPIKey() != "" }

func (r *WhoisFreaksClient) apiBase() string { return cmp.Or(r.baseURL, whoisFreaksBaseURL) }

// whoisFreaksResponse mirrors the WhoisFreaks v2.0 Live WHOIS JSON response.
//
// Status is reported in the body rather than the status code, so an
// unsuccessful payload arrives as an HTTP 200 and the status field — not the
// status code — decides.
type whoisFreaksResponse struct {
	Status           bool                 `json:"status"`
	DomainName       string               `json:"domain_name"`
	DomainRegistered string               `json:"domain_registered"`
	CreateDate       string               `json:"create_date"`
	UpdateDate       string               `json:"update_date"`
	ExpiryDate       string               `json:"expiry_date"`
	WhoisServer      string               `json:"whois_server"`
	DomainRegistrar  whoisFreaksRegistrar `json:"domain_registrar"`
	NameServers      []string             `json:"name_servers"`
	DomainStatus     []string             `json:"domain_status"`
	Registrant       whoisFreaksContact   `json:"registrant_contact"`
	Admin            whoisFreaksContact   `json:"administrative_contact"`
	Tech             whoisFreaksContact   `json:"technical_contact"`
	Billing          whoisFreaksContact   `json:"billing_contact"`
}

type whoisFreaksRegistrar struct {
	RegistrarName string `json:"registrar_name"`
}

type whoisFreaksContact struct {
	Name         string `json:"name"`
	Company      string `json:"company"`
	EmailAddress string `json:"email_address"`
	Street       string `json:"street"`
	City         string `json:"city"`
	State        string `json:"state"`
	ZipCode      string `json:"zip_code"`
	CountryName  string `json:"country_name"`
	CountryCode  string `json:"country_code"`
	Phone        string `json:"phone"`
}

// LookupDomain queries the WhoisFreaks v2.0 Live WHOIS API for domain registration
// data.
//
// A missing key is ErrNoCredential, not a silent empty result: the two are
// indistinguishable to a caller, and an operator who configured this provider
// needs to find out it is not actually serving traffic.
func (r *WhoisFreaksClient) LookupDomain(ctx context.Context, domain string) (result DomainResult, err error) {
	defer logLookup(r.Name(), domain, time.Now(), &result, &err)

	apiKey := r.resolveAPIKey()
	if apiKey == "" {
		return DomainResult{}, ErrNoCredential
	}

	params := url.Values{}
	params.Set("apiKey", apiKey)
	params.Set("domainName", domain)
	reqURL := r.apiBase() + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return DomainResult{}, fmt.Errorf("whoisfreaks: building request for %s: %w", domain, err)
	}

	httpClient := cmp.Or(r.httpClient, http.DefaultClient)
	resp, err := httpClient.Do(req)
	if err != nil {
		// Unwrap *url.Error before reporting. WhoisFreaks authenticates with a
		// query parameter, so Go renders a transport failure as
		// `Get "<full url>": <cause>` — with the API key embedded in it.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return DomainResult{}, fmt.Errorf("whoisfreaks: request failed for %s: %w", domain, urlErr.Err)
		}
		return DomainResult{}, fmt.Errorf("whoisfreaks: request failed for %s", domain)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return DomainResult{}, fmt.Errorf("whoisfreaks: API returned HTTP %d for %s", resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return DomainResult{}, fmt.Errorf("whoisfreaks: reading response for %s: %w", domain, err)
	}

	var wfResp whoisFreaksResponse
	if err := json.Unmarshal(body, &wfResp); err != nil {
		return DomainResult{}, fmt.Errorf("whoisfreaks: decoding response for %s: %w", domain, err)
	}

	// Reported inside an HTTP 200. Trusting the status code here would record a
	// provider-side failure as "this domain has no data".
	if !wfResp.Status {
		return DomainResult{}, fmt.Errorf("whoisfreaks: API returned unsuccessful status for %s", domain)
	}

	if wfResp.DomainRegistered == "no" {
		return DomainResult{Domain: domain, Unregistered: true}, nil
	}

	return mapWhoisFreaksToResult(domain, wfResp), nil
}

func mapWhoisFreaksToResult(domain string, wf whoisFreaksResponse) DomainResult {
	return DomainResult{
		Domain:      domain,
		Registrar:   wf.DomainRegistrar.RegistrarName,
		Created:     wf.CreateDate,
		Updated:     wf.UpdateDate,
		Expiration:  wf.ExpiryDate,
		WhoisServer: wf.WhoisServer,
		NameServers: wf.NameServers,
		Status:      wf.DomainStatus,
		Sources:     []string{ProviderWhoisFreaks},
		Registrant:  mapWhoisFreaksContact(wf.Registrant),
		Admin:       mapWhoisFreaksContact(wf.Admin),
		Tech:        mapWhoisFreaksContact(wf.Tech),
		Billing:     mapWhoisFreaksContact(wf.Billing),
	}
}

func mapWhoisFreaksContact(c whoisFreaksContact) Contact {
	return Contact{
		Organization: c.Company,
		Name:         c.Name,
		Email:        c.EmailAddress,
		Country:      c.CountryCode,
		Province:     c.State,
		City:         c.City,
		Street:       c.Street,
		PostalCode:   c.ZipCode,
		Phone:        c.Phone,
	}
}
