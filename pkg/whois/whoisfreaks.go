package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
)

// whoisFreaksBaseURL is the WhoisFreaks v2.0 Live WHOIS API endpoint.
// It is a var so tests can point it at httptest.Server.
var whoisFreaksBaseURL = "https://api.whoisfreaks.com/v2.0/whois/live"

// whoisFreaksResponse mirrors the WhoisFreaks v2.0 Live WHOIS JSON response.
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

// whoisFreaksLookup queries the WhoisFreaks v2.0 Live WHOIS API for domain
// registration data. If WHOISFREAKS_API_KEY is unset, it returns a zero Result
// with nil error (no-op).
//
// Prefer WhoisFreaksResolver, which participates in the configurable fallback
// route and reports a missing key as ErrNoCredential rather than silently
// doing nothing.
func whoisFreaksLookup(ctx context.Context, httpClient *http.Client, domain string) (Result, error) {
	return whoisFreaksLookupWithKey(ctx, httpClient, os.Getenv("WHOISFREAKS_API_KEY"), domain)
}

// whoisFreaksLookupWithKey is whoisFreaksLookup with the credential supplied by
// the caller, so a resolver configured with an explicit key does not have to go
// through the environment.
func whoisFreaksLookupWithKey(ctx context.Context, httpClient *http.Client, apiKey, domain string) (Result, error) {
	if apiKey == "" {
		return Result{}, nil
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	params := url.Values{}
	params.Set("apiKey", apiKey)
	params.Set("domainName", domain)
	reqURL := whoisFreaksBaseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("whoisfreaks: building request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			return Result{}, fmt.Errorf("whoisfreaks: request failed for %s: %w", domain, urlErr.Err)
		}
		return Result{}, fmt.Errorf("whoisfreaks: request failed for %s: %w", domain, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		slog.Debug("WhoisFreaks API returned non-200", "domain", domain, "status", resp.StatusCode)
		return Result{}, fmt.Errorf("whoisfreaks: API returned HTTP %d for %s", resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return Result{}, fmt.Errorf("whoisfreaks: reading response for %s: %w", domain, err)
	}

	var wfResp whoisFreaksResponse
	if err := json.Unmarshal(body, &wfResp); err != nil {
		return Result{}, fmt.Errorf("whoisfreaks: decoding response for %s: %w", domain, err)
	}

	if !wfResp.Status {
		return Result{}, fmt.Errorf("whoisfreaks: API returned unsuccessful status for %s", domain)
	}

	if wfResp.DomainRegistered == "no" {
		return Result{Domain: domain, Unregistered: true}, nil
	}

	return mapWhoisFreaksToResult(domain, wfResp), nil
}

func mapWhoisFreaksToResult(domain string, wf whoisFreaksResponse) Result {
	return Result{
		Domain:      domain,
		Registrar:   wf.DomainRegistrar.RegistrarName,
		Created:     wf.CreateDate,
		Updated:     wf.UpdateDate,
		Expiration:  wf.ExpiryDate,
		WhoisServer: wf.WhoisServer,
		NameServers: wf.NameServers,
		Status:      wf.DomainStatus,
		Sources:     []string{"whoisfreaks"},
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
