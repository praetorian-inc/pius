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
	"strings"
)

// Provider endpoints are vars so tests can point them at httptest.Server.
var (
	whoisFreaksBaseURL        = "https://api.whoisfreaks.com/v2.0/whois/live"
	whoisFreaksHistoryBaseURL = "https://api.whoisfreaks.com/v2.0/whois/history"
)

// WhoisFreaksClient looks up live WHOIS through the WhoisFreaks v2.0 API.
//
// WhoisFreaks has the cheapest marginal live rate of the three commercial legs,
// but GATE 1 measured its free tier throttling at concurrency 1 on a per-minute
// limit shared across its products, so it sits behind the incumbent rather than
// ahead of it.
type WhoisFreaksClient struct {
	httpClient     *http.Client
	apiKey         string
	baseURL        string
	historyBaseURL string
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

// LookupDomain queries the WhoisFreaks v2.0 Live WHOIS API for domain registration
// data.
//
// A missing key is ErrNoCredential, not a silent empty result: the two are
// indistinguishable to a caller, and an operator who configured this provider
// needs to find out it is not actually serving traffic.
func (r *WhoisFreaksClient) LookupDomain(ctx context.Context, domain string) (result DomainResult, err error) {
	var response whoisFreaksResponse
	if err := r.lookupDomainJSON(ctx, "live", r.apiBase(), domain, &response); err != nil {
		return DomainResult{}, err
	}
	if !response.Status {
		return DomainResult{}, fmt.Errorf("whoisfreaks: API returned unsuccessful status for %s", domain)
	}
	if response.DomainRegistered == "no" {
		return DomainResult{Domain: domain, Unregistered: true}, nil
	}
	return mapWhoisFreaksToResult(domain, response), nil
}

// LookupDomainHistory queries WhoisFreaks for up to 30 historical WHOIS records, newest first.
func (r *WhoisFreaksClient) LookupDomainHistory(ctx context.Context, domain string) ([]DomainHistoryRecord, error) {
	var response whoisFreaksHistoryResponse
	if err := r.lookupDomainJSON(ctx, "history", r.historyAPIBase(), domain, &response); err != nil {
		return nil, err
	}
	if !response.Status {
		return nil, fmt.Errorf("whoisfreaks: history API returned unsuccessful status for %s", domain)
	}

	records := make([]DomainHistoryRecord, 0, len(response.Records))
	for _, record := range response.Records {
		result := mapWhoisFreaksToResult(cmp.Or(record.DomainName, domain), record.whoisFreaksResponse)
		if registry := record.RegistryData; registry != nil {
			result.Merge(mapWhoisFreaksToResult(cmp.Or(registry.DomainName, domain), registry.whoisFreaksResponse))
		}
		result.Unregistered = strings.EqualFold(record.DomainRegistered, "no") && !result.hasRegistrationData()
		records = append(records, DomainHistoryRecord{
			DomainResult: result,
			QueryTime:    cmp.Or(record.QueryTime, record.registryQueryTime()),
		})
	}
	return normalizeDomainHistory(domain, ProviderWhoisFreaks, records), nil
}

func mapWhoisFreaksToResult(domain string, response whoisFreaksResponse) DomainResult {
	return DomainResult{
		Domain:      domain,
		Registrar:   response.DomainRegistrar.RegistrarName,
		Created:     response.CreateDate,
		Updated:     response.UpdateDate,
		Expiration:  response.ExpiryDate,
		WhoisServer: response.WhoisServer,
		NameServers: response.NameServers,
		Status:      response.DomainStatus,
		Sources:     []string{ProviderWhoisFreaks},
		Registrant:  mapWhoisFreaksContact(response.Registrant),
		Admin:       mapWhoisFreaksContact(response.Admin),
		Tech:        mapWhoisFreaksContact(response.Tech),
		Billing:     mapWhoisFreaksContact(response.Billing),
	}
}

func mapWhoisFreaksContact(contact whoisFreaksContact) Contact {
	return Contact{
		Organization: contact.Company,
		Name:         contact.Name,
		Email:        contact.EmailAddress,
		Country:      cmp.Or(contact.CountryCode, contact.CountryName),
		Province:     contact.State,
		City:         contact.City,
		Street:       cmp.Or(contact.Street, contact.MailingAddress),
		PostalCode:   contact.ZipCode,
		Phone:        contact.Phone,
	}
}

func (r *WhoisFreaksClient) historyAPIBase() string {
	return cmp.Or(r.historyBaseURL, whoisFreaksHistoryBaseURL)
}

func (r *WhoisFreaksClient) lookupDomainJSON(ctx context.Context, operation, endpoint, domain string, out any) error {
	apiKey := r.resolveAPIKey()
	if apiKey == "" {
		return ErrNoCredential
	}

	params := url.Values{}
	params.Set("apiKey", apiKey)
	params.Set("domainName", domain)
	reqURL := endpoint + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("whoisfreaks: building %s request for %s: %w", operation, domain, err)
	}

	httpClient := cmp.Or(r.httpClient, http.DefaultClient)
	resp, err := httpClient.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("whoisfreaks: %s request failed for %s: %w", operation, domain, urlErr.Err)
		}
		return fmt.Errorf("whoisfreaks: %s request failed for %s", operation, domain)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("whoisfreaks: %s API returned HTTP %d for %s", operation, resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("whoisfreaks: reading %s response for %s: %w", operation, domain, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("whoisfreaks: decoding %s response for %s: %w", operation, domain, err)
	}
	return nil
}

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

type whoisFreaksHistoryResponse struct {
	Status  bool                       `json:"status"`
	Records []whoisFreaksHistoryRecord `json:"whois_domains_historical"`
}

type whoisFreaksHistoryRecord struct {
	whoisFreaksResponse
	QueryTime    string                  `json:"query_time"`
	RegistryData *whoisFreaksHistoryData `json:"registry_data"`
}

func (r whoisFreaksHistoryRecord) registryQueryTime() string {
	if r.RegistryData == nil {
		return ""
	}
	return r.RegistryData.QueryTime
}

type whoisFreaksHistoryData struct {
	whoisFreaksResponse
	QueryTime string `json:"query_time"`
}

type whoisFreaksRegistrar struct {
	RegistrarName string `json:"registrar_name"`
}

type whoisFreaksContact struct {
	Name           string `json:"name"`
	Company        string `json:"company"`
	EmailAddress   string `json:"email_address"`
	Street         string `json:"street"`
	MailingAddress string `json:"mailing_address"`
	City           string `json:"city"`
	State          string `json:"state"`
	ZipCode        string `json:"zip_code"`
	CountryName    string `json:"country_name"`
	CountryCode    string `json:"country_code"`
	Phone          string `json:"phone"`
}
