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
	whoisXMLBaseURL        = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
	whoisXMLHistoryBaseURL = "https://whois-history.whoisxmlapi.com/api/v1"
)

// WhoisXMLClient looks up live WHOIS through the WhoisXML API.
//
// Of the three providers this is the most expensive per query and by far the
// highest throughput, so it runs last and is reached only when the cheaper
// providers did not complete the record.
type WhoisXMLClient struct {
	httpClient     *http.Client
	apiKey         string
	baseURL        string
	historyBaseURL string

	// hardRefresh forces WhoisXML to re-query the registry rather than serve
	// its cache. It costs 5 credits against 1 for a normal lookup, so it is off
	// unless explicitly enabled and must never become implicit.
	hardRefresh bool
}

// NewWhoisXMLClient returns a WhoisXML resolver with hard refresh disabled.
// An empty apiKey falls back to WHOISXML_API_KEY.
func NewWhoisXMLClient(httpClient *http.Client, apiKey string) *WhoisXMLClient {
	return &WhoisXMLClient{httpClient: httpClient, apiKey: apiKey}
}

// WithHardRefresh enables WhoisXML's hard refresh. It is a 5x cost multiplier
// (5 credits per query against 1), so callers must opt in deliberately.
func (r *WhoisXMLClient) WithHardRefresh(enabled bool) *WhoisXMLClient {
	r.hardRefresh = enabled
	return r
}

func (r *WhoisXMLClient) Name() string { return ProviderWhoisXML }

func (r *WhoisXMLClient) resolveAPIKey() string {
	return cmp.Or(r.apiKey, os.Getenv("WHOISXML_API_KEY"))
}

func (r *WhoisXMLClient) hasCredential() bool { return r.resolveAPIKey() != "" }

func (r *WhoisXMLClient) apiBase() string { return cmp.Or(r.baseURL, whoisXMLBaseURL) }

// dataErrorMissingWhois is WhoisXML's marker for "no WHOIS data available".
const dataErrorMissingWhois = "MISSING_WHOIS_DATA"

func (r *WhoisXMLClient) LookupDomain(ctx context.Context, domain string) (result DomainResult, err error) {
	params := url.Values{"outputFormat": {"JSON"}}
	if r.hardRefresh {
		params.Set("_hardRefresh", "1")
	}

	var wx whoisXMLResponse
	if err := r.lookupDomainJSON(ctx, "live", r.apiBase(), domain, params, &wx); err != nil {
		return DomainResult{}, err
	}

	// Checked on the decoded envelope rather than by scanning the payload for a
	// marker string: a WHOIS record is attacker-influenced text, and matching
	// loose substrings against a successful body is how a valid record gets
	// misread as a failure.
	if e := wx.ErrorMessage; e != nil && e.ErrorCode != "" {
		return DomainResult{}, fmt.Errorf("whoisxml: %s for %s: %s", e.ErrorCode, domain, e.Msg)
	}

	rec := wx.WhoisRecord
	registry := rec.RegistryData

	// Either record may carry the verdict, so read dataError across the pair.
	dataErr := rec.DataError
	if registry != nil {
		dataErr = cmp.Or(dataErr, registry.DataError)
	}

	// WhoisXML splits data across the registrar-level record and the
	// registry-level one, documents them as having "almost identical data
	// structures", and recommends looking "under both WhoisRecord and
	// registryData when searching for a piece of information (e.g. registrant,
	// createdDate)". Most ccTLDs populate only registryData — and ccTLDs are the
	// bulk of the coverage gap this lookup exists to close — so both are mapped
	// and merged. Merging whole Results rather than copying selected fields also
	// means contacts are carried across, which is the reason this lookup was
	// consulted in the first place.
	result = mapWhoisXMLToResult(domain, rec)
	if registry != nil {
		result.Merge(mapWhoisXMLToResult(domain, *registry))
	}
	// Merge accumulates Sources, but both halves came from one provider.
	result.Sources = []string{ProviderWhoisXML}

	// Judged on the merged record, not on the registrar-level marker alone. A
	// thin registry sets dataError at the registrar level while registryData
	// carries the actual record, so testing dataError first would throw away a
	// usable answer — and worse, report a live domain as unregistered.
	result.Normalize()
	if result.hasRegistrationData() {
		return result, nil
	}

	if dataErr == dataErrorMissingWhois {
		// Documented as "domain is not registered; no need to retry fetching the
		// data", so with no substance anywhere this is a verdict, not a gap.
		//
		// Safe to report here: Lookup discards an Unregistered result whenever
		// an earlier lookup already
		// returned a record, so it is only believed when nothing else resolved
		// the domain at all.
		return DomainResult{Domain: domain, Unregistered: true}, nil
	}

	// Answered, but holds nothing usable — Lookup should continue.
	return DomainResult{}, nil
}

// LookupDomainHistory queries WhoisXML for up to 30 historical WHOIS records, newest first.
func (r *WhoisXMLClient) LookupDomainHistory(ctx context.Context, domain string) ([]DomainHistoryRecord, error) {
	params := url.Values{"mode": {"purchase"}}
	var response whoisXMLHistoryResponse
	if err := r.lookupDomainJSON(ctx, "history", r.historyAPIBase(), domain, params, &response); err != nil {
		return nil, err
	}
	if response.Code != 0 {
		return nil, fmt.Errorf("whoisxml: history API returned code %d for %s: %s", response.Code, domain, response.Messages)
	}

	records := make([]DomainHistoryRecord, 0, len(response.Records))
	for _, record := range response.Records {
		records = append(records, DomainHistoryRecord{
			QueryTime: cmp.Or(record.Audit.CreatedDate, record.Audit.UpdatedDate),
			DomainResult: DomainResult{
				Domain:      record.DomainName,
				Registrar:   record.RegistrarName,
				Created:     cmp.Or(record.CreatedDate, record.CreatedDateRaw),
				Updated:     cmp.Or(record.UpdatedDate, record.UpdatedDateRaw),
				Expiration:  cmp.Or(record.ExpiresDate, record.ExpiresDateRaw),
				WhoisServer: record.WhoisServer,
				NameServers: record.NameServers,
				Status:      record.Status,
				Registrant:  mapWhoisXMLHistoryContact(record.Registrant),
				Admin:       mapWhoisXMLHistoryContact(record.Admin),
				Tech:        mapWhoisXMLHistoryContact(record.Tech),
				Billing:     mapWhoisXMLHistoryContact(record.Billing),
			},
		})
	}
	return normalizeDomainHistory(domain, ProviderWhoisXML, records), nil
}

func mapWhoisXMLToResult(domain string, rec whoisXMLRecord) DomainResult {
	return DomainResult{
		Domain:      domain,
		Registrar:   rec.RegistrarName,
		Created:     rec.CreatedDate,
		Updated:     rec.UpdatedDate,
		Expiration:  rec.ExpiresDate,
		WhoisServer: rec.WhoisServer,
		NameServers: rec.NameServers.HostNames,
		Status:      splitWhoisXMLStatus(rec.Status),
		Sources:     []string{ProviderWhoisXML},
		Registrant:  mapWhoisXMLContact(rec.Registrant),
		Admin:       mapWhoisXMLContact(rec.Admin),
		Tech:        mapWhoisXMLContact(rec.Tech),
		Billing:     mapWhoisXMLContact(rec.Billing),
	}
}

// splitWhoisXMLStatus turns WhoisXML's space-separated status string into the
// slice Result carries. EPP status values are routinely followed by the ICANN
// URL that documents them, which is noise rather than status.
func splitWhoisXMLStatus(status string) []string {
	fields := strings.Fields(status)
	if len(fields) == 0 {
		return nil
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			continue
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mapWhoisXMLContact(c whoisXMLContact) Contact {
	return Contact{
		Organization: c.Organization,
		Name:         c.Name,
		Email:        c.Email,
		Country:      cmp.Or(c.CountryCode, c.Country),
		Province:     c.State,
		City:         c.City,
		Street:       c.Street1,
		PostalCode:   c.PostalCode,
		Phone:        c.Telephone,
	}
}

func mapWhoisXMLHistoryContact(contact whoisXMLHistoryContact) Contact {
	return Contact{
		Organization: contact.Organization,
		Name:         contact.Name,
		Email:        contact.Email,
		Country:      contact.Country,
		Province:     contact.State,
		City:         contact.City,
		Street:       contact.Street,
		PostalCode:   contact.PostalCode,
		Phone:        contact.Telephone,
	}
}

func (r *WhoisXMLClient) historyAPIBase() string {
	return cmp.Or(r.historyBaseURL, whoisXMLHistoryBaseURL)
}

func (r *WhoisXMLClient) lookupDomainJSON(
	ctx context.Context,
	operation string,
	endpoint string,
	domain string,
	params url.Values,
	out any,
) error {
	apiKey := r.resolveAPIKey()
	if apiKey == "" {
		return ErrNoCredential
	}

	params.Set("apiKey", apiKey)
	params.Set("domainName", domain)
	reqURL := endpoint + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("whoisxml: building %s request for %s: %w", operation, domain, err)
	}

	httpClient := cmp.Or(r.httpClient, http.DefaultClient)
	resp, err := httpClient.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("whoisxml: %s request failed for %s: %w", operation, domain, urlErr.Err)
		}
		return fmt.Errorf("whoisxml: %s request failed for %s", operation, domain)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("whoisxml: %s API returned HTTP %d for %s", operation, resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("whoisxml: reading %s response for %s: %w", operation, domain, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("whoisxml: decoding %s response for %s: %w", operation, domain, err)
	}
	return nil
}

type whoisXMLResponse struct {
	WhoisRecord  whoisXMLRecord `json:"WhoisRecord"`
	ErrorMessage *whoisXMLError `json:"ErrorMessage,omitempty"`
}

type whoisXMLError struct {
	ErrorCode string `json:"errorCode"`
	Msg       string `json:"msg"`
}

type whoisXMLRecord struct {
	DomainName    string              `json:"domainName"`
	CreatedDate   string              `json:"createdDate"`
	UpdatedDate   string              `json:"updatedDate"`
	ExpiresDate   string              `json:"expiresDate"`
	RegistrarName string              `json:"registrarName"`
	WhoisServer   string              `json:"whoisServer"`
	Status        string              `json:"status"`
	DataError     string              `json:"dataError"`
	NameServers   whoisXMLNameServers `json:"nameServers"`
	Registrant    whoisXMLContact     `json:"registrant"`
	Admin         whoisXMLContact     `json:"administrativeContact"`
	Tech          whoisXMLContact     `json:"technicalContact"`
	Billing       whoisXMLContact     `json:"billingContact"`
	RegistryData  *whoisXMLRecord     `json:"registryData,omitempty"`
}

type whoisXMLNameServers struct {
	HostNames []string `json:"hostNames"`
}

type whoisXMLContact struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Email        string `json:"email"`
	Street1      string `json:"street1"`
	City         string `json:"city"`
	State        string `json:"state"`
	PostalCode   string `json:"postalCode"`
	Country      string `json:"country"`
	CountryCode  string `json:"countryCode"`
	Telephone    string `json:"telephone"`
}

type whoisXMLHistoryResponse struct {
	Code     int                     `json:"code"`
	Messages string                  `json:"messages"`
	Records  []whoisXMLHistoryRecord `json:"records"`
}

type whoisXMLHistoryRecord struct {
	Audit          whoisXMLHistoryAudit   `json:"audit"`
	DomainName     string                 `json:"domainName"`
	CreatedDate    string                 `json:"createdDateISO8601"`
	CreatedDateRaw string                 `json:"createdDateRaw"`
	UpdatedDate    string                 `json:"updatedDateISO8601"`
	UpdatedDateRaw string                 `json:"updatedDateRaw"`
	ExpiresDate    string                 `json:"expiresDateISO8601"`
	ExpiresDateRaw string                 `json:"expiresDateRaw"`
	RegistrarName  string                 `json:"registrarName"`
	WhoisServer    string                 `json:"whoisServer"`
	NameServers    []string               `json:"nameServers"`
	Status         []string               `json:"status"`
	Registrant     whoisXMLHistoryContact `json:"registrantContact"`
	Admin          whoisXMLHistoryContact `json:"administrativeContact"`
	Tech           whoisXMLHistoryContact `json:"technicalContact"`
	Billing        whoisXMLHistoryContact `json:"billingContact"`
}

type whoisXMLHistoryAudit struct {
	CreatedDate string `json:"createdDate"`
	UpdatedDate string `json:"updatedDate"`
}

type whoisXMLHistoryContact struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Email        string `json:"email"`
	Street       string `json:"street"`
	City         string `json:"city"`
	State        string `json:"state"`
	PostalCode   string `json:"postalCode"`
	Country      string `json:"country"`
	Telephone    string `json:"telephone"`
}
