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

// whoisXMLBaseURL is the WhoisXML API v1 Live WHOIS endpoint. It is a var so
// tests can point it at an httptest.Server.
var whoisXMLBaseURL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

// WhoisXMLResolver looks up live WHOIS through the WhoisXML API.
//
// Of the three providers this is the most expensive per query and by far the
// highest throughput, so it earns its place at the end of the default route:
// reached only when the cheaper providers had no answer.
type WhoisXMLResolver struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string

	// hardRefresh forces WhoisXML to re-query the registry rather than serve
	// its cache. It costs 5 credits against 1 for a normal lookup, so it is off
	// unless explicitly enabled and must never become implicit.
	hardRefresh bool
}

// NewWhoisXMLResolver returns a WhoisXML resolver with hard refresh disabled.
// An empty apiKey falls back to WHOISXML_API_KEY.
func NewWhoisXMLResolver(httpClient *http.Client, apiKey string) *WhoisXMLResolver {
	return &WhoisXMLResolver{httpClient: httpClient, apiKey: apiKey}
}

// WithHardRefresh enables WhoisXML's hard refresh. It is a 5x cost multiplier
// (5 credits per query against 1), so callers must opt in deliberately.
func (r *WhoisXMLResolver) WithHardRefresh(enabled bool) *WhoisXMLResolver {
	r.hardRefresh = enabled
	return r
}

func (r *WhoisXMLResolver) Name() string { return ProviderWhoisXML }

func (r *WhoisXMLResolver) resolveAPIKey() string {
	return cmp.Or(r.apiKey, os.Getenv("WHOISXML_API_KEY"))
}

func (r *WhoisXMLResolver) hasCredential() bool { return r.resolveAPIKey() != "" }

func (r *WhoisXMLResolver) apiBase() string { return cmp.Or(r.baseURL, whoisXMLBaseURL) }

type whoisXMLResponse struct {
	WhoisRecord  whoisXMLRecord `json:"WhoisRecord"`
	ErrorMessage *whoisXMLError `json:"ErrorMessage,omitempty"`
}

// whoisXMLError is WhoisXML's error envelope. It arrives with HTTP 200, so the
// status code alone cannot be trusted to mean success — AUTHENTICATE_06
// (exhausted or unauthorized account) is reported this way.
type whoisXMLError struct {
	ErrorCode string `json:"errorCode"`
	Msg       string `json:"msg"`
}

// whoisXMLRecord is one WHOIS record. RegistryData carries the registry's own
// view and is used only to fill fields the registrar-level record left empty —
// reserved and thin-registry domains populate one but not the other.
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

	RegistryData *whoisXMLRecord `json:"registryData,omitempty"`
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

// dataErrorMissingWhois is WhoisXML's marker for "no WHOIS data available".
const dataErrorMissingWhois = "MISSING_WHOIS_DATA"

func (r *WhoisXMLResolver) Lookup(ctx context.Context, domain string) (Result, error) {
	apiKey := r.resolveAPIKey()
	if apiKey == "" {
		return Result{}, ErrNoCredential
	}

	params := url.Values{}
	params.Set("apiKey", apiKey)
	params.Set("domainName", domain)
	params.Set("outputFormat", "JSON")
	if r.hardRefresh {
		params.Set("_hardRefresh", "1")
	}
	reqURL := r.apiBase() + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("whoisxml: building request for %s: %w", domain, err)
	}

	httpClient := cmp.Or(r.httpClient, http.DefaultClient)
	resp, err := httpClient.Do(req)
	if err != nil {
		// Unwrap *url.Error first: WhoisXML authenticates with a query
		// parameter, so a transport failure would otherwise be rendered as
		// `Get "<full url>": <cause>` with the API key embedded.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return Result{}, fmt.Errorf("whoisxml: request failed for %s: %w", domain, urlErr.Err)
		}
		return Result{}, fmt.Errorf("whoisxml: request failed for %s", domain)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("whoisxml: API returned HTTP %d for %s", resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return Result{}, fmt.Errorf("whoisxml: reading response for %s: %w", domain, err)
	}

	var wx whoisXMLResponse
	if err := json.Unmarshal(body, &wx); err != nil {
		return Result{}, fmt.Errorf("whoisxml: decoding response for %s: %w", domain, err)
	}

	// Checked on the decoded envelope rather than by scanning the payload for a
	// marker string: a WHOIS record is attacker-influenced text, and matching
	// loose substrings against a successful body is how a valid record gets
	// misread as a failure.
	if e := wx.ErrorMessage; e != nil && e.ErrorCode != "" {
		return Result{}, fmt.Errorf("whoisxml: %s for %s: %s", e.ErrorCode, domain, e.Msg)
	}

	rec := wx.WhoisRecord
	if rec.RegistryData != nil {
		rec.fillFrom(*rec.RegistryData)
	}

	if rec.DataError == dataErrorMissingWhois || rec.DomainName == "" {
		// Answered, but holds nothing usable. Deliberately not reported as
		// Unregistered: absent data is weaker evidence than a registry saying
		// the domain does not exist, and a wrong Unregistered would mark a live
		// domain dead.
		return Result{}, nil
	}

	return mapWhoisXMLToResult(domain, rec), nil
}

// fillFrom copies fields from the registry-level record into any the
// registrar-level record left empty.
func (rec *whoisXMLRecord) fillFrom(other whoisXMLRecord) {
	rec.DomainName = cmp.Or(rec.DomainName, other.DomainName)
	rec.CreatedDate = cmp.Or(rec.CreatedDate, other.CreatedDate)
	rec.UpdatedDate = cmp.Or(rec.UpdatedDate, other.UpdatedDate)
	rec.ExpiresDate = cmp.Or(rec.ExpiresDate, other.ExpiresDate)
	rec.RegistrarName = cmp.Or(rec.RegistrarName, other.RegistrarName)
	rec.WhoisServer = cmp.Or(rec.WhoisServer, other.WhoisServer)
	rec.Status = cmp.Or(rec.Status, other.Status)
	if len(rec.NameServers.HostNames) == 0 {
		rec.NameServers = other.NameServers
	}
}

func mapWhoisXMLToResult(domain string, rec whoisXMLRecord) Result {
	return Result{
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
