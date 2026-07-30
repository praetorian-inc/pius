package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	whoisparser "github.com/likexian/whois-parser"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("whoisfreaks", func() plugins.Plugin { return &WhoisFreaksPlugin{client: client.New()} })
}

// WhoisFreaksPlugin resolves a domain's WHOIS record through the WhoisFreaks
// API and emits the registrant organization, contacts, and emails as preseeds.
type WhoisFreaksPlugin struct {
	client  *client.Client
	baseURL string // overridable for tests
}

func (p *WhoisFreaksPlugin) Name() string { return "whoisfreaks" }
func (p *WhoisFreaksPlugin) Description() string {
	return "Domain WHOIS via WhoisFreaks API — extracts registrant organization, contacts, and emails (paid, requires WHOISFREAKS_API_KEY)"
}
func (p *WhoisFreaksPlugin) Category() string { return "domain" }
func (p *WhoisFreaksPlugin) Phase() int       { return 0 }
func (p *WhoisFreaksPlugin) Mode() string     { return plugins.ModePassive }

func (p *WhoisFreaksPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("WHOISFREAKS_API_KEY") != "" && input.Domain != ""
}

func (p *WhoisFreaksPlugin) apiBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.whoisfreaks.com/v1.0"
}

type whoisFreaksLiveResponse struct {
	DomainRegistered string `json:"domain_registered"`
	RawDomain        string `json:"whois_raw_domain"`
	RegistryData     struct {
		// Upstream misspells "registry".
		RawRegistry string `json:"whois_raw_registery"`
	} `json:"registry_data"`
	// RegistrantContact is the vendor's own parsed contact block. It is the ONLY
	// contact source for ccTLDs — see structuredWhoisInfo.
	RegistrantContact struct {
		Name         string `json:"name"`
		Company      string `json:"company"`
		EmailAddress string `json:"email_address"`
	} `json:"registrant_contact"`
}

// hasStructuredContact reports whether the vendor returned any parsed contact
// field, masked or not. Distinguishes "no record came back" from "a record came
// back but every field is a redaction placeholder".
func (r whoisFreaksLiveResponse) hasStructuredContact() bool {
	c := r.RegistrantContact
	return c.Company != "" || c.Name != "" || c.EmailAddress != ""
}

// structuredWhoisInfo adapts the vendor's parsed contact block into the shape
// whoisparser produces, so the structured path and the raw path both flow
// through extractPreseeds and get identical filtering and typing.
//
// This exists because WhoisFreaks omits raw WHOIS text entirely for ccTLDs.
// Verified 2026-07-29: praetorian.com and bbc.com (gTLD) return
// whois_raw_domain plus registry_data; bbc.co.uk and siemens.de (ccTLD) return
// NEITHER, while still populating registrant_contact. A raw-only reader
// therefore emitted nothing for every ccTLD asset — siemens.de was discarding
// "Siemens AG" and domainmanagement.cc@siemens.com.
//
// Redaction placeholders are dropped HERE rather than in extractPreseeds:
// isMaskedOrg's vocabulary already recognises them, and Nominet's
// "redacted@nominet.uk" would otherwise become a whois+email pivot matching
// every redacted .uk domain. extractPreseeds is shared with the port-43 plugin
// and deliberately left alone — the raw path keeps its existing behaviour.
func (r whoisFreaksLiveResponse) structuredWhoisInfo() whoisparser.WhoisInfo {
	contact := whoisparser.Contact{
		Organization: blankIfMasked(r.RegistrantContact.Company),
		Name:         blankIfMasked(r.RegistrantContact.Name),
		Email:        blankIfMasked(r.RegistrantContact.EmailAddress),
	}
	return whoisparser.WhoisInfo{Registrant: &contact}
}

func blankIfMasked(v string) string {
	if isMaskedOrg(v) {
		return ""
	}
	return v
}

func (p *WhoisFreaksPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	domain := rootDomain(input.Domain)
	if domain == "" {
		return nil, fmt.Errorf("whoisfreaks: unable to determine root domain from %q", input.Domain)
	}

	body, err := p.live(ctx, domain)
	if err != nil {
		return nil, err
	}

	// An in-band definitive negative: the domain is unregistered, so there is
	// nothing to extract and no error to report.
	if strings.EqualFold(body.DomainRegistered, "no") {
		return nil, nil
	}

	// Prefer the registrar-level record: it is the one that carries contacts.
	raw := body.RawDomain
	if strings.TrimSpace(raw) == "" {
		raw = body.RegistryData.RawRegistry
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ccTLD responses carry no raw text at all, only the vendor's parsed contact
	// block. Fall back to it rather than discarding the record.
	if strings.TrimSpace(raw) == "" {
		if !body.hasStructuredContact() {
			return nil, fmt.Errorf("whoisfreaks: no WHOIS record returned for %q", domain)
		}
		return extractPreseeds(body.structuredWhoisInfo(), p.Name()), nil
	}

	parsed, perr := parseWhoisRecordSafely(raw)
	if perr != nil {
		slog.Warn("whoisfreaks: parse failed, skipping preseed extraction", "domain", domain, "error", perr)
		return nil, nil
	}

	return extractPreseeds(parsed, p.Name()), nil
}

// parseWhoisRecordSafely wraps the parser in a recover scoped to that one call.
func parseWhoisRecordSafely(raw string) (info whoisparser.WhoisInfo, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("recovered panic parsing WHOIS record: %v", rec)
		}
	}()
	return whoisParseFn(raw)
}

func (p *WhoisFreaksPlugin) live(ctx context.Context, domain string) (whoisFreaksLiveResponse, error) {
	params := url.Values{
		"apiKey":     {os.Getenv("WHOISFREAKS_API_KEY")},
		"whois":      {"live"},
		"domainName": {domain},
	}
	reqURL := fmt.Sprintf("%s/whois?%s", p.apiBase(), params.Encode())

	raw, err := p.client.Get(ctx, reqURL)
	if err != nil {
		// Do not propagate: the URL contains the API key, and the usage endpoint
		// echoes it in the response body.
		return whoisFreaksLiveResponse{}, fmt.Errorf("whoisfreaks: request failed for %q", domain)
	}

	var body whoisFreaksLiveResponse
	if err := json.Unmarshal(raw, &body); err != nil {
		return whoisFreaksLiveResponse{}, fmt.Errorf("whoisfreaks: parse response for %q: %w", domain, err)
	}
	return body, nil
}
