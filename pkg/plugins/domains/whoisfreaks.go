package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"

	whoisparser "github.com/likexian/whois-parser"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("whoisfreaks", func() plugins.Plugin {
		return &WhoisFreaksPlugin{whoisFreaksClient: &whoisFreaksClient{client: client.New()}}
	})
}

// WhoisFreaksPlugin resolves a domain's WHOIS record through the WhoisFreaks
// API and emits the registrant organization, contacts, and emails as preseeds.
type WhoisFreaksPlugin struct {
	*whoisFreaksClient
}

func (p *WhoisFreaksPlugin) Name() string { return "whoisfreaks" }
func (p *WhoisFreaksPlugin) Description() string {
	return "Domain WHOIS via WhoisFreaks API — extracts registrant organization, contacts, and emails (paid, requires WHOISFREAKS_API_KEY)"
}
func (p *WhoisFreaksPlugin) Category() string { return "domain" }
func (p *WhoisFreaksPlugin) Phase() int       { return 0 }
func (p *WhoisFreaksPlugin) Mode() string     { return plugins.ModePassive }

func (p *WhoisFreaksPlugin) Accepts(input plugins.Input) bool {
	return p.key() != "" && input.Domain != ""
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
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("whoisfreaks: no raw WHOIS record returned for %q", domain)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	parsed, perr := parseWhoisRecordSafely(raw)
	if perr != nil {
		slog.Warn("whoisfreaks: parse failed, skipping preseed extraction", "domain", domain, "error", perr)
		return nil, nil
	}

	return extractPreseeds(parsed, p.Name()), nil
}

func parseWhoisRecordSafely(raw string) (info whoisparser.WhoisInfo, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("recovered panic parsing WHOIS record: %v", rec)
		}
	}()
	return whoisParseFn(raw)
}

const (
	whoisFreaksHost = "https://api.whoisfreaks.com"

	// The two legs are pinned to different API versions deliberately: WHOIS
	// history is only served on v2.0, and the live leg's response shape is the
	// v1.0 one this plugin already parses.
	whoisFreaksLiveVersion    = "v1.0"
	whoisFreaksHistoryVersion = "v2.0"

	// maxWhoisFreaksHistoryPages bounds the page walk: total_pages is provider
	// input and a bad value must not spin the fetch.
	maxWhoisFreaksHistoryPages = 10
)

type whoisFreaksClient struct {
	client  *client.Client
	apiKey  string
	baseURL string // overridable for tests
}

type whoisFreaksLiveResponse struct {
	DomainRegistered string `json:"domain_registered"`
	RawDomain        string `json:"whois_raw_domain"`
	RegistryData     struct {
		// Upstream misspells "registry".
		RawRegistry string `json:"whois_raw_registery"`
	} `json:"registry_data"`
}

type whoisFreaksHistoryResponse struct {
	Status       *bool `json:"status"`
	TotalRecords int   `json:"total_records"`
	TotalPages   int   `json:"total_pages"`
	// Records stays raw: the consumer persists the provider's JSON verbatim, so
	// re-marshalling through a Go shape would drop fields it retains.
	Records json.RawMessage `json:"whois_domains_historical"`
}

func (c *whoisFreaksClient) live(ctx context.Context, domain string) (whoisFreaksLiveResponse, error) {
	var resp whoisFreaksLiveResponse
	endpoint := c.apiBase(whoisFreaksLiveVersion) + "/whois"
	if err := c.fetch(ctx, "whois", endpoint, domain, url.Values{"whois": {"live"}}, &resp); err != nil {
		return whoisFreaksLiveResponse{}, err
	}
	return resp, nil
}

// Zero records is a result, not a failure.
func (c *whoisFreaksClient) history(ctx context.Context, domain string) (json.RawMessage, error) {
	endpoint := c.apiBase(whoisFreaksHistoryVersion) + "/whois/history"

	var (
		records    []json.RawMessage
		totalPages = 1
	)
	for page := 1; page <= totalPages && page <= maxWhoisFreaksHistoryPages; page++ {
		var resp whoisFreaksHistoryResponse
		params := url.Values{"page": {strconv.Itoa(page)}}
		if err := c.fetch(ctx, "history", endpoint, domain, params, &resp); err != nil {
			return nil, err
		}
		if resp.Status != nil && !*resp.Status {
			return nil, fmt.Errorf("whoisfreaks history: request rejected for %q", domain)
		}
		if len(resp.Records) > 0 {
			var pageRecords []json.RawMessage
			if err := json.Unmarshal(resp.Records, &pageRecords); err != nil {
				return nil, fmt.Errorf("whoisfreaks history: parse records for %q: %w", domain, err)
			}
			records = append(records, pageRecords...)
		}
		if resp.TotalPages > totalPages {
			totalPages = resp.TotalPages
		}
	}

	if totalPages > maxWhoisFreaksHistoryPages {
		slog.Warn("whoisfreaks history: page cap reached, record set truncated",
			"domain", domain, "pages_fetched", maxWhoisFreaksHistoryPages, "total_pages", totalPages)
	}

	if len(records) == 0 {
		return json.RawMessage("[]"), nil
	}
	joined, err := json.Marshal(records)
	if err != nil {
		return nil, fmt.Errorf("whoisfreaks history: join records for %q: %w", domain, err)
	}
	return joined, nil
}

func (c *whoisFreaksClient) key() string {
	if c.apiKey != "" {
		return c.apiKey
	}
	return os.Getenv("WHOISFREAKS_API_KEY")
}

func (c *whoisFreaksClient) apiBase(version string) string {
	host := whoisFreaksHost
	if c.baseURL != "" {
		host = c.baseURL
	}
	return host + "/" + version
}

func (c *whoisFreaksClient) fetch(ctx context.Context, leg, endpoint, domain string, params url.Values, out any) error {
	params.Set("apiKey", c.key())
	params.Set("domainName", domain)

	body, err := c.client.Get(ctx, endpoint+"?"+params.Encode())
	if err != nil {
		// Replace, never wrap: Go renders a transport failure as
		// `Get "<full url>": <cause>`, and the URL carries the API key in its
		// apiKey parameter, which pkg/client's sanitizeURL does not redact.
		return fmt.Errorf("whoisfreaks %s: request failed for %q", leg, domain)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("whoisfreaks %s: parse response for %q: %w", leg, domain, err)
	}
	return nil
}
