package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
)

// whoxyWhoisClient is the paid live+history WHOIS transport backing the last
// stage of the WHOIS cascade. It is an internal helper rather than a registered
// plugin: WhoisPlugin owns the call order (MAR-10241) and the credit spend, and
// a second registered plugin would query Whoxy again independently.
type whoxyWhoisClient struct {
	client  *client.Client
	apiKey  string
	baseURL string // overridable for tests
}

func (c *whoxyWhoisClient) apiBase() string {
	if c.baseURL != "" {
		return c.baseURL
	}
	return "https://api.whoxy.com"
}

type whoxyLiveResponse struct {
	Raw          string `json:"raw_whois"`
	Status       int    `json:"status"`
	StatusReason string `json:"status_reason"`
}

type whoxyHistoryResponse struct {
	Status            int    `json:"status"`
	StatusReason      string `json:"status_reason"`
	TotalRecordsFound int    `json:"total_records_found"`
	// Records stays raw: the consumer persists the provider's JSON verbatim, so
	// re-marshalling through a Go shape would drop fields it retains.
	Records json.RawMessage `json:"whois_records"`
}

// record fetches the live WHOIS record for a domain.
func (c *whoxyWhoisClient) record(ctx context.Context, domain string) (whoisRecord, error) {
	var resp whoxyLiveResponse
	if err := c.fetch(ctx, "whois", domain, &resp); err != nil {
		return whoisRecord{}, err
	}
	if resp.Status != 1 {
		return whoisRecord{}, fmt.Errorf("whoxy whois: %s", whoxyStatusReason(resp.StatusReason))
	}
	if strings.TrimSpace(resp.Raw) == "" {
		return whoisRecord{}, fmt.Errorf("whoxy whois: empty record for %q", domain)
	}
	return textWhoisRecord(whoisMethodWhoxy, resp.Raw)
}

// history fetches the provider's historical record set, returning it verbatim.
func (c *whoxyWhoisClient) history(ctx context.Context, domain string) (json.RawMessage, error) {
	var resp whoxyHistoryResponse
	if err := c.fetch(ctx, "history", domain, &resp); err != nil {
		return nil, err
	}
	if resp.Status != 1 {
		return nil, fmt.Errorf("whoxy history: %s", whoxyStatusReason(resp.StatusReason))
	}
	if resp.TotalRecordsFound == 0 {
		return json.RawMessage("[]"), nil
	}
	return resp.Records, nil
}

func (c *whoxyWhoisClient) key() string {
	if c.apiKey != "" {
		return c.apiKey
	}
	return os.Getenv("WHOXY_API_KEY")
}

func (c *whoxyWhoisClient) fetch(ctx context.Context, endpoint, domain string, out any) error {
	reqURL := fmt.Sprintf(
		"%s/?key=%s&%s=%s",
		c.apiBase(),
		url.QueryEscape(c.key()),
		endpoint,
		url.QueryEscape(domain),
	)

	body, err := c.client.Get(ctx, reqURL)
	if err != nil {
		// Replace, never wrap: Go renders a transport failure as
		// `Get "<full url>": <cause>`, and the URL carries the API key in its
		// key= parameter. The consumer surfaces this error to tenant users.
		return fmt.Errorf("whoxy %s: request failed for %q", endpoint, domain)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("whoxy %s: parse response for %q: %w", endpoint, domain, err)
	}
	return nil
}

// whoxyStatusReason keeps an in-band failure legible when the provider omits a
// reason string.
func whoxyStatusReason(reason string) string {
	if r := strings.TrimSpace(reason); r != "" {
		return r
	}
	return "request rejected"
}
