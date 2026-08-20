package domains

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("viewdns-reverse-whois", func() plugins.Plugin { return &ViewDNSReverseWhoisPlugin{client: client.New()} })
}

// ViewDNSReverseWhoisPlugin discovers related domains via ViewDNS reverse WHOIS.
// It emits scored FindingDomain results with Data["pivot_org"], corroborating
// each candidate against a fresh WHOIS response.
type ViewDNSReverseWhoisPlugin struct {
	client      *client.Client
	baseURL     string // overridable for tests
	lookupWhois domainWhoisLookup
}

// NewViewDNSReverseWhoisPlugin creates a plugin with an injectable HTTP client.
func NewViewDNSReverseWhoisPlugin(httpClient *client.Client) *ViewDNSReverseWhoisPlugin {
	return &ViewDNSReverseWhoisPlugin{client: httpClient}
}

func (p *ViewDNSReverseWhoisPlugin) apiBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.viewdns.info"
}

func (p *ViewDNSReverseWhoisPlugin) Name() string { return "viewdns-reverse-whois" }
func (p *ViewDNSReverseWhoisPlugin) Description() string {
	return "ViewDNS Reverse WHOIS (requires VIEWDNS_API_KEY)"
}
func (p *ViewDNSReverseWhoisPlugin) Category() string { return "domain" }
func (p *ViewDNSReverseWhoisPlugin) Phase() int       { return 0 }
func (p *ViewDNSReverseWhoisPlugin) Mode() string     { return plugins.ModePassive }

func (p *ViewDNSReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("VIEWDNS_API_KEY") != "" && (input.OrgName != "" || input.PersonName != "" || input.Email != "")
}

type viewDNSResponse struct {
	Response struct {
		Matches []struct {
			Domain string `json:"domain"`
		} `json:"matches"`
	} `json:"response"`
}

func (p *ViewDNSReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("VIEWDNS_API_KEY")

	query := cmp.Or(input.OrgName, input.PersonName, input.Email)

	reqURL := fmt.Sprintf(
		"%s/reversewhois/?q=%s&apikey=%s&output=json",
		p.apiBase(), url.QueryEscape(query), apiKey,
	)

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("viewdns-reverse-whois: request failed")
	}

	var response viewDNSResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("viewdns-reverse-whois: parse response: %w", err)
	}

	var rawDomains []string
	for _, d := range response.Response.Matches {
		rawDomains = append(rawDomains, d.Domain)
	}

	findings := domainFindings(p.Name(), query, rawDomains)
	addReverseWhoisConfidences(ctx, input, findings, p.lookupWhois)
	return findings, nil
}
