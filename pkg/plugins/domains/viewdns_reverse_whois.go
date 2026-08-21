package domains

import (
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
// Findings retain the typed pivot for deferred WHOIS corroboration in Guard.
type ViewDNSReverseWhoisPlugin struct {
	client  *client.Client
	baseURL string // overridable for tests
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
	return os.Getenv("VIEWDNS_API_KEY") != "" &&
		(input.OrgName != "" || input.PersonName != "" || input.Email != "")
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
	parameters := whoisParametersFromInput(input)
	if len(parameters) == 0 {
		return nil, nil
	}

	var rawDomains []WhoisDomain
	for _, parameter := range parameters {
		domains, err := p.query(ctx, apiKey, parameter.Value)
		if err != nil {
			return nil, err
		}
		for _, domain := range domains {
			rawDomains = append(rawDomains, WhoisDomain{
				value:      domain,
				parameters: []WhoisParameter{parameter},
			})
		}
	}

	return reverseWhoisFindings("https://viewdns.info/", rawDomains), nil
}

func (p *ViewDNSReverseWhoisPlugin) query(ctx context.Context, apiKey, value string) ([]string, error) {
	reqURL := fmt.Sprintf(
		"%s/reversewhois/?q=%s&apikey=%s&output=json",
		p.apiBase(), url.QueryEscape(value), apiKey,
	)
	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("viewdns-reverse-whois: request failed")
	}

	var response viewDNSResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("viewdns-reverse-whois: parse response: %w", err)
	}

	domains := make([]string, 0, len(response.Response.Matches))
	for _, match := range response.Response.Matches {
		domains = append(domains, match.Domain)
	}
	return domains, nil
}
