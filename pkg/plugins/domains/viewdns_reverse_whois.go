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
	_, ok := viewDNSReverseWhoisParameter(input)
	return os.Getenv("VIEWDNS_API_KEY") != "" && ok
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

	parameter, ok := viewDNSReverseWhoisParameter(input)
	if !ok {
		return nil, nil
	}

	reqURL := fmt.Sprintf(
		"%s/reversewhois/?q=%s&apikey=%s&output=json",
		p.apiBase(), url.QueryEscape(parameter.Value), apiKey,
	)

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("viewdns-reverse-whois: request failed")
	}

	var response viewDNSResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("viewdns-reverse-whois: parse response: %w", err)
	}

	rawDomains := make([]reverseWhoisDomain, 0, len(response.Response.Matches))
	for _, match := range response.Response.Matches {
		rawDomains = append(rawDomains, reverseWhoisDomain{
			value:      match.Domain,
			parameters: []ReverseWhoisParameter{parameter},
		})
	}

	return domainFindings(p.Name(), rawDomains), nil
}

func viewDNSReverseWhoisParameter(input plugins.Input) (ReverseWhoisParameter, bool) {
	parameters := reverseWhoisParameters(input)
	if len(parameters) == 0 {
		return ReverseWhoisParameter{}, false
	}

	var company, name, email string
	for _, parameter := range parameters {
		switch parameter.Field {
		case "company":
			company = parameter.Value
		case "name":
			name = parameter.Value
		case "email":
			email = parameter.Value
		}
	}
	selectedValue := cmp.Or(company, name, email)
	for _, parameter := range parameters {
		if parameter.Value == selectedValue {
			return parameter, true
		}
	}
	return ReverseWhoisParameter{}, false
}
