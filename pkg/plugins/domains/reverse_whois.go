package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

func init() {
	plugins.Register("reverse-whois", func() plugins.Plugin { return &ReverseWhoisPlugin{client: client.New()} })
}

// ReverseWhoisPlugin discovers related domains via ViewDNS reverse WHOIS.
// Emits FindingDomain with Data["pivot_org"]. Verification happens when Guard
// runs the whois capability on each discovered domain.
type ReverseWhoisPlugin struct {
	client  *client.Client
	baseURL string // overridable for tests
}

// NewReverseWhoisPlugin creates a plugin with an injectable HTTP client.
func NewReverseWhoisPlugin(httpClient *client.Client) *ReverseWhoisPlugin {
	return &ReverseWhoisPlugin{client: httpClient}
}

func (p *ReverseWhoisPlugin) apiBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.viewdns.info"
}

func (p *ReverseWhoisPlugin) Name() string        { return "reverse-whois" }
func (p *ReverseWhoisPlugin) Description() string { return "ViewDNS Reverse WHOIS (requires VIEWDNS_API_KEY)" }
func (p *ReverseWhoisPlugin) Category() string    { return "domain" }
func (p *ReverseWhoisPlugin) Phase() int          { return 0 }
func (p *ReverseWhoisPlugin) Mode() string        { return plugins.ModePassive }

func (p *ReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("VIEWDNS_API_KEY") != "" && (input.OrgName != "" || input.Email != "")
}

func (p *ReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("VIEWDNS_API_KEY")

	query := input.OrgName
	if query == "" {
		query = input.Email
	}

	reqURL := fmt.Sprintf(
		"%s/reversewhois/?q=%s&apikey=%s&output=json",
		p.apiBase(),
		url.QueryEscape(query),
		apiKey,
	)

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("reverse-whois: request failed")
	}

	var response struct {
		Response struct {
			Matches []struct {
				Domain string `json:"domain"`
			} `json:"matches"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("reverse-whois: parse response: %w", err)
	}

	seen := make(map[string]struct{})
	var findings []plugins.Finding

	for _, d := range response.Response.Matches {
		if d.Domain == "" {
			continue
		}
		domain := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(d.Domain)), ".")
		if domain == "" || !whois.IsPlausibleDomain(domain) {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}

		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: p.Name(),
			Data:   map[string]any{"pivot_org": query},
		})
	}

	return findings, nil
}
