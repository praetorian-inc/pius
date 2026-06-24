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
)

func init() {
	plugins.Register("reverse-whois", func() plugins.Plugin { return &ReverseWhoisPlugin{client: client.New()} })
}

type ReverseWhoisPlugin struct {
	client  *client.Client
	baseURL string // overridable for tests
}

func (p *ReverseWhoisPlugin) apiBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.viewdns.info"
}

func (p *ReverseWhoisPlugin) Name() string        { return "reverse-whois" }
func (p *ReverseWhoisPlugin) Description() string { return "ViewDNS Reverse WHOIS: discovers domain portfolio (requires VIEWDNS_API_KEY)" }
func (p *ReverseWhoisPlugin) Category() string    { return "domain" }
func (p *ReverseWhoisPlugin) Phase() int          { return 0 }
func (p *ReverseWhoisPlugin) Mode() string        { return plugins.ModePassive }

// Only runs if VIEWDNS_API_KEY is set and an org name or registrant email
// seed is provided.
func (p *ReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("VIEWDNS_API_KEY") != "" && (input.OrgName != "" || input.Email != "")
}

func (p *ReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("VIEWDNS_API_KEY")

	// Active seed: org name by default, registrant email when only Email is set.
	query := input.OrgName
	if query == "" {
		query = input.Email
	}

	// ViewDNS Reverse WHOIS API
	reqURL := fmt.Sprintf(
		"%s/reversewhois/?q=%s&apikey=%s&output=json",
		p.apiBase(),
		url.QueryEscape(query),
		apiKey,
	)

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		// Return sanitized error — strip URL which contains the API key.
		return nil, fmt.Errorf("reverse-whois: request failed for %q", query)
	}

	var response struct {
		Query struct {
			Domains []struct {
				DomainName string `json:"domain_name"`
			} `json:"domains"`
		} `json:"query"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("reverse-whois: parse response for %q: %w", query, err)
	}

	findings := make([]plugins.Finding, 0, len(response.Query.Domains))
	for _, d := range response.Query.Domains {
		if d.DomainName == "" {
			continue
		}
		domain := strings.ToLower(d.DomainName)
		domain = strings.TrimSpace(domain)
		domain = strings.TrimSuffix(domain, ".")
		f := plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: p.Name(),
			Data: map[string]any{
				"org": query,
			},
		}
		// WHOIS registrant matching is reliable but not perfect: the org name
		// query may match similarly-named registrants. Score at 0.75 — above
		// the review threshold so output is clean, but confidence is available
		// in Data for agent/downstream use.
		plugins.SetConfidence(&f, 0.75)
		findings = append(findings, f)
	}
	return findings, nil
}
