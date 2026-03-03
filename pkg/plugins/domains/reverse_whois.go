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
	client *client.Client
}

func (p *ReverseWhoisPlugin) Name() string        { return "reverse-whois" }
func (p *ReverseWhoisPlugin) Description() string { return "ViewDNS Reverse WHOIS: discovers domain portfolio (requires VIEWDNS_API_KEY)" }
func (p *ReverseWhoisPlugin) Category() string    { return "domain" }
func (p *ReverseWhoisPlugin) Phase() int          { return 0 }

// Only runs if VIEWDNS_API_KEY is set
func (p *ReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("VIEWDNS_API_KEY") != "" && input.OrgName != ""
}

func (p *ReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("VIEWDNS_API_KEY")

	// ViewDNS Reverse WHOIS API
	reqURL := fmt.Sprintf(
		"https://api.viewdns.info/reversewhois/?q=%s&apikey=%s&output=json",
		url.QueryEscape(input.OrgName),
		apiKey,
	)

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		// Return sanitized error — strip URL which contains the API key.
		return nil, fmt.Errorf("ViewDNS reverse WHOIS request failed for %q", input.OrgName)
	}

	var response struct {
		Query struct {
			Domains []struct {
				DomainName string `json:"domain_name"`
			} `json:"domains"`
		} `json:"query"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("parse ViewDNS response for %q: %w", input.OrgName, err)
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
				"org": input.OrgName,
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
