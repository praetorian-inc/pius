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
	plugins.Register("passive-dns", func() plugins.Plugin { return &PassiveDNSPlugin{client: client.New()} })
}

type PassiveDNSPlugin struct {
	client *client.Client
}

func (p *PassiveDNSPlugin) Name() string        { return "passive-dns" }
func (p *PassiveDNSPlugin) Description() string { return "SecurityTrails Passive DNS: discovers historical DNS data (requires SECURITYTRAILS_API_KEY)" }
func (p *PassiveDNSPlugin) Category() string    { return "domain" }
func (p *PassiveDNSPlugin) Phase() int          { return 0 }

// Only runs if SECURITYTRAILS_API_KEY is set and we have a domain to search
func (p *PassiveDNSPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("SECURITYTRAILS_API_KEY") != "" && input.Domain != ""
}

func (p *PassiveDNSPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("SECURITYTRAILS_API_KEY")

	// SecurityTrails domain subdomains API
	reqURL := fmt.Sprintf(
		"https://api.securitytrails.com/v1/domain/%s/subdomains?include_inactive=true",
		url.PathEscape(input.Domain),
	)

	body, err := p.client.GetWithHeaders(ctx, reqURL, map[string]string{
		"APIKEY":       apiKey,
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil, nil
	}

	var response struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, nil
	}

	findings := make([]plugins.Finding, 0, len(response.Subdomains))
	for _, sub := range response.Subdomains {
		if sub == "" {
			continue
		}
		domain := sub + "." + input.Domain
		domain = strings.ToLower(domain)
		domain = strings.TrimSpace(domain)
		domain = strings.TrimSuffix(domain, ".")
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: p.Name(),
			Data: map[string]any{
				"org":         input.OrgName,
				"base_domain": input.Domain,
			},
		})
	}
	return findings, nil
}
