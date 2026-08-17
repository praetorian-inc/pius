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

const confPassiveDNSHistoricalObservation = 60

func init() {
	plugins.Register("passive-dns", func() plugins.Plugin { return &PassiveDNSPlugin{client: client.New()} })
}

type PassiveDNSPlugin struct {
	client *client.Client
	apiKey string // set by NewPassiveDNSPlugin; falls back to SECURITYTRAILS_API_KEY
}

// NewPassiveDNSPlugin builds the plugin around a caller-supplied client and API
// key, so embedders can route its egress through their own transport and resolve
// the key from their own secret store instead of the environment.
func NewPassiveDNSPlugin(c *client.Client, apiKey string) *PassiveDNSPlugin {
	return &PassiveDNSPlugin{client: c, apiKey: apiKey}
}

// key prefers an injected key so embedders never depend on process environment.
func (p *PassiveDNSPlugin) key() string {
	if p.apiKey != "" {
		return p.apiKey
	}
	return os.Getenv("SECURITYTRAILS_API_KEY")
}

func (p *PassiveDNSPlugin) Name() string { return "passive-dns" }
func (p *PassiveDNSPlugin) Description() string {
	return "SecurityTrails Passive DNS: discovers historical DNS data (requires SECURITYTRAILS_API_KEY)"
}
func (p *PassiveDNSPlugin) Category() string { return "domain" }
func (p *PassiveDNSPlugin) Phase() int       { return 0 }
func (p *PassiveDNSPlugin) Mode() string     { return plugins.ModePassive }

// Only runs if SECURITYTRAILS_API_KEY is set and we have a domain to search
func (p *PassiveDNSPlugin) Accepts(input plugins.Input) bool {
	return p.key() != "" && isDomainName(input.Domain)
}

func (p *PassiveDNSPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := p.key()

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
		return nil, fmt.Errorf("passive-dns: SecurityTrails request: %w", err)
	}

	var response struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("passive-dns: parse response: %w", err)
	}

	seen := make(map[string]bool)
	findings := make([]plugins.Finding, 0, len(response.Subdomains))
	for _, sub := range response.Subdomains {
		if sub == "" {
			continue
		}
		domain := sub + "." + input.Domain
		domain = strings.ToLower(domain)
		domain = strings.TrimSpace(domain)
		domain = strings.TrimSuffix(domain, ".")
		if seen[domain] {
			continue
		}
		seen[domain] = true
		finding := plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: p.Name(),
			Data: map[string]any{
				"org":         input.OrgName,
				"base_domain": input.Domain,
			},
		}
		plugins.AddConfidence(&finding, confPassiveDNSHistoricalObservation,
			fmt.Sprintf("SecurityTrails historical/passive DNS data records subdomain %q for base domain %q",
				domain, input.Domain))
		findings = append(findings, finding)
	}
	return findings, nil
}
