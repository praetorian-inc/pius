package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("crt-sh", func() plugins.Plugin { return &CRTShPlugin{client: client.New()} })
}

type CRTShPlugin struct {
	client  *client.Client
	baseURL string // override for testing
}

func (p *CRTShPlugin) crtshBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://crt.sh"
}

func (p *CRTShPlugin) Name() string        { return "crt-sh" }
func (p *CRTShPlugin) Description() string { return "crt.sh: discovers domains via Certificate Transparency logs" }
func (p *CRTShPlugin) Category() string    { return "domain" }
func (p *CRTShPlugin) Phase() int          { return 0 }
func (p *CRTShPlugin) Mode() string        { return plugins.ModePassive }

// Accepts if we have a domain or org name to search
func (p *CRTShPlugin) Accepts(input plugins.Input) bool {
	return input.Domain != "" || input.OrgName != ""
}

func (p *CRTShPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	// Search by domain if available, otherwise by org name
	query := input.Domain
	if query == "" {
		query = input.OrgName
	}

	urlStr := fmt.Sprintf("%s/?q=%s&output=json", p.crtshBase(), url.QueryEscape(query))
	body, err := p.client.Get(ctx, urlStr)
	if err != nil {
		return nil, nil // Rate limit or network error — not critical
	}

	// Parse crt.sh response
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, nil
	}

	// Deduplicate domains
	seen := make(map[string]bool)
	var findings []plugins.Finding
	for _, entry := range entries {
		// name_value can contain multiple domains separated by newlines
		for _, domain := range strings.Split(entry.NameValue, "\n") {
			domain = strings.TrimSpace(domain)
			domain = strings.ToLower(domain)
			domain = strings.TrimSuffix(domain, ".")
			// Skip wildcards and empty
			if domain == "" || strings.HasPrefix(domain, "*") {
				continue
			}
			if !seen[domain] {
				seen[domain] = true
				findings = append(findings, plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  domain,
					Source: p.Name(),
					Data: map[string]any{
						"org":   input.OrgName,
						"query": query,
					},
				})
			}
		}
	}
	return findings, nil
}
