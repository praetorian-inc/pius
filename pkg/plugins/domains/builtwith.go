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
	plugins.Register("builtwith", func() plugins.Plugin { return &BuiltWithPlugin{client: client.New()} })
}

type BuiltWithPlugin struct {
	client  *client.Client
	baseURL string
	apiKey  string // set by NewBuiltWithPlugin; falls back to BUILTWITH_API_KEY
}

// NewBuiltWithPlugin builds the plugin around a caller-supplied client and API
// key, so embedders can route its egress through their own transport and resolve
// the key from their own secret store instead of the environment.
func NewBuiltWithPlugin(c *client.Client, apiKey string) *BuiltWithPlugin {
	return &BuiltWithPlugin{client: c, apiKey: apiKey}
}

// key prefers an injected key so embedders never depend on process environment.
func (p *BuiltWithPlugin) key() string {
	if p.apiKey != "" {
		return p.apiKey
	}
	return os.Getenv("BUILTWITH_API_KEY")
}

func (p *BuiltWithPlugin) Name() string { return "builtwith" }
func (p *BuiltWithPlugin) Description() string {
	return "BuiltWith technology correlation — discovers related domains via shared analytics tracking codes (paid, requires BUILTWITH_API_KEY)"
}
func (p *BuiltWithPlugin) Category() string { return "domain" }
func (p *BuiltWithPlugin) Phase() int       { return 3 }
func (p *BuiltWithPlugin) Mode() string     { return plugins.ModePassive }

func (p *BuiltWithPlugin) Accepts(input plugins.Input) bool {
	return p.key() != "" && input.Meta["analytics_ids"] != ""
}

type builtWithEntry struct {
	Value   string `json:"Value"`
	Matches []struct {
		Domain string `json:"Domain"`
	} `json:"Matches"`
}

func (p *BuiltWithPlugin) apiBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.builtwith.com"
}

func (p *BuiltWithPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := p.key()
	ids := strings.Split(input.Meta["analytics_ids"], ",")

	domains := make(map[string]struct{})
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		matches, err := p.lookup(ctx, apiKey, id)
		if err != nil {
			continue
		}
		for _, d := range matches {
			domains[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
		}
	}

	findings := make([]plugins.Finding, 0, len(domains))
	for domain := range domains {
		if domain == "" {
			continue
		}
		f := plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: p.Name(),
			Data: map[string]any{
				"org": input.OrgName,
			},
		}
		plugins.SetConfidence(&f, 0.6)
		findings = append(findings, f)
	}
	return findings, nil
}

func (p *BuiltWithPlugin) lookup(ctx context.Context, apiKey, analyticsID string) ([]string, error) {
	reqURL := fmt.Sprintf(
		"%s/tag1/api.json?KEY=%s&LOOKUP=%s",
		p.apiBase(),
		url.QueryEscape(apiKey),
		url.QueryEscape(analyticsID),
	)

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("builtwith: request failed for %q", analyticsID)
	}

	var resp []builtWithEntry
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("builtwith: parse response for %q: %w", analyticsID, err)
	}

	var domains []string
	for _, entry := range resp {
		for _, match := range entry.Matches {
			if match.Domain != "" {
				domains = append(domains, match.Domain)
			}
		}
	}
	return domains, nil
}
