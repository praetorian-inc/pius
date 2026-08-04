package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// confBuiltWithSharedAnalytics is the evidence contributed by one analytics
// identifier shared between a discovered domain and the target.
const confBuiltWithSharedAnalytics = 0.60

func init() {
	plugins.Register("builtwith", func() plugins.Plugin { return &BuiltWithPlugin{client: client.New()} })
}

type BuiltWithPlugin struct {
	client  *client.Client
	baseURL string
}

func (p *BuiltWithPlugin) Name() string { return "builtwith" }
func (p *BuiltWithPlugin) Description() string {
	return "BuiltWith technology correlation — discovers related domains via shared analytics tracking codes (paid, requires BUILTWITH_API_KEY)"
}
func (p *BuiltWithPlugin) Category() string { return "domain" }
func (p *BuiltWithPlugin) Phase() int       { return 3 }
func (p *BuiltWithPlugin) Mode() string     { return plugins.ModePassive }

func (p *BuiltWithPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("BUILTWITH_API_KEY") != "" && input.Meta["analytics_ids"] != ""
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
	apiKey := os.Getenv("BUILTWITH_API_KEY")
	ids := strings.Split(input.Meta["analytics_ids"], ",")

	// Keyed by domain, then by the analytics identifier that linked it to the
	// target. Retaining the identifiers is what lets each one become its own
	// evidence entry — collapsing to a bare domain set would throw away exactly
	// the justification a reviewer needs.
	domainIDs := make(map[string]map[string]struct{})
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
			domain := strings.ToLower(strings.TrimSpace(d))
			if domain == "" {
				continue
			}
			if domainIDs[domain] == nil {
				domainIDs[domain] = make(map[string]struct{})
			}
			domainIDs[domain][id] = struct{}{}
		}
	}

	findings := make([]plugins.Finding, 0, len(domainIDs))
	for domain, analyticsIDs := range domainIDs {
		f := plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  domain,
			Source: p.Name(),
			Data: map[string]any{
				"org": input.OrgName,
			},
		}
		// Each distinct identifier is an independent link between the domain and
		// the target, so each gets its own entry and several of them aggregate
		// toward the cap. The nested set deduplicates repeated domain/identifier
		// pairs across lookups.
		for _, id := range slices.Sorted(maps.Keys(analyticsIDs)) {
			plugins.AddConfidence(&f, confBuiltWithSharedAnalytics,
				fmt.Sprintf("Domain shares analytics identifier %q with the target", id))
		}
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
