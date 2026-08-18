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

// confBuiltWithSharedAnalytics is the evidence contributed by a discovered
// domain sharing analytics identifiers with the target.
//
// It is one entry regardless of how many identifiers matched, and the
// identifiers are listed in its justification. Scoring per identifier instead
// would mean two matching trackers summed to 120 and capped at 100 — full
// certainty from a shared tracker, which is not what a tracker match proves.
const confBuiltWithSharedAnalytics = 60

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
		// One entry naming every identifier that reached this domain. The nested
		// set deduplicates repeated domain/identifier pairs across lookups, and
		// sorting keeps the justification stable rather than map-order dependent.
		plugins.AddConfidence(&f, confBuiltWithSharedAnalytics, builtWithJustification(slices.Sorted(maps.Keys(analyticsIDs))), nil)

		findings = append(findings, f)
	}
	return findings, nil
}

// builtWithJustification names every analytics identifier that linked a domain
// to the target. ids must already be deduplicated and sorted.
func builtWithJustification(ids []string) string {
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = fmt.Sprintf("%q", id)
	}

	noun := "identifier"
	if len(ids) > 1 {
		noun = "identifiers"
	}
	return fmt.Sprintf("Domain shares analytics %s %s with the target",
		noun, strings.Join(quoted, ", "))
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
