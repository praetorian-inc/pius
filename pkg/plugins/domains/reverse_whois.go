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
	client   *client.Client
	baseURL  string             // overridable for tests
	resolver registrantResolver // overridable for tests; defaults to rdapWhoisResolver
}

func (p *ReverseWhoisPlugin) apiBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.viewdns.info"
}

func (p *ReverseWhoisPlugin) Name() string { return "reverse-whois" }
func (p *ReverseWhoisPlugin) Description() string {
	return "ViewDNS Reverse WHOIS: discovers domain portfolio (requires VIEWDNS_API_KEY)"
}
func (p *ReverseWhoisPlugin) Category() string { return "domain" }
func (p *ReverseWhoisPlugin) Phase() int       { return 0 }
func (p *ReverseWhoisPlugin) Mode() string     { return plugins.ModePassive }

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

	// Build an ordered, deduped candidate list (the resolve cap is applied
	// downstream in verifyCandidates). A ViewDNS match is only
	// a lead (broad substring/token search over the full WHOIS record), so each
	// candidate is corroborated against its own registrant in verifyCandidates
	// rather than emitted at a flat score here (ENG-5123).
	cands := make([]candidate, 0, len(response.Response.Matches))
	seen := make(map[string]struct{})
	for _, d := range response.Response.Matches {
		if d.Domain == "" {
			continue
		}
		domain := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(d.Domain)), ".")
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		cands = append(cands, candidate{
			domain: domain,
			finding: plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  domain,
				Source: p.Name(),
				Data: map[string]any{
					"org": query,
				},
			},
		})
	}

	// Resolve into a local rather than mutating p.resolver: writing shared plugin
	// state inside Run() would be a data race if an instance were ever reused or
	// run concurrently (Gemini review, ENG-5123).
	resolver := p.resolver
	if resolver == nil {
		resolver = &rdapWhoisResolver{}
	}
	// input.OrgName drives corroboration; email-mode (OrgName == "") short-
	// circuits inside verifyCandidates. Data["org"] provenance stays the query.
	return verifyCandidates(ctx, resolver, input.OrgName, cands)
}
