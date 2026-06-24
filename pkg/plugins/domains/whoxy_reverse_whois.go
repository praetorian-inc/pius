package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const maxWhoxyPages = 100

func init() {
	plugins.Register("whoxy-reverse-whois", func() plugins.Plugin { return &WhoxyReverseWhoisPlugin{client: client.New()} })
}

type WhoxyReverseWhoisPlugin struct {
	client  *client.Client
	baseURL string // overridable for tests
}

func (p *WhoxyReverseWhoisPlugin) Name() string { return "whoxy-reverse-whois" }
func (p *WhoxyReverseWhoisPlugin) Description() string {
	return "Reverse WHOIS via Whoxy API — discovers related domains by registrant name (paid, requires WHOXY_API_KEY)"
}
func (p *WhoxyReverseWhoisPlugin) Category() string { return "domain" }
func (p *WhoxyReverseWhoisPlugin) Phase() int       { return 0 }
func (p *WhoxyReverseWhoisPlugin) Mode() string     { return plugins.ModePassive }

// Accepts only runs if WHOXY_API_KEY is set and an org name or registrant
// email seed is provided.
func (p *WhoxyReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("WHOXY_API_KEY") != "" && (input.OrgName != "" || input.Email != "")
}

type whoxyResponse struct {
	TotalPages   int                 `json:"total_pages"`
	SearchResult []whoxySearchResult `json:"search_result"`
}

type whoxySearchResult struct {
	DomainName string `json:"domain_name"`
	QueryTime  string `json:"query_time"`
}

func (p *WhoxyReverseWhoisPlugin) apiBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.whoxy.com"
}

func (p *WhoxyReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("WHOXY_API_KEY")

	page := 1
	totalPages := 1
	var findings []plugins.Finding
	seen := make(map[string]struct{})

	for {
		resp, err := p.fetchPage(ctx, apiKey, input.OrgName, page)
		if err != nil {
			slog.Warn("whoxy-reverse-whois: stopping pagination", "page", page, "org", input.OrgName, "error", err)
			break
		}

		if resp.TotalPages > 0 {
			totalPages = resp.TotalPages
		}

		for _, result := range resp.SearchResult {
			if result.DomainName == "" {
				continue
			}
			if whoxyRecordStale(result.QueryTime) {
				continue
			}
			domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(result.DomainName), "."))
			if _, ok := seen[domain]; ok {
				continue
			}
			seen[domain] = struct{}{}
			f := plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  domain,
				Source: p.Name(),
				Data: map[string]any{
					"org": input.OrgName,
				},
			}
			// WHOIS registrant name matching is reliable but not perfect.
			// Score at 0.75 — above the review threshold so output is clean,
			// but confidence is available in Data for agent/downstream use.
			plugins.SetConfidence(&f, 0.75)
			findings = append(findings, f)
		}

		if len(resp.SearchResult) == 0 || page >= totalPages || page >= maxWhoxyPages {
			break
		}
		page++
	}

	return findings, nil
}

func (p *WhoxyReverseWhoisPlugin) fetchPage(ctx context.Context, apiKey, orgName string, page int) (whoxyResponse, error) {
	reqURL := fmt.Sprintf(
		"%s/?key=%s&reverse=whois&name=%s&mode=micro&page=%d",
		p.apiBase(),
		url.QueryEscape(apiKey),
		url.QueryEscape(orgName),
		page,
	)

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		// Do not propagate the URL — it contains the API key.
		return whoxyResponse{}, fmt.Errorf("request failed")
	}

	var resp whoxyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return whoxyResponse{}, fmt.Errorf("parse response: %w", err)
	}

	return resp, nil
}

// whoxyRecordStale filters out records where Whoxy's query_time (last cache
// refresh) is older than 10 years. This is guard-core parity — note that
// query_time is NOT the domain registration date but when Whoxy last crawled it.
func whoxyRecordStale(queryTime string) bool {
	t, err := time.Parse(time.DateTime, queryTime)
	if err != nil {
		return true
	}
	return t.Before(time.Now().AddDate(-10, 0, 0))
}
