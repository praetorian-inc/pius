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

// WhoxyReverseWhoisPlugin discovers related domains via Whoxy reverse WHOIS.
// It emits FindingDomain with Data["pivot_org"] for each discovered domain.
// Verification is NOT done inline — Guard fans out whois jobs on discovered
// domains for parallel corroboration.
type WhoxyReverseWhoisPlugin struct {
	client  *client.Client
	baseURL string // overridable for tests
}

// NewWhoxyReverseWhoisPlugin creates a plugin with an injectable HTTP client.
func NewWhoxyReverseWhoisPlugin(httpClient *client.Client) *WhoxyReverseWhoisPlugin {
	return &WhoxyReverseWhoisPlugin{client: httpClient}
}

func (p *WhoxyReverseWhoisPlugin) Name() string { return "whoxy-reverse-whois" }
func (p *WhoxyReverseWhoisPlugin) Description() string {
	return "Reverse WHOIS via Whoxy API (requires WHOXY_API_KEY)"
}
func (p *WhoxyReverseWhoisPlugin) Category() string { return "domain" }
func (p *WhoxyReverseWhoisPlugin) Phase() int       { return 0 }
func (p *WhoxyReverseWhoisPlugin) Mode() string     { return plugins.ModePassive }

func (p *WhoxyReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("WHOXY_API_KEY") != "" && (input.OrgName != "" || input.Email != "")
}

func (p *WhoxyReverseWhoisPlugin) apiBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.whoxy.com"
}

type whoxyResponse struct {
	TotalPages   int                 `json:"total_pages"`
	SearchResult []whoxySearchResult `json:"search_result"`
}

type whoxySearchResult struct {
	DomainName string `json:"domain_name"`
	QueryTime  string `json:"query_time"`
}

func (p *WhoxyReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("WHOXY_API_KEY")

	query, byEmail := input.OrgName, false
	if input.OrgName == "" && input.Email != "" {
		query, byEmail = input.Email, true
	}

	page := 1
	totalPages := 1
	seen := make(map[string]struct{})
	var findings []plugins.Finding

	for {
		resp, err := p.fetchPage(ctx, apiKey, query, byEmail, page)
		if err != nil {
			slog.Warn("whoxy-reverse-whois: stopping pagination", "page", page, "error", err)
			break
		}

		if resp.TotalPages > 0 {
			totalPages = resp.TotalPages
		}

		for _, result := range resp.SearchResult {
			if result.DomainName == "" || whoxyRecordStale(result.QueryTime) {
				continue
			}
			domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(result.DomainName), "."))
			if domain == "" || !isPlausibleDomain(domain) {
				continue
			}
			if _, ok := seen[domain]; ok {
				continue
			}
			seen[domain] = struct{}{}

			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  domain,
				Source: p.Name(),
				Data: map[string]any{
					"pivot_org": query,
				},
			})
		}

		if len(resp.SearchResult) == 0 || page >= totalPages || page >= maxWhoxyPages {
			break
		}
		page++
	}

	return findings, nil
}

func (p *WhoxyReverseWhoisPlugin) fetchPage(ctx context.Context, apiKey, query string, byEmail bool, page int) (whoxyResponse, error) {
	param := "name"
	if byEmail {
		param = "email"
	}
	reqURL := fmt.Sprintf(
		"%s/?key=%s&reverse=whois&%s=%s&mode=micro&page=%d",
		p.apiBase(),
		url.QueryEscape(apiKey),
		param,
		url.QueryEscape(query),
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

// whoxyRecordStale filters records where Whoxy's query_time is older than 10 years.
func whoxyRecordStale(queryTime string) bool {
	t, err := time.Parse(time.DateTime, queryTime)
	if err != nil {
		return true
	}
	return t.Before(time.Now().AddDate(-10, 0, 0))
}
