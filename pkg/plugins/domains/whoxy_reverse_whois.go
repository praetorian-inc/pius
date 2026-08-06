package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const maxWhoxyPages = 100

func init() {
	plugins.Register("whoxy-reverse-whois", func() plugins.Plugin { return &WhoxyReverseWhoisPlugin{client: client.New()} })
}

// WhoxyReverseWhoisPlugin discovers related domains via Whoxy reverse WHOIS.
// Emits FindingDomain with Data["pivot_org"]. Verification happens when Guard
// runs the whois capability on each discovered domain.
type WhoxyReverseWhoisPlugin struct {
	client  *client.Client
	baseURL string // overridable for tests
}

// NewWhoxyReverseWhoisPlugin creates a plugin with an injectable HTTP client.
func NewWhoxyReverseWhoisPlugin(httpClient *client.Client) *WhoxyReverseWhoisPlugin {
	return &WhoxyReverseWhoisPlugin{client: httpClient}
}

func (p *WhoxyReverseWhoisPlugin) Name() string        { return "whoxy-reverse-whois" }
func (p *WhoxyReverseWhoisPlugin) Description() string { return "Reverse WHOIS via Whoxy API (requires WHOXY_API_KEY)" }
func (p *WhoxyReverseWhoisPlugin) Category() string    { return "domain" }
func (p *WhoxyReverseWhoisPlugin) Phase() int          { return 0 }
func (p *WhoxyReverseWhoisPlugin) Mode() string        { return plugins.ModePassive }

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

	var rawDomains []string
	page := 1
	totalPages := 1

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
			if result.DomainName != "" && !whoxyRecordStale(result.QueryTime) {
				rawDomains = append(rawDomains, result.DomainName)
			}
		}
		if len(resp.SearchResult) == 0 || page >= totalPages || page >= maxWhoxyPages {
			break
		}
		page++
	}

	return domainFindings(p.Name(), query, rawDomains), nil
}

func (p *WhoxyReverseWhoisPlugin) fetchPage(ctx context.Context, apiKey, query string, byEmail bool, page int) (whoxyResponse, error) {
	param := "name"
	if byEmail {
		param = "email"
	}
	reqURL := fmt.Sprintf(
		"%s/?key=%s&reverse=whois&%s=%s&mode=micro&page=%d",
		p.apiBase(), url.QueryEscape(apiKey), param, url.QueryEscape(query), page,
	)

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		return whoxyResponse{}, fmt.Errorf("request failed")
	}

	var resp whoxyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return whoxyResponse{}, fmt.Errorf("parse response: %w", err)
	}
	return resp, nil
}

func whoxyRecordStale(queryTime string) bool {
	t, err := time.Parse(time.DateTime, queryTime)
	if err != nil {
		return true
	}
	return t.Before(time.Now().AddDate(-10, 0, 0))
}
