package domains

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const maxWhoxyPages = 100

func init() {
	plugins.Register("whoxy-reverse-whois", func() plugins.Plugin { return &WhoxyReverseWhoisPlugin{client: client.New()} })
}

// WhoxyReverseWhoisPlugin discovers related domains via Whoxy reverse WHOIS.
// It emits scored FindingDomain results with Data["pivot_org"], corroborating
// each candidate against a fresh WHOIS response.
type WhoxyReverseWhoisPlugin struct {
	client      *client.Client
	apiKey      string
	baseURL     string // overridable for tests
	lookupWhois domainWhoisLookup
}

// NewWhoxyReverseWhoisPlugin creates a plugin with an injectable HTTP client and API key.
func NewWhoxyReverseWhoisPlugin(httpClient *client.Client, apiKey string) *WhoxyReverseWhoisPlugin {
	return &WhoxyReverseWhoisPlugin{client: httpClient, apiKey: apiKey}
}

func (p *WhoxyReverseWhoisPlugin) Name() string { return "whoxy-reverse-whois" }
func (p *WhoxyReverseWhoisPlugin) Description() string {
	return "Reverse WHOIS via Whoxy API (requires WHOXY_API_KEY)"
}
func (p *WhoxyReverseWhoisPlugin) Category() string { return "domain" }
func (p *WhoxyReverseWhoisPlugin) Phase() int       { return 0 }
func (p *WhoxyReverseWhoisPlugin) Mode() string     { return plugins.ModePassive }

func (p *WhoxyReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return p.resolveAPIKey() != "" && (input.OrgName != "" || input.PersonName != "" || input.Email != "")
}

func (p *WhoxyReverseWhoisPlugin) resolveAPIKey() string {
	return cmp.Or(p.apiKey, os.Getenv("WHOXY_API_KEY"))
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

// whoxyQuery pairs a Whoxy API parameter name with the search value.
type whoxyQuery struct {
	param string // "company", "name", or "email"
	value string
}

func (p *WhoxyReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := p.resolveAPIKey()

	// Build the set of queries from the input. Whoxy distinguishes company
	// names (&company=) from person names (&name=) from email (&email=).
	queries := buildWhoxyQueries(input)
	if len(queries) == 0 {
		return nil, nil
	}

	pivotOrg := cmp.Or(input.OrgName, input.PersonName, input.Email)

	var allDomains []string
	for _, q := range queries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		domains, err := p.paginateQuery(ctx, apiKey, q)
		if err != nil {
			slog.Warn("whoxy-reverse-whois: query failed", "param", q.param, "value", q.value, "error", err)
			continue
		}
		allDomains = append(allDomains, domains...)
	}

	findings := domainFindings(p.Name(), pivotOrg, allDomains)
	addReverseWhoisConfidences(ctx, input, findings, p.lookupWhois)
	return findings, nil
}

// buildWhoxyQueries maps Input fields to the correct Whoxy API parameters.
func buildWhoxyQueries(input plugins.Input) []whoxyQuery {
	var queries []whoxyQuery
	if input.OrgName != "" {
		queries = append(queries, whoxyQuery{param: "company", value: input.OrgName})
	}
	if input.PersonName != "" {
		queries = append(queries, whoxyQuery{param: "name", value: input.PersonName})
	}
	if input.Email != "" {
		queries = append(queries, whoxyQuery{param: "email", value: input.Email})
	}
	return queries
}

func (p *WhoxyReverseWhoisPlugin) paginateQuery(ctx context.Context, apiKey string, q whoxyQuery) ([]string, error) {
	var domains []string
	page := 1
	totalPages := 1

	for {
		resp, err := p.fetchPage(ctx, apiKey, q.param, q.value, page)
		if err != nil {
			if page == 1 {
				return nil, err
			}
			slog.Warn("whoxy-reverse-whois: stopping pagination", "page", page, "error", err)
			break
		}
		if resp.TotalPages > 0 {
			totalPages = resp.TotalPages
		}
		for _, result := range resp.SearchResult {
			if result.DomainName != "" && !whoxyRecordStale(result.QueryTime) {
				domains = append(domains, result.DomainName)
			}
		}
		if len(resp.SearchResult) == 0 || page >= totalPages || page >= maxWhoxyPages {
			break
		}
		page++
	}

	return strutil.Unique(domains), nil
}

func (p *WhoxyReverseWhoisPlugin) fetchPage(ctx context.Context, apiKey, param, value string, page int) (whoxyResponse, error) {
	reqURL := fmt.Sprintf(
		"%s/?key=%s&reverse=whois&%s=%s&mode=micro&page=%d",
		p.apiBase(), url.QueryEscape(apiKey), param, url.QueryEscape(value), page,
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
