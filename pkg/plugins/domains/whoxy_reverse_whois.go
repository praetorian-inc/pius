package domains

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

const maxWhoxyPages = 100

func init() {
	plugins.Register("whoxy-reverse-whois", func() plugins.Plugin {
		return NewWhoxyReverseWhoisPlugin(nil)
	})
}

// WhoxyReverseWhoisPlugin discovers related domains via Whoxy reverse WHOIS.
// Emits FindingDomain with Data["pivot_org"]. Verification happens when Guard
// runs the whois capability on each discovered domain.
type WhoxyReverseWhoisPlugin struct {
	client *whois.WhoxyClient
}

// NewWhoxyReverseWhoisPlugin creates a plugin with an injectable HTTP client.
func NewWhoxyReverseWhoisPlugin(httpClient *http.Client) *WhoxyReverseWhoisPlugin {
	return &WhoxyReverseWhoisPlugin{client: whois.NewWhoxyClient(httpClient, "")}
}

func (p *WhoxyReverseWhoisPlugin) Name() string { return "whoxy-reverse-whois" }
func (p *WhoxyReverseWhoisPlugin) Description() string {
	return "Reverse WHOIS via Whoxy API (requires WHOXY_API_KEY)"
}
func (p *WhoxyReverseWhoisPlugin) Category() string { return "domain" }
func (p *WhoxyReverseWhoisPlugin) Phase() int       { return 0 }
func (p *WhoxyReverseWhoisPlugin) Mode() string     { return plugins.ModePassive }

func (p *WhoxyReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("WHOXY_API_KEY") != "" && (input.OrgName != "" || input.PersonName != "" || input.Email != "")
}

// whoxyQuery pairs a Whoxy API parameter name with the search value.
type whoxyQuery struct {
	param string // "company", "name", or "email"
	value string
}

func (p *WhoxyReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
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
		domains, err := p.paginateQuery(ctx, q)
		if err != nil {
			slog.Warn("whoxy-reverse-whois: query failed", "param", q.param, "value", q.value, "error", err)
			continue
		}
		allDomains = append(allDomains, domains...)
	}

	return domainFindings(p.Name(), pivotOrg, allDomains), nil
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

func (p *WhoxyReverseWhoisPlugin) paginateQuery(ctx context.Context, q whoxyQuery) ([]string, error) {
	var domains []string
	page := 1
	totalPages := 1

	for {
		resp, err := p.client.ReverseLookup(ctx, q.param, q.value, page)
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

func whoxyRecordStale(queryTime string) bool {
	t, err := time.Parse(time.DateTime, queryTime)
	if err != nil {
		return true
	}
	return t.Before(time.Now().AddDate(-10, 0, 0))
}
