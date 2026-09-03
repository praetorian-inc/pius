package domains

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

func init() {
	plugins.Register("whoisfreaks-reverse-whois", func() plugins.Plugin {
		return NewWhoisFreaksReverseWhoisPlugin(nil, "")
	})
}

type WhoisFreaksReverseWhoisPlugin struct {
	client *whois.WhoisFreaksClient
	apiKey string
}

func NewWhoisFreaksReverseWhoisPlugin(httpClient *http.Client, apiKey string) *WhoisFreaksReverseWhoisPlugin {
	return &WhoisFreaksReverseWhoisPlugin{
		client: whois.NewWhoisFreaksClient(httpClient, apiKey),
		apiKey: apiKey,
	}
}

func (p *WhoisFreaksReverseWhoisPlugin) Name() string { return "whoisfreaks-reverse-whois" }
func (p *WhoisFreaksReverseWhoisPlugin) Description() string {
	return "Reverse WHOIS via WhoisFreaks API (requires WHOISFREAKS_API_KEY)"
}
func (p *WhoisFreaksReverseWhoisPlugin) Category() string { return "domain" }
func (p *WhoisFreaksReverseWhoisPlugin) Phase() int       { return 0 }
func (p *WhoisFreaksReverseWhoisPlugin) Mode() string     { return plugins.ModePassive }

func (p *WhoisFreaksReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return p.resolveAPIKey() != "" &&
		(input.OrgName != "" || input.PersonName != "" || input.Email != "")
}

func (p *WhoisFreaksReverseWhoisPlugin) resolveAPIKey() string {
	return cmp.Or(p.apiKey, os.Getenv("WHOISFREAKS_API_KEY"))
}

type whoisFreaksQuery struct {
	param string // API parameter: "company", "owner", or "email"
	field string // provenance field: "company", "name", or "email"
	value string
}

func (p *WhoisFreaksReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	queries := buildWhoisFreaksQueries(input)
	if len(queries) == 0 {
		return nil, nil
	}

	var rawDomains []WhoisDomain
	for _, q := range queries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		records, err := p.client.ReverseLookup(ctx, q.param, q.value)
		if err != nil {
			slog.Warn("whoisfreaks-reverse-whois: query failed", "param", q.param, "value", q.value, "error", err)
			continue
		}
		for _, record := range records {
			if record.DomainName == "" || reverseWhoisRecordStale(record.QueryTime) {
				continue
			}
			rawDomains = append(rawDomains, WhoisDomain{
				value: record.DomainName,
				parameters: []WhoisParameter{{
					Field: q.field,
					Value: q.value,
				}},
			})
		}
	}

	return reverseWhoisFindings("https://whoisfreaks.com/", rawDomains), nil
}

func buildWhoisFreaksQueries(input plugins.Input) []whoisFreaksQuery {
	parameters := whoisParametersFromInput(input, stripLegalSuffixPeriods)
	queries := make([]whoisFreaksQuery, 0, len(parameters)+1)
	for _, parameter := range parameters {
		switch parameter.Field {
		case "company":
			// Organization names appear in either the company or registrant-name index.
			queries = append(queries,
				whoisFreaksQuery{param: "company", field: "company", value: parameter.Value},
				whoisFreaksQuery{param: "owner", field: "name", value: parameter.Value},
			)
		case "name":
			queries = append(queries, whoisFreaksQuery{param: "owner", field: "name", value: parameter.Value})
		case "email":
			queries = append(queries, whoisFreaksQuery{param: "email", field: "email", value: parameter.Value})
		}
	}
	return strutil.Unique(queries)
}
