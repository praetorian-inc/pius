package domains

import (
	"context"
	"net/http"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

func init() {
	plugins.Register("whois-domain-history", func() plugins.Plugin { return &WhoisHistoryPlugin{} })
}

// WhoisHistoryPlugin retrieves historical domain registration records.
type WhoisHistoryPlugin struct {
	HTTPClient *http.Client
	options    []whois.Option
}

// NewWhoisHistoryPlugin creates a WhoisHistoryPlugin with an injectable HTTP client and WHOIS options.
func NewWhoisHistoryPlugin(httpClient *http.Client, opts ...whois.Option) *WhoisHistoryPlugin {
	return &WhoisHistoryPlugin{HTTPClient: httpClient, options: append([]whois.Option{}, opts...)}
}

func (p *WhoisHistoryPlugin) Name() string { return "whois-domain-history" }
func (p *WhoisHistoryPlugin) Description() string {
	return "Historical domain registration records from commercial WHOIS providers"
}
func (p *WhoisHistoryPlugin) Category() string                 { return "domain" }
func (p *WhoisHistoryPlugin) Phase() int                       { return 0 }
func (p *WhoisHistoryPlugin) Mode() string                     { return plugins.ModePassive }
func (p *WhoisHistoryPlugin) Accepts(input plugins.Input) bool { return input.Domain != "" }

func (p *WhoisHistoryPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	domain := whois.RootDomain(input.Domain)

	opts := []whois.Option{whois.WithHTTPClient(p.HTTPClient)}
	opts = append(opts, p.options...)

	client := whois.New(opts...)

	records, err := client.LookupDomainHistory(ctx, domain)
	if err != nil {
		return nil, err
	}
	if records == nil {
		records = []whois.DomainHistoryRecord{}
	}

	return []plugins.Finding{{
		Type:   plugins.FindingWhoisHistory,
		Value:  domain,
		Source: p.Name(),
		Data: plugins.FindingData(WhoisHistoryFindingData{
			Records: records,
		}),
	}}, nil
}

// WhoisHistoryFindingData is the typed payload emitted for historical WHOIS findings.
type WhoisHistoryFindingData struct {
	Records []whois.DomainHistoryRecord `json:"records"`
}
