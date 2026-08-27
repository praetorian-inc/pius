package domains

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

func init() {
	plugins.Register("whois", func() plugins.Plugin { return &WhoisPlugin{} })
}

// WhoisPlugin performs domain registration lookups through the configured
// WHOIS sequence, emitting structured WHOIS results and preseed findings.
type WhoisPlugin struct {
	HTTPClient *http.Client
}

// NewWhoisPlugin creates a WhoisPlugin with an injectable HTTP client.
func NewWhoisPlugin(httpClient *http.Client) *WhoisPlugin {
	return &WhoisPlugin{HTTPClient: httpClient}
}

func (p *WhoisPlugin) Name() string                     { return "whois" }
func (p *WhoisPlugin) Description() string              { return "Domain WHOIS via RDAP and TCP 43" }
func (p *WhoisPlugin) Category() string                 { return "domain" }
func (p *WhoisPlugin) Phase() int                       { return 0 }
func (p *WhoisPlugin) Mode() string                     { return plugins.ModePassive }
func (p *WhoisPlugin) Accepts(input plugins.Input) bool { return input.Domain != "" }

func (p *WhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	var opts []func(*whois.WHOIS)
	if p.HTTPClient != nil {
		opts = append(opts, whois.WithHTTPClient(p.HTTPClient))
	}

	result, err := whois.New(opts...).LookupDomain(ctx, input.Domain)
	if err != nil {
		return nil, err
	}

	var findings []plugins.Finding
	findings = append(findings, buildWhoisResultFinding(result, input.OrgName))
	if !result.Unregistered {
		findings = append(findings, extractPreseeds(result)...)
	}
	return findings, nil
}

// WhoisFindingData wraps a domain registration result with corroboration metadata.
type WhoisFindingData struct {
	whois.DomainResult
	Corroboration string `json:"corroboration,omitempty"`
}

func buildWhoisResultFinding(r whois.DomainResult, pivotOrg string) plugins.Finding {
	if r.Unregistered {
		return plugins.Finding{
			Type:   plugins.FindingWhoisResult,
			Value:  r.Domain,
			Source: "whois",
			Data:   plugins.FindingData(whois.DomainResult{Domain: r.Domain, Unregistered: true}),
		}
	}

	fd := WhoisFindingData{DomainResult: r}
	if pivotOrg != "" {
		fd.Corroboration = whois.Corroborate(pivotOrg, r.Registrant.Organization)
	}

	return plugins.Finding{
		Type:   plugins.FindingWhoisResult,
		Value:  r.Domain,
		Source: "whois",
		Data:   plugins.FindingData(fd),
	}
}

const confWhoisServerRecord = 85

type preseedCandidate struct {
	field string
	role  string
	value string
}

func extractPreseeds(r whois.DomainResult) []plugins.Finding {
	var candidates []preseedCandidate
	for _, contact := range r.AllContacts() {
		candidates = append(candidates, contactPreseedCandidates(contact)...)
	}

	// Keep the highest-priority role for each field and value.
	unique := strutil.UniqueFunc(candidates, func(c preseedCandidate) [2]string {
		return [2]string{c.field, c.value}
	})

	// Name the answering server so a reviewer can retrace the record to its
	// source. It is only known when the TCP-43 chain contributed to the
	// result; an RDAP-only lookup has no WHOIS server to cite.
	source := "WHOIS"
	if r.WhoisServer != "" {
		source = "WHOIS server " + r.WhoisServer
	}

	var findings []plugins.Finding
	for _, cd := range unique {
		f := plugins.Finding{
			Type:   plugins.FindingPreseed,
			Value:  cd.value,
			Source: "whois",
			Data: map[string]any{
				"preseed_type":  "whois+" + cd.field,
				"preseed_title": cd.value,
			},
		}
		plugins.AddConfidence(&f, confWhoisServerRecord,
			fmt.Sprintf("%s records %q as the %s contact %s",
				source, cd.value, cd.role, cd.field))
		findings = append(findings, f)
	}
	return findings
}

func contactPreseedCandidates(contact whois.DomainContact) []preseedCandidate {
	candidates := []preseedCandidate{
		{field: "company", role: contact.Role, value: contact.Organization},
		{field: "name", role: contact.Role, value: contact.Name},
		{field: "email", role: contact.Role, value: contact.Email},
	}
	return slices.DeleteFunc(candidates, func(candidate preseedCandidate) bool {
		return candidate.value == "" || candidate.value == whois.PrivacyRedaction ||
			(candidate.field == "email" && !whois.IsEmail(candidate.value))
	})
}
