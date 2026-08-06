package domains

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
)

func init() {
	plugins.Register("whois", func() plugins.Plugin { return &WhoisPlugin{} })
}

// WhoisPlugin performs domain WHOIS lookups via RDAP (primary) with TCP-43
// fallback, emitting structured WHOIS result and preseed findings.
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
	var opts []whois.Option
	if p.HTTPClient != nil {
		opts = append(opts, whois.WithHTTPClient(p.HTTPClient))
	}

	result, err := whois.Lookup(ctx, input.Domain, opts...)
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

// whoisResultData is the structured payload for FindingWhoisResult.
// Using a struct instead of a hand-built map makes this testable and
// keeps the keys in sync between producer and consumer.
type whoisResultData struct {
	Registrant    string `json:"registrant,omitempty"`
	Email         string `json:"email,omitempty"`
	Registrar     string `json:"registrar,omitempty"`
	Country       string `json:"country,omitempty"`
	Province      string `json:"province,omitempty"`
	City          string `json:"city,omitempty"`
	Purchased     string `json:"purchased,omitempty"`
	Updated       string `json:"updated,omitempty"`
	Expiration    string `json:"expiration,omitempty"`
	Raw           string `json:"raw,omitempty"`
	Corroboration string `json:"corroboration,omitempty"`
	Unregistered  bool   `json:"unregistered,omitempty"`
}

// toMap round-trips the struct through JSON into map[string]any. This keeps
// Finding.Data generic while letting us define the schema as a struct.
func (d whoisResultData) toMap() map[string]any {
	b, _ := json.Marshal(d)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func buildWhoisResultFinding(r whois.Result, pivotOrg string) plugins.Finding {
	finding := func(d whoisResultData) plugins.Finding {
		return plugins.Finding{
			Type:   plugins.FindingWhoisResult,
			Value:  r.Domain,
			Source: "whois",
			Data:   d.toMap(),
		}
	}

	if r.Unregistered {
		return finding(whoisResultData{Unregistered: true})
	}

	org := whois.RegistrantOrg(r.Registrant, r.Domain)
	d := whoisResultData{
		Registrant: whois.NormalizePrivacy(org),
		Country:    whois.NormalizePrivacy(r.Registrant.Country),
		Province:   whois.NormalizePrivacy(r.Registrant.Province),
		City:       whois.NormalizePrivacy(r.Registrant.City),
		Registrar:  whois.NormalizeRegistrar(r.Registrar),
		Purchased:  r.Created,
		Updated:    r.Updated,
		Expiration: r.Expiration,
		Raw:        r.Raw,
	}

	email, sawProxy := whois.ContactEmail(r)
	switch {
	case email != "":
		d.Email = email
	case sawProxy || d.Registrant == whois.PrivacyRedaction:
		d.Email = whois.PrivacyRedaction
	}

	if pivotOrg != "" {
		d.Corroboration = whois.Corroborate(pivotOrg, org)
	}

	return finding(d)
}

func extractPreseeds(r whois.Result) []plugins.Finding {
	type param struct{ name, value string }

	seen := map[param]bool{}
	var findings []plugins.Finding

	contacts := r.AllContacts()
	for i, c := range contacts {
		org := c.Organization
		if i == 0 { // registrant
			org = whois.RegistrantOrg(c, r.Domain)
		}

		for _, p := range []param{
			{"company", org},
			{"name", c.Name},
			{"email", c.Email},
		} {
			if p.value == "" || seen[p] || whois.IsPrivacy(p.value) {
				continue
			}
			if p.name == "email" && !whois.IsEmail(p.value) {
				continue
			}
			seen[p] = true

			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingPreseed,
				Value:  p.value,
				Source: "whois",
				Data: map[string]any{
					"preseed_type":  "whois+" + p.name,
					"preseed_title": p.value,
				},
			})
		}
	}
	return findings
}
