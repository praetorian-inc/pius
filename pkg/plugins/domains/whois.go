package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
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

// toMap round-trips a struct through JSON into map[string]any. This keeps
// Finding.Data generic while letting us define the schema as a struct.
func toMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// whoisFindingData wraps a whois.Result with corroboration metadata for the
// Finding payload.
type whoisFindingData struct {
	whois.Result
	Corroboration string `json:"corroboration,omitempty"`
}

func buildWhoisResultFinding(r whois.Result, pivotOrg string) plugins.Finding {
	if r.Unregistered {
		return plugins.Finding{
			Type:   plugins.FindingWhoisResult,
			Value:  r.Domain,
			Source: "whois",
			Data:   toMap(whois.Result{Domain: r.Domain, Unregistered: true}),
		}
	}

	// Normalize privacy on the registrant fields before emitting.
	org := whois.RegistrantOrg(r.Registrant, r.Domain)
	r.Registrant.Organization = whois.NormalizePrivacy(org)
	r.Registrant.Country = whois.NormalizePrivacy(r.Registrant.Country)
	r.Registrant.Province = whois.NormalizePrivacy(r.Registrant.Province)
	r.Registrant.City = whois.NormalizePrivacy(r.Registrant.City)
	r.Registrar = whois.NormalizeRegistrar(r.Registrar)

	// Find the best non-privacy email across all contacts.
	email, sawProxy := whois.ContactEmail(r)
	switch {
	case email != "":
		r.Registrant.Email = email
	case sawProxy || r.Registrant.Organization == whois.PrivacyRedaction:
		r.Registrant.Email = whois.PrivacyRedaction
	}

	fd := whoisFindingData{Result: r}
	if pivotOrg != "" {
		fd.Corroboration = whois.Corroborate(pivotOrg, org)
	}

	return plugins.Finding{
		Type:   plugins.FindingWhoisResult,
		Value:  r.Domain,
		Source: "whois",
		Data:   toMap(fd),
	}
}

const confWhoisServerRecord = 0.85

func extractPreseeds(r whois.Result) []plugins.Finding {
	type candidate struct {
		field, role, value string
	}

	roles := [4]string{"registrant", "administrative", "technical", "billing"}
	contacts := r.AllContacts()

	// Collect all valid candidates, then dedupe by {field, value}.
	var all []candidate
	for i, c := range contacts {
		org := c.Organization
		if i == 0 {
			org = whois.RegistrantOrg(c, r.Domain)
		}
		for _, cd := range []candidate{
			{"company", roles[i], org},
			{"name", roles[i], c.Name},
			{"email", roles[i], c.Email},
		} {
			if cd.value == "" || whois.IsPrivacy(cd.value) {
				continue
			}
			if cd.field == "email" && !whois.IsEmail(cd.value) {
				continue
			}
			all = append(all, cd)
		}
	}

	// Dedupe: keep first occurrence per {field, value} (preserves the
	// highest-priority role since contacts are ordered registrant-first).
	unique := strutil.UniqueFunc(all, func(c candidate) [2]string {
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
