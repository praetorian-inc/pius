package domains

import (
	"context"
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
	HTTPClient *http.Client // injectable for Guard's collector transport
}

// NewWhoisPlugin creates a WhoisPlugin with an injectable HTTP client.
func NewWhoisPlugin(httpClient *http.Client) *WhoisPlugin {
	return &WhoisPlugin{HTTPClient: httpClient}
}

func (p *WhoisPlugin) Name() string                       { return "whois" }
func (p *WhoisPlugin) Description() string                { return "Domain WHOIS via RDAP and TCP 43" }
func (p *WhoisPlugin) Category() string                   { return "domain" }
func (p *WhoisPlugin) Phase() int                         { return 0 }
func (p *WhoisPlugin) Mode() string                       { return plugins.ModePassive }
func (p *WhoisPlugin) Accepts(input plugins.Input) bool   { return input.Domain != "" }

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

	// Emit structured WHOIS result (metadata, raw text, corroboration).
	findings = append(findings, buildWhoisResultFinding(result, input.OrgName))

	// Emit preseeds (company, email, name) — only for registered domains.
	if !result.Unregistered {
		findings = append(findings, extractPreseeds(result)...)
	}

	return findings, nil
}

// buildWhoisResultFinding converts a whois.Result into a FindingWhoisResult.
func buildWhoisResultFinding(r whois.Result, pivotOrg string) plugins.Finding {
	data := map[string]any{}

	if r.Unregistered {
		data["unregistered"] = true
	} else {
		org := whois.RegistrantOrg(r.Registrant, r.Domain)
		normalizedOrg := whois.NormalizePrivacy(org)

		email, sawProxy := whois.ContactEmail(r)
		registrantRedacted := normalizedOrg == whois.PrivacyRedaction

		if normalizedOrg != "" {
			data["registrant"] = normalizedOrg
		}
		switch {
		case email != "":
			data["email"] = email
		case sawProxy || registrantRedacted:
			data["email"] = whois.PrivacyRedaction
		}

		data["country"] = whois.NormalizePrivacy(r.Registrant.Country)
		data["province"] = whois.NormalizePrivacy(r.Registrant.Province)
		data["city"] = whois.NormalizePrivacy(r.Registrant.City)
		data["registrar"] = whois.NormalizeRegistrar(r.Registrar)
		data["purchased"] = r.Created
		data["updated"] = r.Updated
		data["expiration"] = r.Expiration
		data["raw"] = r.Raw

		if pivotOrg != "" {
			data["corroboration"] = whois.Corroborate(pivotOrg, org)
		}
	}

	return plugins.Finding{
		Type:   plugins.FindingWhoisResult,
		Value:  r.Domain,
		Source: "whois",
		Data:   data,
	}
}

// extractPreseeds pulls registrant organization, name, and email from WHOIS
// contacts, filtering out privacy/proxy noise.
func extractPreseeds(r whois.Result) []plugins.Finding {
	type param struct{ name, value string }

	seen := map[param]bool{}
	var findings []plugins.Finding

	contacts := r.AllContacts()
	for i, c := range contacts {
		// For registrant, use RegistrantOrg (handles ccTLD promotion and
		// registry artifact filtering). For other contacts, use org directly
		// but still filter registry artifacts.
		org := c.Organization
		if i == 0 { // registrant
			org = whois.RegistrantOrg(c, r.Domain)
		}

		candidates := []param{
			{"company", org},
			{"name", c.Name},
			{"email", c.Email},
		}

		for _, p := range candidates {
			if p.value == "" || seen[p] {
				continue
			}
			if whois.IsPrivacy(p.value) {
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
