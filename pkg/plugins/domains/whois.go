package domains

import (
	"context"
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
			Data:   plugins.FindingData(whois.Result{Domain: r.Domain, Unregistered: true}),
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
		Data:   plugins.FindingData(fd),
	}
}

const confWhoisServerRecord = 85

type domainContact struct {
	field string
	role  string
	value string
}

func extractPreseeds(r whois.Result) []plugins.Finding {
	roles := [4]string{"registrant", "administrative", "technical", "billing"}
	contacts := r.AllContacts()

	// Collect all valid candidates, then dedupe by {field, value}.
	var all []domainContact
	for i, c := range contacts {
		org := c.Organization
		if i == 0 {
			org = whois.RegistrantOrg(c, r.Domain)
		}
		for _, cd := range []domainContact{
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
	unique := strutil.UniqueFunc(all, func(c domainContact) [2]string {
		return [2]string{c.field, c.value}
	})

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
		addDomainRegistrationConfidence(&f, r, cd)
		findings = append(findings, f)
	}
	return findings
}

func addDomainRegistrationConfidence(finding *plugins.Finding, result whois.Result, contact domainContact) {
	reference := domainRegistrationReference(result, contact.value)
	source := "WHOIS"
	if reference != nil && reference.Type == plugins.ReferenceTypeRDAP {
		source = "RDAP"
	} else if result.WhoisServer != "" {
		source += " server " + result.WhoisServer
	}

	justification := domainRegistrationJustification(source, result, contact)
	if reference == nil {
		plugins.AddConfidence(finding, confWhoisServerRecord, justification)
		return
	}
	plugins.AddConfidenceWithReference(finding, confWhoisServerRecord, justification, *reference)
}

func domainRegistrationJustification(source string, result whois.Result, contact domainContact) string {
	return fmt.Sprintf("%s for domain %q records %q as the %s contact %s",
		source, result.Domain, contact.value, contact.role, contact.field)
}

func domainRegistrationReference(result whois.Result, value string) *plugins.Reference {
	if len(result.RDAPResponse) > 0 && strutil.ContainsFold(string(result.RDAPResponse), value) {
		return &plugins.Reference{
			Label: "Observed domain RDAP response",
			Type:  plugins.ReferenceTypeRDAP,
			Data: plugins.RDAPReferenceData{
				Domain:   result.Domain,
				Response: result.RDAPResponse,
			},
		}
	}
	if !strutil.ContainsFold(result.WHOISResponse, value) {
		return nil
	}
	return &plugins.Reference{
		Label: "Observed domain WHOIS response",
		Type:  plugins.ReferenceTypeWHOIS,
		Data: plugins.WHOISReferenceData{
			Domain:        result.Domain,
			WHOISServer:   result.WhoisServer,
			WHOISResponse: result.WHOISResponse,
		},
	}
}
