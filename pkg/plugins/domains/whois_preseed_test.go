package domains

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/whois"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPreseeds_DropsMonikerPrivacyServices(t *testing.T) {
	contact := whois.Contact{
		Name:         "Moniker Privacy Services",
		Organization: "Moniker Privacy Services",
		Email:        "676db20f21af0a0a9ccb7d19f72c34238d63e06ceb66bf94ec7f7ce203093358@randommedia.com.whoisproxy.org",
	}
	r := whois.DomainResult{
		Domain:     "randommedia.com",
		Registrant: contact,
		Admin:      contact,
		Tech:       contact,
		Billing:    contact,
	}
	r.Normalize()

	assert.Empty(t, extractPreseeds(r))
}

// A preseed justification names the server that answered the WHOIS query, so a
// reviewer can retrace the claim to the record it came from.
func TestExtractPreseeds_JustificationNamesWhoisServer(t *testing.T) {
	r := whois.DomainResult{
		Domain:      "example.com",
		WhoisServer: "whois.registrar.example",
		Registrant:  whois.Contact{Organization: "ACME-CORP"},
	}

	findings := extractPreseeds(r)

	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t,
		`WHOIS server whois.registrar.example records "ACME-CORP" as the registrant contact company`,
		findings[0].Confidences[0].Justification)
}

// An RDAP-only lookup has no WHOIS server to cite, so the justification falls
// back to the unattributed wording rather than naming an empty server.
func TestExtractPreseeds_JustificationOmitsUnknownWhoisServer(t *testing.T) {
	r := whois.DomainResult{
		Domain:     "example.com",
		Registrant: whois.Contact{Organization: "ACME-CORP"},
	}

	findings := extractPreseeds(r)

	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t,
		`WHOIS records "ACME-CORP" as the registrant contact company`,
		findings[0].Confidences[0].Justification)
}

func TestBuildWhoisResultFinding_PreservesContactRoles(t *testing.T) {
	result := whois.DomainResult{
		Domain:     "example.com",
		Registrant: whois.Contact{Email: "proxy@withheldforprivacy.com"},
		Admin:      whois.Contact{Email: "admin@example.com"},
	}
	result.Normalize()

	finding := buildWhoisResultFinding(result, "")

	registrant, ok := finding.Data["registrant"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, whois.PrivacyRedaction, registrant["email"])
	assert.Equal(t, "admin@example.com", finding.Data["contact_email"])
	assert.Equal(t, "administrative", finding.Data["contact_email_role"])

	preseeds := extractPreseeds(result)
	require.Len(t, preseeds, 1)
	assert.Equal(t, "admin@example.com", preseeds[0].Value)
	assert.Equal(t, "whois+email", preseeds[0].Data["preseed_type"])
}

func TestBuildWhoisResultFinding_NameOnlyRegistrantRemainsTypedAsName(t *testing.T) {
	result := whois.DomainResult{
		Domain:     "acme.cn",
		Registrant: whois.Contact{Name: "Acme Holdings Ltd."},
	}
	result.Normalize()

	finding := buildWhoisResultFinding(result, "Acme Holdings Ltd.")

	assert.Equal(t, "Acme Holdings Ltd.", finding.Data["registrant_identity"])
	assert.Equal(t, "unverifiable", finding.Data["corroboration"])
	preseeds := extractPreseeds(result)
	require.Len(t, preseeds, 1)
	assert.Equal(t, "whois+name", preseeds[0].Data["preseed_type"])
	assert.Equal(t, "Acme Holdings Ltd.", preseeds[0].Value)
}
