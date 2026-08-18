package domains

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/whois"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A preseed justification names the server that answered the WHOIS query, so a
// reviewer can retrace the claim to the record it came from.
func TestExtractPreseeds_JustificationNamesWhoisServer(t *testing.T) {
	r := whois.Result{
		Domain:        "example.com",
		WhoisServer:   "whois.registrar.example",
		WHOISResponse: "Registrant Organization: ACME-CORP",
		Registrant:    whois.Contact{Organization: "ACME-CORP"},
	}

	findings := extractPreseeds(r)

	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t,
		`WHOIS server whois.registrar.example for domain "example.com" records "ACME-CORP" as the registrant contact company`,
		findings[0].Confidences[0].Justification)
	require.NotNil(t, findings[0].Confidences[0].Reference)
	assert.Equal(t, plugins.ReferenceTypeWHOIS, findings[0].Confidences[0].Reference.Type)
	data := findings[0].Confidences[0].Reference.Data.(map[string]any)
	assert.Equal(t, r.WHOISResponse, data["whois_response"])
}

// An RDAP-only lookup has no WHOIS server to cite, so the justification falls
// back to the unattributed wording rather than naming an empty server.
func TestExtractPreseeds_BundlesRDAPAndWhoisReferences(t *testing.T) {
	r := whois.Result{
		Domain:        "example.com",
		WhoisServer:   "whois.registrar.example",
		RDAPResponse:  json.RawMessage(`{"ldhName":"EXAMPLE.COM"}`),
		WHOISResponse: "Registrant Organization: ACME-CORP",
		Registrant:    whois.Contact{Organization: "ACME-CORP"},
	}

	findings := extractPreseeds(r)

	reference := findings[0].Confidences[0].Reference
	require.NotNil(t, reference)
	assert.Equal(t, plugins.ReferenceTypeReferences, reference.Type)
	references := reference.Data.([]plugins.Reference)
	require.Len(t, references, 2)
	assert.Equal(t, plugins.ReferenceTypeRDAP, references[0].Type)
	assert.Equal(t, plugins.ReferenceTypeWHOIS, references[1].Type)
}

func TestExtractPreseeds_FiltersAnonymisedEmail(t *testing.T) {
	r := whois.Result{
		Domain: "texture.com",
		Tech: whois.Contact{
			Email: "texture.com-tech@anonymised.email",
		},
	}

	assert.Empty(t, extractPreseeds(r))
}

func TestExtractPreseeds_JustificationOmitsUnknownWhoisServer(t *testing.T) {
	r := whois.Result{
		Domain:     "example.com",
		Registrant: whois.Contact{Organization: "ACME-CORP"},
	}

	findings := extractPreseeds(r)

	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t,
		`WHOIS for domain "example.com" records "ACME-CORP" as the registrant contact company`,
		findings[0].Confidences[0].Justification)
}
