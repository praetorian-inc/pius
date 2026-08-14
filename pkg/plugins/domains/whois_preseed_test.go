package domains

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/whois"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A preseed justification names the server that answered the WHOIS query, so a
// reviewer can retrace the claim to the record it came from.
func TestExtractPreseeds_JustificationNamesWhoisServer(t *testing.T) {
	r := whois.Result{
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
	r := whois.Result{
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
