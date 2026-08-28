package whois

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRawDomainResult_NICChileFallback(t *testing.T) {
	result, err := parseRawDomainResult("example.cl", readDomainFixture(t, "nic_cl.raw"))

	require.NoError(t, err)
	assert.Equal(t, "Example Media LLC", result.Registrant.Name)
	assert.Equal(t, "Example Media LLC", result.RegistrantIdentity)
	assert.Empty(t, result.Registrant.Organization)
	assert.Equal(t, "Example Registrar", result.Registrar)
	assert.Equal(t, "2009-08-11 21:24:25 CLST", result.Created)
	assert.Equal(t, "2027-10-14 11:07:01 CLST", result.Expiration)
	assert.Equal(t, []string{"ns1.example.net", "ns2.example.net"}, result.NameServers)
	assert.Empty(t, result.Registrant.Email)
	assert.Empty(t, result.Admin.Email)
	assert.Empty(t, result.Tech.Email)
	assert.Empty(t, result.Billing.Email)
	assert.Empty(t, result.ContactEmail)
}

func TestParseRawDomainResult_AppliesISOCILFallback(t *testing.T) {
	const raw = `% registry record
domain: example.co.il

# holder record
descr: Example Ltd.
e-mail: admin AT example.com
`

	result, err := parseRawDomainResult("example.co.il", raw)

	require.NoError(t, err)
	assert.Equal(t, "Example Ltd.", result.Registrant.Organization)
	assert.Equal(t, "admin@example.com", result.Registrant.Email)
}

func TestApplyNICChileFallback_PreservesPrimaryValues(t *testing.T) {
	result := DomainResult{
		Domain:     "example.cl",
		Registrar:  "Primary Registrar",
		Registrant: Contact{Name: "Primary Registrant"},
	}

	applyRawDomainFallback(&result, newRawDomainRecord(readDomainFixture(t, "nic_cl.raw")))

	assert.Equal(t, "Primary Registrant", result.Registrant.Name)
	assert.Equal(t, "Primary Registrar", result.Registrar)
	assert.Equal(t, "2009-08-11 21:24:25 CLST", result.Created)
}

func TestParseRawDomainResult_PreservesGenericFields(t *testing.T) {
	result, err := parseRawDomainResult("example.co", readDomainFixture(t, "registry_co.raw"))

	require.NoError(t, err)
	assert.Equal(t, "Example Registrar, LLC", result.Registrar)
	assert.Equal(t, "2012-08-07T14:51:18.0Z", result.Created)
	assert.Equal(t, "2026-08-07T12:02:21.0Z", result.Updated)
	assert.Equal(t, "2027-08-06T23:59:59.0Z", result.Expiration)
	assert.Equal(t, "unsigned", result.DNSSEC)
	assert.Equal(t, []string{"ns1.example.net", "ns2.example.net"}, result.NameServers)
	assert.NotEmpty(t, result.Registrant.Email)
	assert.NotEmpty(t, result.Admin.Email)
	assert.NotEmpty(t, result.Tech.Email)
	assert.NotEmpty(t, result.Billing.Email)
	assert.Empty(t, result.RegistrantIdentity)
	assert.Empty(t, result.ContactEmail)
	assert.Empty(t, result.ContactEmailRole)
}

func TestParseRawDomainResult_RejectsNonDomainResponses(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		err     error
	}{
		{name: "registry access denied", fixture: "nic_ch_denied.raw", err: errRegistryAccessDenied},
		{name: "IANA bootstrap", fixture: "iana_no_referral.raw", err: errBootstrapDomainResponse},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := parseRawDomainResult("example.test", readDomainFixture(t, test.fixture))

			assert.ErrorIs(t, err, test.err)
			assert.Equal(t, DomainResult{}, result)
		})
	}
}

func readDomainFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "domain", name))
	require.NoError(t, err)
	return string(raw)
}
