package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResult_Normalize(t *testing.T) {
	result := Result{
		Domain:      " example.com ",
		Registrar:   " Example Registrar ",
		Created:     " 2020-01-01 ",
		Updated:     " 2025-01-01 ",
		Expiration:  " 2030-01-01 ",
		DNSSEC:      " signed ",
		WhoisServer: " whois.example.com ",
		Status:      []string{" active ", " ", "\t"},
		NameServers: []string{" ns1.example.com ", " ", " ns2.example.com "},
		Sources:     []string{" rdap ", "", " whois "},
		Registrant: Contact{
			Organization: " Example Inc. ",
			Name:         " ",
			Email:        " admin@example.com ",
		},
		Admin: Contact{Name: "REDACTED FOR PRIVACY"},
	}

	result.Normalize()

	assert.Equal(t, Result{
		Domain:      "example.com",
		Registrar:   "Example Registrar",
		Created:     "2020-01-01",
		Updated:     "2025-01-01",
		Expiration:  "2030-01-01",
		DNSSEC:      "signed",
		WhoisServer: "whois.example.com",
		Status:      []string{"active"},
		NameServers: []string{"ns1.example.com", "ns2.example.com"},
		Sources:     []string{"rdap", "whois"},
		Registrant: Contact{
			Organization: "Example Inc.",
			Email:        "admin@example.com",
		},
		Admin:              Contact{Name: PrivacyRedaction},
		RegistrantIdentity: "Example Inc.",
		ContactEmail:       "admin@example.com",
		ContactEmailRole:   "registrant",
	}, result)
}

func TestResult_NormalizeAllowsProviderFallback(t *testing.T) {
	primary := Result{
		Registrar:   " ",
		NameServers: []string{" "},
		Status:      []string{"\t"},
		Registrant:  Contact{Name: " "},
	}
	fallback := Result{
		Registrar:   "Fallback Registrar",
		NameServers: []string{"ns1.example.com"},
		Status:      []string{"active"},
		Registrant:  Contact{Name: "Jane Doe"},
	}

	primary.Normalize()
	fallback.Normalize()
	primary.Merge(fallback)

	assert.Equal(t, "Fallback Registrar", primary.Registrar)
	assert.Equal(t, []string{"ns1.example.com"}, primary.NameServers)
	assert.Equal(t, []string{"active"}, primary.Status)
	assert.Equal(t, "Jane Doe", primary.Registrant.Name)
	assert.Equal(t, "Jane Doe", primary.RegistrantIdentity)
}

func TestResult_NormalizePopulatesDerivedFields(t *testing.T) {
	result := Result{
		Domain:    "acme.cn",
		Registrar: "Example Registrar [Tag = EXAMPLE]",
		Registrant: Contact{
			Name:  "Acme Holdings Ltd.",
			Email: "proxy@withheldforprivacy.com",
		},
		Admin: Contact{Email: "admin@example.com"},
	}

	result.Normalize()

	assert.Empty(t, result.Registrant.Organization)
	assert.Equal(t, "Acme Holdings Ltd.", result.Registrant.Name)
	assert.Equal(t, "Acme Holdings Ltd.", result.RegistrantIdentity)
	assert.Equal(t, "EXAMPLE", result.Registrar)
	assert.Equal(t, PrivacyRedaction, result.Registrant.Email)
	assert.Equal(t, "admin@example.com", result.ContactEmail)
	assert.Equal(t, "administrative", result.ContactEmailRole)
}

func TestResult_NormalizePreservesPrivateContactEmail(t *testing.T) {
	result := Result{Tech: Contact{Email: "domains@markmonitor.com"}}

	result.Normalize()

	assert.Equal(t, PrivacyRedaction, result.ContactEmail)
	assert.Equal(t, "technical", result.ContactEmailRole)
}

func TestResult_MergeRecomputesDerivedFields(t *testing.T) {
	primary := Result{Registrant: Contact{Email: "proxy@withheldforprivacy.com"}}
	fallback := Result{Admin: Contact{Email: "admin@example.com"}}
	primary.Normalize()
	fallback.Normalize()

	primary.Merge(fallback)

	assert.Equal(t, "admin@example.com", primary.ContactEmail)
	assert.Equal(t, "administrative", primary.ContactEmailRole)
}

func TestResult_MergeContactPrefersRealValues(t *testing.T) {
	tests := []struct {
		name  string
		base  string
		other string
		want  string
	}{
		{name: "fills empty base", other: "Fallback Inc.", want: "Fallback Inc."},
		{name: "replaces privacy with real value", base: PrivacyRedaction, other: "Fallback Inc.", want: "Fallback Inc."},
		{name: "preserves privacy without fallback", base: PrivacyRedaction, want: PrivacyRedaction},
		{name: "preserves primary real value", base: "Primary Inc.", other: "Fallback Inc.", want: "Primary Inc."},
		{name: "ignores fallback privacy", base: "Primary Inc.", other: PrivacyRedaction, want: "Primary Inc."},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := Result{Registrant: Contact{Organization: test.base}}
			other := Result{Registrant: Contact{Organization: test.other}}

			base.Merge(other)

			assert.Equal(t, test.want, base.Registrant.Organization)
		})
	}
}
