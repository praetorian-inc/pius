package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResult_Clean(t *testing.T) {
	result := DomainResult{
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

	assert.Equal(t, DomainResult{
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

func TestResult_CleanAllowsProviderFallback(t *testing.T) {
	primary := DomainResult{
		Registrar:   " ",
		NameServers: []string{" "},
		Status:      []string{"\t"},
		Registrant:  Contact{Name: " "},
	}
	fallback := DomainResult{
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

func TestDomainResult_NormalizePopulatesDerivedFields(t *testing.T) {
	result := DomainResult{
		Registrant: Contact{
			Organization: "REDACTED FOR PRIVACY",
			Name:         "Jane Doe",
			Email:        "proxy@withheldforprivacy.com",
		},
		Admin: Contact{Email: "admin@example.com"},
	}

	result.Normalize()

	assert.Equal(t, "Jane Doe", result.RegistrantIdentity)
	assert.Equal(t, "admin@example.com", result.ContactEmail)
	assert.Equal(t, "administrative", result.ContactEmailRole)
}

func TestDomainResult_NormalizeDefaultsUnavailableContactEmailToRegistrantPrivacy(t *testing.T) {
	tests := []struct {
		name   string
		result DomainResult
	}{
		{name: "missing"},
		{name: "malformed", result: DomainResult{Registrant: Contact{Email: "not-an-email"}}},
		{name: "redacted", result: DomainResult{Tech: Contact{Email: "domains@markmonitor.com"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.result.Normalize()

			assert.Equal(t, PrivacyRedaction, test.result.ContactEmail)
			assert.Equal(t, "registrant", test.result.ContactEmailRole)
		})
	}
}

func TestDomainResult_MergeContactPrefersRealValues(t *testing.T) {
	private := Contact{
		Organization: PrivacyRedaction,
		Name:         PrivacyRedaction,
		Email:        PrivacyRedaction,
		Country:      PrivacyRedaction,
		Province:     PrivacyRedaction,
		City:         PrivacyRedaction,
		Street:       PrivacyRedaction,
		PostalCode:   PrivacyRedaction,
		Phone:        PrivacyRedaction,
	}
	fallback := Contact{
		Organization: "Fallback Inc.",
		Name:         "Jane Doe",
		Email:        "jane@example.com",
		Country:      "US",
		Province:     "Texas",
		City:         "Austin",
		Street:       "1 Main St",
		PostalCode:   "78701",
		Phone:        "+1-555-0100",
	}
	primary := DomainResult{Registrant: private}

	primary.Merge(DomainResult{Registrant: fallback})

	assert.Equal(t, fallback, primary.Registrant)
	assert.Equal(t, "Fallback Inc.", primary.RegistrantIdentity)
	assert.Equal(t, "jane@example.com", primary.ContactEmail)
	assert.Equal(t, "registrant", primary.ContactEmailRole)
}

func TestDomainResult_MergeContactPreservesPrimaryRealValues(t *testing.T) {
	primary := DomainResult{Registrant: Contact{Organization: "Primary Inc."}}

	primary.Merge(DomainResult{Registrant: Contact{Organization: "Fallback Inc."}})

	assert.Equal(t, "Primary Inc.", primary.Registrant.Organization)
	assert.Equal(t, "Primary Inc.", primary.RegistrantIdentity)
}
