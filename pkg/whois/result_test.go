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
}
