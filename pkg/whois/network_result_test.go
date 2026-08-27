package whois

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkResult_Normalize(t *testing.T) {
	result := NetworkResult{
		Query:        " 8.8.8.8 ",
		StartAddress: " 8.8.8.0 ",
		EndAddress:   " 8.8.8.255 ",
		Handle:       " NET-8-8-8-0-1 ",
		Name:         " EXAMPLE-NET ",
		Type:         " DIRECT ALLOCATION ",
		Status:       []string{" active ", " "},
		Country:      " US ",
		ParentHandle: " PARENT-1 ",
		Registry:     " whois.example.com ",
		Server:       " rdap.example.com ",
		RDAPServer:   " rdap.example.com ",
		WhoisServer:  " whois.example.com ",
		Contacts: []NetworkContact{
			{
				Handle: " CONTACT-1 ",
				Roles:  []string{" registrant ", " "},
				Status: []string{" validated ", " "},
				Kind:   " org ",
				Direct: true,
				Contact: Contact{
					Organization: " Example Networks ",
					Name:         " ",
					Email:        " admin@example.com ",
					Country:      " US ",
				},
			},
			{
				Roles:  []string{" customer "},
				Kind:   " org ",
				Direct: true,
				Contact: Contact{
					Organization: " REDACTED FOR PRIVACY ",
					Email:        " domains@markmonitor.com ",
				},
			},
			{Contact: Contact{Name: " "}},
		},
		Sources: []string{" rdap ", " ", " whois "},
		Raw:     " raw response \n",
	}

	result.Normalize()

	assert.Equal(t, NetworkResult{
		Query:        "8.8.8.8",
		StartAddress: "8.8.8.0",
		EndAddress:   "8.8.8.255",
		Handle:       "NET-8-8-8-0-1",
		Name:         "EXAMPLE-NET",
		Type:         "DIRECT ALLOCATION",
		Status:       []string{"active"},
		Country:      "US",
		ParentHandle: "PARENT-1",
		Registry:     "whois.example.com",
		Server:       "rdap.example.com",
		RDAPServer:   "rdap.example.com",
		WhoisServer:  "whois.example.com",
		Contacts: []NetworkContact{
			{
				Handle: "CONTACT-1",
				Roles:  []string{"registrant"},
				Status: []string{"validated"},
				Kind:   "org",
				Direct: true,
				Contact: Contact{
					Organization: "Example Networks",
					Email:        "admin@example.com",
					Country:      "US",
				},
			},
			{
				Roles:  []string{"customer"},
				Kind:   "org",
				Direct: true,
				Contact: Contact{
					Organization: PrivacyRedaction,
					Email:        PrivacyRedaction,
				},
			},
		},
		Sources: []string{"rdap", "whois"},
		Raw:     " raw response \n",
	}, result)

	normalized := result
	result.Normalize()
	assert.Equal(t, normalized, result)
}

func TestNetworkContact_IdentityPrefersRealNameOverPrivateOrganization(t *testing.T) {
	contact := NetworkContact{
		Kind: "org",
		Contact: Contact{
			Organization: PrivacyRedaction,
			Name:         "Example Networks",
		},
	}

	assert.Equal(t, "Example Networks", contact.Identity())
}

func TestNetworkContact_JSONFlattensContact(t *testing.T) {
	contact := NetworkContact{
		Handle: "CONTACT-1",
		Roles:  []string{"registrant"},
		Kind:   "org",
		Direct: true,
		Contact: Contact{
			Organization: "Example Networks",
			Email:        "admin@example.com",
		},
	}

	encoded, err := json.Marshal(contact)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"handle":"CONTACT-1",
		"roles":["registrant"],
		"kind":"org",
		"direct":true,
		"organization":"Example Networks",
		"email":"admin@example.com"
	}`, string(encoded))

	var decoded NetworkContact
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, contact, decoded)
}
