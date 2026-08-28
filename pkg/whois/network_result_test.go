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
			{
				Roles: []string{" technical "},
				Contact: Contact{
					Phone:  " +1-555-0100 ",
					Street: " 1 Main St ",
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
			{
				Roles: []string{"technical"},
				Contact: Contact{
					Phone:  "+1-555-0100",
					Street: "1 Main St",
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

func TestNetworkResult_MergePreservesDistinctPartialContacts(t *testing.T) {
	result := NetworkResult{Contacts: []NetworkContact{{
		Roles:   []string{"technical"},
		Contact: Contact{Phone: "+1-555-0100"},
	}}}

	result.Merge(NetworkResult{Contacts: []NetworkContact{{
		Roles:   []string{"technical"},
		Contact: Contact{Phone: "+1-555-0101"},
	}}})

	require.Len(t, result.Contacts, 2)
	assert.Equal(t, "+1-555-0100", result.Contacts[0].Phone)
	assert.Equal(t, "+1-555-0101", result.Contacts[1].Phone)
}

func TestNetworkContact_IsEmptyPreservesPartialEvidence(t *testing.T) {
	tests := []struct {
		name    string
		contact NetworkContact
		empty   bool
	}{
		{name: "empty", contact: NetworkContact{}, empty: true},
		{name: "phone only", contact: NetworkContact{Contact: Contact{Phone: "+1-555-0100"}}},
		{name: "address only", contact: NetworkContact{Contact: Contact{Street: "1 Main St"}}},
		{name: "status only", contact: NetworkContact{Status: []string{"private"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.empty, test.contact.IsEmpty())
		})
	}
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
