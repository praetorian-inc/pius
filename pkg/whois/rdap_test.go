package whois

import (
	"testing"

	"github.com/openrdap/rdap"
	"github.com/stretchr/testify/assert"
)

func TestContactFromVCard_CleansIdentity(t *testing.T) {
	tests := []struct {
		name         string
		contactName  string
		organization string
		expected     Contact
	}{
		{
			name:         "trims identity",
			contactName:  " Jane Doe ",
			organization: " Example Inc. ",
			expected: Contact{
				Name:         "Jane Doe",
				Organization: "Example Inc.",
			},
		},
		{
			name:         "clears whitespace-only identity",
			contactName:  " ",
			organization: "\t",
			expected:     Contact{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcard := &rdap.VCard{Properties: []*rdap.VCardProperty{
				{Name: "fn", Type: "text", Value: tt.contactName},
				{Name: "org", Type: "text", Value: tt.organization},
			}}

			assert.Equal(t, tt.expected, contactFromVCard(vcard))
		})
	}
}
