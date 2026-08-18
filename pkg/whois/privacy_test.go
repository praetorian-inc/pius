package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPrivacy(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		// Real companies — must NOT be flagged.
		{"real org", "Acme Corporation", false},
		{"real org lowercase", "globex holdings ag", false},
		{"real org with suffix", "Contoso Ltd.", false},
		{"real person", "John Smith", false},

		// Known privacy orgs — must be flagged.
		{"whoisguard", "WhoisGuard, Inc.", true},
		{"domains by proxy", "Domains By Proxy, LLC", true},
		{"withheld for privacy", "Privacy service provided by Withheld for Privacy ehf", true},

		// Privacy names — must be flagged.
		{"redacted for privacy", "REDACTED FOR PRIVACY", true},
		{"domain administrator", "Domain Administrator", true},

		// Email suffixes — must be flagged.
		{"proxy email", "abc123@withheldforprivacy.com", true},
		{"anonymised email", "texture.com-tech@anonymised.email", true},
		{"markmonitor email", "domains@markmonitor.com", true},
		{"bluehost privacy", "user@bluehostprivatename.com", true},

		// Real emails — must NOT be flagged.
		{"real email", "admin@example.com", false},
		{"real email 2", "support@company.org", false},

		// Marker tokens.
		{"redacted text", "DATA REDACTED", true},
		{"not disclosed", "Not Disclosed", true},

		// Edge: "privacy" alone is NOT a marker (legitimate orgs use it).
		{"privacy in name", "Privacy International", false},

		// Edge: company with "redacted" substring but not as a token.
		{"redactron systems", "Redactron Systems", false},

		// Empty.
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsPrivacy(tt.value), "IsPrivacy(%q)", tt.value)
		})
	}
}

func TestNormalizePrivacy(t *testing.T) {
	assert.Equal(t, "", NormalizePrivacy(""))
	assert.Equal(t, PrivacyRedaction, NormalizePrivacy("REDACTED FOR PRIVACY"))
	assert.Equal(t, "Acme Corporation", NormalizePrivacy("Acme Corporation"))
}
