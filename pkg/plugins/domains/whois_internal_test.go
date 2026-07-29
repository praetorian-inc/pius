package domains

import (
	"testing"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"", ""},
		{"localhost", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, rootDomain(tt.input), "rootDomain(%q)", tt.input)
	}
}

func TestExtractPreseeds_WithContacts(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "Acme Corp",
			Name:         "John Doe",
			Email:        "admin@acme.com",
		},
		Administrative: &whoisparser.Contact{
			Organization: "Acme Corp", // duplicate, should be deduped
			Name:         "Jane Smith",
			Email:        "not-an-email", // invalid, should be skipped
		},
	}

	findings := extractPreseeds(info, "whois")

	// Expect: company=Acme Corp, name=John Doe, email=admin@acme.com, name=Jane Smith
	// Acme Corp from Administrative is deduped
	require.Len(t, findings, 4)

	types := make(map[string][]string)
	for _, f := range findings {
		assert.Equal(t, plugins.FindingPreseed, f.Type)
		assert.Equal(t, "whois", f.Source)
		pt := f.Data["preseed_type"].(string)
		types[pt] = append(types[pt], f.Value)
	}

	assert.Equal(t, []string{"Acme Corp"}, types["whois+company"])
	assert.ElementsMatch(t, []string{"John Doe", "Jane Smith"}, types["whois+name"])
	assert.Equal(t, []string{"admin@acme.com"}, types["whois+email"])
}

func TestExtractPreseeds_NilContacts(t *testing.T) {
	info := whoisparser.WhoisInfo{}
	findings := extractPreseeds(info, "whois")
	assert.Empty(t, findings)
}

func TestExtractPreseeds_EmptyFields(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "",
			Name:         "",
			Email:        "",
		},
	}
	findings := extractPreseeds(info, "whois")
	assert.Empty(t, findings)
}

func TestExtractPreseeds_PrivacyGuardBlocksCompany(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "Domains By Proxy, LLC",
			Name:         "Registration Private",
			Email:        "proxy@domainsbyproxy.com",
		},
	}
	findings := extractPreseeds(info, "whois")
	for _, f := range findings {
		preseedType, _ := f.Data["preseed_type"].(string)
		assert.NotEqual(t, "whois+company", preseedType, "privacy guard org should be filtered")
	}
}

func TestExtractPreseeds_PrivacyGuardCaseInsensitive(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "DOMAINS BY PROXY, LLC",
		},
	}
	findings := extractPreseeds(info, "whois")
	for _, f := range findings {
		preseedType, _ := f.Data["preseed_type"].(string)
		assert.NotEqual(t, "whois+company", preseedType, "case-insensitive privacy guard check")
	}
}

func TestExtractPreseeds_LegitimateOrgNotFiltered(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "Acme Corporation",
		},
	}
	findings := extractPreseeds(info, "whois")
	require.Len(t, findings, 1)
	assert.Equal(t, "whois+company", findings[0].Data["preseed_type"])
	assert.Equal(t, "Acme Corporation", findings[0].Value)
}
