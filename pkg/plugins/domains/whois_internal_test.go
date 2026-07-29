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
		name  string
		input string
		want  string
	}{
		{"already registrable", "example.com", "example.com"},
		{"one subdomain", "sub.example.com", "example.com"},
		{"deep subdomain", "deep.sub.example.com", "example.com"},
		{"uppercase normalized", "EXAMPLE.COM", "example.com"},
		{"trailing dot trimmed", "example.com.", "example.com"},
		{"whitespace trimmed", "  sub.example.com  ", "example.com"},
		{"empty", "", ""},
		{"bare hostname", "localhost", ""},

		// Multi-label ICANN suffixes. The previous last-two-labels heuristic
		// returned "co.uk" for every one of these, so the vendor was asked about a
		// public suffix instead of the customer's domain.
		{"multi-label suffix, registrable", "example.co.uk", "example.co.uk"},
		{"multi-label suffix, subdomain", "www.example.co.uk", "example.co.uk"},
		{"multi-label suffix, deep", "a.b.example.co.uk", "example.co.uk"},
		{"multi-label suffix alone", "co.uk", ""},
		{"tld alone", "com", ""},

		// Private PSL suffixes collapse to the provider's ICANN-level domain,
		// which is the only thing in the chain with a WHOIS record.
		{"cloudfront", "d2anv8h5waxwp1.cloudfront.net", "cloudfront.net"},
		{"heroku", "myapp.herokuapp.com", "herokuapp.com"},
		{"s3 bucket", "mybucket.s3.amazonaws.com", "amazonaws.com"},
		{"api gateway", "abc123.execute-api.us-east-1.amazonaws.com", "amazonaws.com"},

		// IPs are not domains.
		{"ipv4", "192.0.2.1", ""},
		{"ipv6", "2001:db8::1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rootDomain(tt.input), "rootDomain(%q)", tt.input)
		})
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
