package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRootDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Standard domains.
		{"www.example.com", "example.com"},
		{"sub.domain.example.com", "example.com"},
		{"example.com", "example.com"},

		// ccTLDs.
		{"example.co.uk", "example.co.uk"},
		{"sub.example.co.il", "example.co.il"},
		{"example.com.br", "example.com.br"},

		// Cloud infrastructure — private PSL suffixes should walk up to ICANN root.
		{"mybucket.s3.amazonaws.com", "amazonaws.com"},
		{"ec2-1-2-3-4.us-east-1.compute.amazonaws.com", "amazonaws.com"},
		{"myapp.us-east-1.elasticbeanstalk.com", "elasticbeanstalk.com"},
		{"d1234.cloudfront.net", "cloudfront.net"},
		{"myapp.azurewebsites.net", "azurewebsites.net"},
		{"myapp.herokuapp.com", "herokuapp.com"},

		// IPs are not domains.
		{"192.168.1.1", ""},
		{"10.0.0.1", ""},

		// Edge cases.
		{"", ""},
		{"localhost", ""},
		{"  example.com  ", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, RootDomain(tt.input))
		})
	}
}

func TestCorroborate(t *testing.T) {
	tests := []struct {
		name     string
		pivot    string
		resolved string
		want     string
	}{
		{"exact match", "Acme Corp", "Acme Corp", "match"},
		{"match with legal suffix", "Acme Corporation", "Acme Corp", "match"},
		{"mismatch", "Acme Corporation", "Globex Inc.", "mismatch"},
		{"privacy resolved", "Acme Corp", "REDACTED FOR PRIVACY", "unverifiable"},
		{"empty resolved", "Acme Corp", "", "unverifiable"},
		{"empty pivot", "", "Acme Corp", ""},
		{"unrelated orgs", "Alpha Holdings AG", "Beta Systems AG", "mismatch"},
		{"same name different suffix", "Acme LLC", "Acme", "match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Corroborate(tt.pivot, tt.resolved))
		})
	}
}

func TestOrgSimilarity(t *testing.T) {
	// Legal suffixes stripped, then token overlap.
	assert.InDelta(t, 1.0, OrgSimilarity("Acme Corporation", "Acme Corp"), 0.01)
	assert.InDelta(t, 1.0, OrgSimilarity("Acme LLC", "Acme"), 0.01)
	assert.InDelta(t, 0.0, OrgSimilarity("Alpha", "Beta"), 0.01)
	assert.InDelta(t, 0.0, OrgSimilarity("", "Alpha"), 0.01)
}

func TestRegistrantOrg(t *testing.T) {
	// Normal: org field present.
	c := Contact{Organization: "Acme Corp", Name: "Domain Admin"}
	assert.Equal(t, "Acme Corp", RegistrantOrg(c, "example.com"))

	// ccTLD name promotion: .cn puts holder in the Name field.
	c2 := Contact{Name: "Acme Holdings Ltd."}
	assert.Equal(t, "Acme Holdings Ltd.", RegistrantOrg(c2, "acme.cn"))

	// No org, no name promotion for .com.
	c3 := Contact{Name: "John Smith"}
	assert.Equal(t, "", RegistrantOrg(c3, "example.com"))
}

func TestContactEmail(t *testing.T) {
	r := Result{
		Registrant: Contact{Email: "admin@example.com"},
		Admin:      Contact{Email: "tech@example.com"},
	}
	email, proxy := ContactEmail(r)
	assert.Equal(t, "admin@example.com", email)
	assert.False(t, proxy)

	// Privacy email in registrant, real in admin.
	r2 := Result{
		Registrant: Contact{Email: "proxy@withheldforprivacy.com"},
		Admin:      Contact{Email: "real@example.com"},
	}
	email2, proxy2 := ContactEmail(r2)
	assert.Equal(t, "real@example.com", email2)
	assert.True(t, proxy2)

	// All privacy.
	r3 := Result{
		Registrant: Contact{Email: "proxy@withheldforprivacy.com"},
	}
	email3, proxy3 := ContactEmail(r3)
	assert.Equal(t, "", email3)
	assert.True(t, proxy3)
}

func TestIsPlausibleDomain(t *testing.T) {
	assert.True(t, IsPlausibleDomain("example.com"))
	assert.True(t, IsPlausibleDomain("sub.example.co.uk"))
	assert.True(t, IsPlausibleDomain("xn--nxasmq6b.com")) // punycode is plausible
	assert.False(t, IsPlausibleDomain(""))
	assert.False(t, IsPlausibleDomain("nodot"))
	assert.False(t, IsPlausibleDomain("has space.com"))
	assert.False(t, IsPlausibleDomain("http://example.com"))
}

func TestNormalizeRegistrar(t *testing.T) {
	assert.Equal(t, "Example Registrar Ltd.", NormalizeRegistrar("Example Registrar Ltd."))
	assert.Equal(t, "NOMINET", NormalizeRegistrar("Some Registrar [Tag = NOMINET]"))
	assert.Equal(t, "Bare", NormalizeRegistrar("Bare [Tag = ]"))
}
