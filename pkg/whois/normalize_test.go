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

		// Dotted legal suffixes used to survive tokenization as single-letter
		// tokens, which both hid the suffix from data.LegalSuffixes and padded
		// the denominator of strutil.TokenSimilarity. These three scored 0.25,
		// 0.50 and 0.33 respectively, landing them in the mismatch and
		// unverifiable bands.
		{"dotted suffix against longer org", "Acme L.L.C.", "Acme Holdings Group Division", "match"},
		{"dotted country prefix", "U.S. Steel Corp.", "US Steel", "match"},
		{"dotted two-letter suffix against longer org", "Globex S.A.", "Globex Worldwide Trading Group", "match"},
		// Control: scored 1.00 before the fix too. Pins that collapsing dotted
		// runs did not disturb the cases that already corroborated.
		{"dotted suffix against bare name", "Acme L.L.C.", "Acme", "match"},
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

	// Dotted acronym runs collapse before tokenizing, so the legal suffix is
	// recognized and stops diluting the score.
	assert.InDelta(t, 1.0, OrgSimilarity("Acme L.L.C.", "Acme Holdings Group Division"), 0.01)
	assert.InDelta(t, 1.0, OrgSimilarity("U.S. Steel Corp.", "US Steel"), 0.01)
}

func TestNormalizeOrg(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// A dotted run collapses to bare letters, so the legal suffix reaches
		// data.LegalSuffixes as one token ("llc", "sa") instead of arriving as
		// single letters that never match and then pad the token count.
		{"dotted legal suffix", "Acme L.L.C.", "acme"},
		{"undotted legal suffix", "Acme LLC", "acme"},
		// "us" is not a legal suffix, so it survives as a content token — which
		// is what lets this match a plain "US Steel".
		{"dotted country prefix kept as content", "U.S. Steel Corp.", "us steel"},
		{"dotted two-letter suffix", "Globex S.A.", "globex"},
		{"undotted legal suffix without run", "Acme Inc.", "acme"},
		{"dotted acronym that is not a suffix", "A.B.C. Holdings", "abc holdings"},

		// Regression rows. The rule is restricted to runs of two or more
		// letter-period pairs; a blanket period strip would break each of these.
		// Keep them if the regex is ever "simplified".

		// Loosened to a blanket strip this merges across the period into the
		// single token "acmecorp", so "corp" never reaches the suffix list.
		{"period separating two words", "Acme.Corp", "acme"},
		// Same failure mode: a blanket strip yields "acmecom" rather than two
		// tokens, turning a match into a mismatch.
		{"domain-shaped org", "acme.com", "acme com"},
		// Pins the {2,} quantifier. "J." is a single letter-period pair followed
		// immediately by a letter, so relaxing {2,} to {1,} merges the initial
		// into the next word and collapses this to the one token "jcrew".
		{"single letter joined to a word", "J.Crew", "j crew"},
		// A lone initial is left alone and keeps its own "q" token. This is a
		// specification row, not a quantifier guard: Tokenize splits on the period
		// regardless, so deleting one only changes the result where it sits between
		// two alphanumerics. The J.Crew row above is what pins {2,}.
		{"single initial left intact", "John Q. Public", "john q public"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeOrg(tt.input))
		})
	}

	// The headline acceptance criterion: the dotted and undotted spellings must
	// not merely each be correct, they must collapse to the same string.
	t.Run("dotted and undotted spellings are equivalent", func(t *testing.T) {
		dotted := normalizeOrg("Acme L.L.C.")
		assert.Equal(t, normalizeOrg("Acme LLC"), dotted)
		assert.Equal(t, "acme", dotted)
	})
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
