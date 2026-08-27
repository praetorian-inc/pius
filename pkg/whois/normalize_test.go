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

		// ENG-5172: a single-token pivot org merely CONTAINED in a longer resolved
		// registrant must not claim a match. {acme} vs {acme, enterprises} is
		// Jaccard 1/2 = 0.5, below the 0.60 floor, so it needs review. The old
		// containment metric divided by the shorter set and read this as 1.0.
		{"contained pivot does not match", "Acme", "Acme Enterprises LLC", "unverifiable"},
		{"contained pivot with descriptor", "Okta", "Okta Security Inc.", "unverifiable"},

		// The other half of ENG-5172: switching to Jaccard pushes that same
		// containment shape off the OTHER end. {walmart} vs {walmart, global,
		// enterprises, holdings} is 1/4 = 0.25, BELOW the 0.30 mismatch floor, so a
		// bare threshold would report a fully contained pivot as a MISMATCH — a
		// worse verdict than the unresolved case. Containment is
		// under-specification (a plausible subsidiary), not disagreement, so
		// TokenSetContained holds it at unverifiable.
		{"sparse containment is not a mismatch, pivot side", "Walmart", "Walmart Global Enterprises Holdings LLC", "unverifiable"},
		// Symmetric: the RESOLVED name is the less-specific one. Jaccard is 1/4
		// again and it is equally under-specified, so it equally must not mismatch.
		{"sparse containment is not a mismatch, resolved side", "Walmart Global Enterprises Holdings", "Walmart Inc.", "unverifiable"},

		// A single-token pivot that genuinely EQUALS the resolved org after suffix
		// stripping must still match — this is the case the fix must not break.
		{"single-token exact match still matches", "Praetorian", "Praetorian Inc.", "match"},

		// Sparse overlap with private tokens on BOTH sides is real disagreement, so
		// the mismatch arm stays reachable through the containment guard.
		// {alpha, bravo, charlie, delta, echo} vs {alpha, bravo, foxtrot, golf,
		// hotel, india}: 2 shared of 9 union = 0.222 < 0.30, and neither side is a
		// subset of the other.
		{"sparse non-contained overlap mismatches", "alpha bravo charlie delta echo", "alpha bravo foxtrot golf hotel india", "mismatch"},

		// Both sides reduce to nothing after legal-suffix stripping, so similarity
		// is undefined — unverifiable, never a mismatch.
		{"all-suffix orgs are unverifiable", "Co., Ltd.", "Acme Corp", "unverifiable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Corroborate(tt.pivot, tt.resolved))
		})
	}
}

func TestOrgSimilarity(t *testing.T) {
	// Legal suffixes stripped, then Jaccard over the distinct token sets. Both
	// sides here reduce to the single token {acme}, so these are equalities
	// scoring 1.0 — NOT containment cases. See below for those.
	assert.InDelta(t, 1.0, OrgSimilarity("Acme Corporation", "Acme Corp"), 0.01)
	assert.InDelta(t, 1.0, OrgSimilarity("Acme LLC", "Acme"), 0.01)
	assert.InDelta(t, 0.0, OrgSimilarity("Alpha", "Beta"), 0.01)
	assert.InDelta(t, 0.0, OrgSimilarity("", "Alpha"), 0.01)

	// ENG-5172: containment is no longer scored as identity. Under the previous
	// containment metric every one of these returned 1.0.
	assert.InDelta(t, 0.5, OrgSimilarity("Acme", "Acme Enterprises"), 0.01)
	assert.InDelta(t, 0.25, OrgSimilarity("Walmart", "Walmart Global Enterprises Holdings"), 0.01)
	// Symmetric in its arguments.
	assert.InDelta(t, 0.25, OrgSimilarity("Walmart Global Enterprises Holdings", "Walmart"), 0.01)

	// An all-suffix org has no comparable tokens left, so similarity is 0 rather
	// than a spurious match on the shared "ltd"/"corp" tokens.
	assert.InDelta(t, 0.0, OrgSimilarity("Co., Ltd.", "Acme Corp"), 0.01)
}

func TestRegistrantOrg(t *testing.T) {
	assert.Equal(t, "Acme Corp", RegistrantOrg(
		Contact{Organization: "Acme Corp", Name: "Domain Admin"},
		"example.com",
	))
	assert.Empty(t, RegistrantOrg(Contact{Organization: "DIDEP2435-002435"}, "example.se"))
}

func TestRegistrantIdentity(t *testing.T) {
	tests := []struct {
		name    string
		contact Contact
		want    string
	}{
		{
			name:    "prefers organization",
			contact: Contact{Organization: "Acme Corp", Name: "Domain Admin"},
			want:    "Acme Corp",
		},
		{
			name:    "falls back to name",
			contact: Contact{Name: "John Smith"},
			want:    "John Smith",
		},
		{
			name: "prefers real name over private organization",
			contact: Contact{
				Organization: PrivacyRedaction,
				Name:         "John Smith",
			},
			want: "John Smith",
		},
		{
			name:    "preserves privacy",
			contact: Contact{Organization: PrivacyRedaction},
			want:    PrivacyRedaction,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, RegistrantIdentity(test.contact))
		})
	}
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
