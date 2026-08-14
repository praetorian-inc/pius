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

		// ENG-5393: dotted legal suffixes survive tokenization as single-letter
		// tokens ("L.L.C." arrives as ["l","l","c"]), so the suffix never reaches
		// data.LegalSuffixes and is never stripped. Those leftover letters are
		// private tokens on ONE side only, which both depresses the Jaccard score
		// AND defeats the TokenSetContained guard — so these pairs returned an
		// affirmative "mismatch", the worst available verdict, for two orgs that
		// merely differ in specificity. Collapsing the dotted run first turns that
		// false contradiction into an honest "unverifiable".
		//
		// {acme} vs {acme, holdings, group, division} is Jaccard 1/4 = 0.25 — still
		// under the 0.60 match floor, and correctly so: the fix removes the false
		// mismatch, it does not manufacture a match out of a containment. Without
		// the collapse this scored 1/6 = 0.167 with a stray "l"/"c" on the pivot
		// side, so it read as "mismatch".
		{"dotted suffix against longer org is unverifiable, not a mismatch", "Acme L.L.C.", "Acme Holdings Group Division", "unverifiable"},
		// Same shape with a two-letter suffix: 1/6 = 0.167 "mismatch" before, 1/4 =
		// 0.25 "unverifiable" after.
		{"dotted two-letter suffix against longer org is unverifiable", "Globex S.A.", "Globex Worldwide Trading Group", "unverifiable"},

		// Where the two sides really are the same org, the collapse does promote
		// the verdict to "match". "us" is not a legal suffix so it survives as a
		// content token, leaving {us, steel} on both sides — Jaccard 1.0. Without
		// the collapse the pivot is {u, s, steel} against {us, steel}: 1/4 = 0.25,
		// non-contained, i.e. "mismatch".
		{"dotted country prefix matches its undotted spelling", "U.S. Steel Corp.", "US Steel", "match"},
		// Both sides reduce to {acme}. Without the collapse the pivot is
		// {acme, l, c} against {acme}: 1/3 = 0.333, which is contained-adjacent
		// enough to land on "unverifiable" rather than "mismatch" — so this row
		// pins unverifiable -> match, not mismatch -> match.
		{"dotted suffix against bare name", "Acme L.L.C.", "Acme", "match"},

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

	// ENG-5393: collapsing the dotted run lets the legal suffix be stripped, so
	// the leftover single letters stop counting as distinguishing tokens. This is
	// a containment pair, not an equality — {acme} vs {acme, holdings, group,
	// division} is 1/4 = 0.25. Before the collapse it was 1/6 = 0.167.
	assert.InDelta(t, 0.25, OrgSimilarity("Acme L.L.C.", "Acme Holdings Group Division"), 0.01)
	// A genuine equality: "us" is not a legal suffix, so both sides reduce to
	// {us, steel} and score 1.0. Before the collapse this was 1/4 = 0.25.
	assert.InDelta(t, 1.0, OrgSimilarity("U.S. Steel Corp.", "US Steel"), 0.01)
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

func TestNormalizeOrgTokens(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// A dotted run collapses to bare letters, so the legal suffix reaches
		// data.LegalSuffixes as one token ("llc", "sa") instead of arriving as
		// single letters that never match and then linger as private tokens.
		{"dotted legal suffix", "Acme L.L.C.", []string{"acme"}},
		{"undotted legal suffix", "Acme LLC", []string{"acme"}},
		// "us" is not a legal suffix, so it survives as a content token — which
		// is what lets this match a plain "US Steel".
		{"dotted country prefix kept as content", "U.S. Steel Corp.", []string{"us", "steel"}},
		{"dotted two-letter suffix", "Globex S.A.", []string{"globex"}},
		{"undotted legal suffix without run", "Acme Inc.", []string{"acme"}},
		{"dotted acronym that is not a suffix", "A.B.C. Holdings", []string{"abc", "holdings"}},

		// Review findings (ENG-5393). Both of these are why the pattern ends on
		// `[a-z]\b` rather than counting letter-period pairs with `{2,}`.

		// A two-letter suffix written WITHOUT its trailing period carries only one
		// period, so a `{2,}` letter-period quantifier skips the run entirely and
		// the suffix is never stripped — leaving ["globex","s","a"], the exact
		// defect this ticket exists to fix. The closing letter needs no period of
		// its own, so the bounded form collapses it.
		{"dotted two-letter suffix without trailing period", "Globex S.A", []string{"globex"}},
		// Without a right-hand boundary the run runs on into the following word
		// and yields the single token "usarmy". Ending the match on a letter that
		// ends a word stops the run at "U.S" and leaves ".Army" for Tokenize.
		{"dotted prefix glued to a following word", "U.S.Army", []string{"us", "army"}},

		// Regression rows. The rule is restricted to dotted acronym runs; a
		// blanket period strip would break each of these. Keep them if the regex
		// is ever "simplified".

		// Loosened to a blanket strip this merges across the period into the
		// single token "acmecorp", so "corp" never reaches the suffix list.
		{"period separating two words", "Acme.Corp", []string{"acme"}},
		// Same failure mode: a blanket strip yields "acmecom" rather than two
		// tokens.
		{"domain-shaped org", "acme.com", []string{"acme", "com"}},
		// Pins the trailing `[a-z]\b`. "J." is a letter-period pair, but the "C"
		// that follows is glued to "rew", so there is no word boundary for the
		// run to close on and no second letter-period pair to consume — the match
		// fails and the period survives as a separator. Drop the `\b` (or the
		// closing `[a-z]`) and this collapses to the one token "jcrew".
		{"single letter joined to a word", "J.Crew", []string{"j", "crew"}},
		// A lone initial is left alone and keeps its own "q" token: "Q." is
		// followed by a space, so again there is no letter on a word boundary to
		// close the run on.
		{"single initial left intact", "John Q. Public", []string{"john", "q", "public"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeOrgTokens(tt.input))
		})
	}

	// The headline acceptance criterion: the dotted and undotted spellings must
	// not merely each be correct, they must reduce to the same token set.
	t.Run("dotted and undotted spellings are equivalent", func(t *testing.T) {
		dotted := normalizeOrgTokens("Acme L.L.C.")
		assert.Equal(t, normalizeOrgTokens("Acme LLC"), dotted)
		assert.Equal(t, []string{"acme"}, dotted)
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
