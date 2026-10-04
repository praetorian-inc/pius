package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsPrivacyDetectsLocalLanguageRedaction is the acceptance test for
// ENG-5420. Each case is a redaction wording in the local language of a registry
// that answers in that language — NOT accented English.
//
// The distinction is the whole point of this change and is worth stating
// explicitly, because the first attempt at this fix (PR #131) got it wrong:
// diacritic folding alone passes a suite built from "RÉDACTED" / "MASKÉD" /
// "WITHHÉLD FOR PRIVACY" while fixing 0 of the wordings below. Accented English
// is not a thing registries emit; folding it proves only that the folder works.
// A test here must name a wording a registrar could actually return.
func TestIsPrivacyDetectsLocalLanguageRedaction(t *testing.T) {
	tests := []struct{ lang, value string }{
		{"fr", "Données protégées"},
		{"fr", "Non divulgué"},
		{"fr", "Informations masquées"},
		{"de", "Nicht offengelegt"},
		{"de", "Nicht veröffentlicht"},
		{"de", "Daten geschützt nach DSGVO"},
		{"de", "Geschützt nach DSGVO"},
		{"de", "Geschwärzt"},
		{"es", "Datos protegidos"},
		{"es", "No divulgado"},
		{"es", "Ocultado"},
		{"pt", "Dados protegidos"},
		{"pt", "Não divulgado"},
		{"it", "Dati protetti"},
		{"it", "Non divulgato"},
		{"it", "Oscurato"},
		{"nl", "Niet vrijgegeven"},
		{"nl", "Gegevens beschermd"},
		{"nl", "Afgeschermd"},
		{"pl", "Dane zastrzeżone"},
		{"pl", "Dane ukryte"},
		{"tr", "Gizlenmiş"},
		{"no", "Skjult av personvernhensyn"},
		{"sv", "Skyddade uppgifter"},
		{"cs", "Skryto"},
		{"cs", "Chráněná data"},
		{"is", "Þagnarskylda"},
		{"el", "Απόκρυψη δεδομένων"},
		{"ru", "Данные защищены"},
		{"ru", "Скрыто"},
		{"ru", "Не раскрывается"},
		{"ja", "非公開"},
		{"ja", "情報非開示"},
		{"ja", "データ保護のため非公開"},
		{"zh", "已隐藏"},
		{"zh", "不公开"},
		{"zh", "登记人信息不公开"},
		{"ko", "비공개"},
	}

	for _, tt := range tests {
		t.Run(tt.lang+"/"+tt.value, func(t *testing.T) {
			assert.Truef(t, IsPrivacy(tt.value),
				"%s redaction wording %q must be detected as privacy (ENG-5420)",
				tt.lang, tt.value)
		})
	}
}

// TestIsPrivacyDetectsRedactionEmbeddedInLongerValue covers wordings that arrive
// with surrounding text, which is the common shape — a registry rarely returns
// the bare marker.
func TestIsPrivacyDetectsRedactionEmbeddedInLongerValue(t *testing.T) {
	values := []string{
		"Données protégées — RGPD art. 6",
		"Titulaire : non divulgué",
		"Daten geschützt (DSGVO)",
		"データ保護のため非公開",
		"登记人信息不公开 / Registrant withheld",
		"Данные защищены в соответствии с законом",
	}
	for _, v := range values {
		assert.Truef(t, IsPrivacy(v), "%q must be detected as privacy", v)
	}
}

// TestIsPrivacyDoesNotFlagGenuineNonASCIIOrgs is the false-positive guard, and
// the reason the vocabulary favours multi-word phrases over bare adjectives. A
// wrong entry here rewrites a real registrant to PrivacyRedaction, which is a
// worse failure than the miss this change fixes.
func TestIsPrivacyDoesNotFlagGenuineNonASCIIOrgs(t *testing.T) {
	genuine := []string{
		// Latin-script with diacritics.
		"Société Générale",
		"Müller GmbH",
		"Ørsted A/S",
		"Citroën Group",
		"Nestlé S.A.",
		"Škoda Auto a.s.",
		"Ångström AB",
		"Peñaflor S.A.",
		"Łódź Software sp. z o.o.",
		"Þór Fisheries hf.",
		"Straßenbau Schmidt GmbH",
		"Æther Labs Ltd",
		"François Première Holdings",
		// Words that are near-misses for vocabulary entries but not markers.
		"Datos Solutions S.L.",         // "datos" without "protegidos"
		"Protégé Consulting",           // folds to "protege", not "protegees"
		"Beschermde Natuurgebieden",    // "beschermde", not "gegevens beschermd"
		"Prawa Zastrzeżone Sp. z o.o.", // "zastrzezone" without "dane"
		"Skyddad Verkstad AB",          // "skyddad" without "uppgifter"
		"Geschützte Werkstätten GmbH",  // "geschutzte", not "geschutzt nach"
		// Non-Latin genuine orgs.
		"Яндекс",
		"株式会社日立製作所",
		"腾讯科技",
		"삼성전자",
		"Ελληνικά Ταχυδρομεία",
	}
	for _, org := range genuine {
		assert.Falsef(t, IsPrivacy(org),
			"%q is a genuine organization and must NOT be flagged as privacy", org)
	}
}

// TestNormalizePrivacyCollapsesLocalLanguageRedaction proves the consequence,
// not just the predicate. IsPrivacy returning true is only useful if the value
// actually collapses to the PrivacyRedaction sentinel that downstream consumers
// branch on — this is the ENG-5420 AC that survived the reverse-whois refactor
// (the original AC named resolveWithFallback, which no longer exists).
func TestNormalizePrivacyCollapsesLocalLanguageRedaction(t *testing.T) {
	assert.Equal(t, PrivacyRedaction, NormalizePrivacy("Données protégées"))
	assert.Equal(t, PrivacyRedaction, NormalizePrivacy("データ保護のため非公開"))
	assert.Equal(t, PrivacyRedaction, NormalizePrivacy("Данные защищены"))
	assert.Equal(t, "Société Générale", NormalizePrivacy("Société Générale"))

	// A CJK company name must survive intact — collapsing it to the sentinel
	// destroys the registrant identity the pipeline exists to resolve.
	assert.Equal(t, "データ保護株式会社", NormalizePrivacy("データ保護株式会社"))
}

// TestCorroborateTreatsLocalLanguageRedactionAsUnverifiable proves the ranking
// consequence. Corroborate short-circuits to "unverifiable" for a privacy value;
// before this change a local-language redaction reached OrgSimilarity instead,
// where it scored ~0 against any real query org and returned "mismatch" — the
// de-ranking ENG-5420 describes.
func TestCorroborateTreatsLocalLanguageRedactionAsUnverifiable(t *testing.T) {
	for _, redacted := range []string{"Données protégées", "非公開", "Скрыто"} {
		assert.Equalf(t, "unverifiable", Corroborate("Acme Corp", redacted),
			"masked registrant %q must be unverifiable, not mismatch", redacted)
	}

	// Control: a genuine unrelated org is still a mismatch, so the change above
	// did not simply collapse every comparison into "unverifiable".
	assert.Equal(t, "mismatch", Corroborate("Acme Corp", "Société Générale"))
}

// TestMarkerPhrasesRequireCompleteTokenRuns covers a boundary bug that predates
// this change but which this change would have widened from 2 phrases to 25.
//
// The phrase pass used strings.Contains over the joined token stream, which
// anchors neither end of the run: "Data ProtectedX" joins to "data protectedx"
// and matched the {"data", "protected"} phrase on a prefix of its final token.
// Phrases are the vocabulary's safest entries precisely because a multi-word run
// cannot collide with a trading name by accident — unanchored matching threw
// that away.
// The boundary property is asserted on hasMarkerToken rather than IsPrivacy,
// because the English collisions are ALSO caught by earlier tiers and would
// pass this test for the wrong reason: "Data ProtectedX" matches Tier 2's
// substring pass against the "data protected" entry in privacy_orgs.txt, and
// "Not DisclosedFoo" matches Tier 0's prefix pass. Both are deliberate
// (privacy orgs append per-customer suffixes like "(customer 12345)"), both are
// out of scope here, and both would mask a regression in the phrase pass.
// End-to-end coverage uses non-English phrases, which no other tier knows.
func TestMarkerPhrasesRequireCompleteTokenRuns(t *testing.T) {
	collisions := []string{
		"data protectedx",  // trailing collision on the final token
		"xdata protected",  // leading collision on the first token
		"not disclosedfoo", //
		"donnees protegeesxyz",
		"datos protegidossa",
	}
	for _, v := range collisions {
		assert.Falsef(t, hasMarkerToken(v),
			"%q matches a marker phrase only as a token prefix/suffix and must "+
				"not be flagged by the phrase pass", v)
	}

	// Control: the genuine phrases still match, so anchoring did not simply
	// disable the phrase pass.
	for _, v := range []string{"data protected", "not disclosed", "donnees protegees"} {
		assert.Truef(t, hasMarkerToken(v), "%q is a genuine marker phrase", v)
	}

	// End-to-end, on phrases only the marker pass can match — no earlier tier
	// carries the non-English vocabulary, so IsPrivacy here is attributable.
	assert.False(t, IsPrivacy("Dane zastrzezoneX"))
	assert.False(t, IsPrivacy("Datos protegidosSA"))
	assert.True(t, IsPrivacy("Dane zastrzeżone"))
	assert.True(t, IsPrivacy("Datos protegidos"))
}

// TestCJKCompanyNamesAreNotFlagged covers the second half of the containment
// pass's safety argument. The no-Latin invariant makes Latin trading names immune
// to substring matching but says nothing about CJK ones, which collide just as
// readily — and in Japanese "非公開会社" is the legal term for a close corporation,
// so the collision is with the vocabulary's own entries.
func TestCJKCompanyNamesAreNotFlagged(t *testing.T) {
	companies := []string{
		"データ保護株式会社",     // "Data Protection Inc." — a plausible real name
		"非公開会社",         // legal term for a close corporation
		"隐私保护科技有限公司",    // "Privacy Protection Technology Co. Ltd."
		"비공개 주식회사",      // "… Co., Ltd."
		"個人情報保護法人",      // "personal data protection" corporate body
		"情報非開示センター株式会社", // marker term inside a company name
	}
	for _, c := range companies {
		assert.Falsef(t, IsPrivacy(c),
			"%q is a CJK company name and must NOT be flagged as privacy", c)
	}

	// Control: the same marker terms without a company form still fire, so the
	// guard suppresses only trading names.
	for _, v := range []string{"非公開", "已隐藏", "비공개", "データ保護のため非公開"} {
		assert.Truef(t, IsPrivacy(v), "%q is a bare redaction marker", v)
	}
}

// TestMarkerMatchingStillRequiresWholeTokens re-asserts the ENG-5404 guarantee
// against the new tokenizer. Latin marker matching remains whole-token, so a
// real name that merely contains a marker as a fragment is not flagged.
func TestMarkerMatchingStillRequiresWholeTokens(t *testing.T) {
	for _, org := range []string{
		"Redactron Systems",
		"Privacy International",
		"Maskell & Sons",
		"Withheldon Consulting",
	} {
		assert.Falsef(t, IsPrivacy(org),
			"%q contains a marker only as a fragment and must not be flagged", org)
	}
}
