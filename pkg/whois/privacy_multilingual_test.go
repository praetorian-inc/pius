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
		{"ja", "データ保護"},
		{"ja", "非公開"},
		{"ja", "情報非開示"},
		{"zh", "隐私保护"},
		{"zh", "已隐藏"},
		{"zh", "不公开"},
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
		"隐私保护 / Privacy Protection",
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
	assert.Equal(t, PrivacyRedaction, NormalizePrivacy("データ保護"))
	assert.Equal(t, PrivacyRedaction, NormalizePrivacy("Данные защищены"))
	assert.Equal(t, "Société Générale", NormalizePrivacy("Société Générale"))
}

// TestCorroborateTreatsLocalLanguageRedactionAsUnverifiable proves the ranking
// consequence. Corroborate short-circuits to "unverifiable" for a privacy value;
// before this change a local-language redaction reached OrgSimilarity instead,
// where it scored ~0 against any real query org and returned "mismatch" — the
// de-ranking ENG-5420 describes.
func TestCorroborateTreatsLocalLanguageRedactionAsUnverifiable(t *testing.T) {
	for _, redacted := range []string{"Données protégées", "データ保護", "Скрыто"} {
		assert.Equalf(t, "unverifiable", Corroborate("Acme Corp", redacted),
			"masked registrant %q must be unverifiable, not mismatch", redacted)
	}

	// Control: a genuine unrelated org is still a mismatch, so the change above
	// did not simply collapse every comparison into "unverifiable".
	assert.Equal(t, "mismatch", Corroborate("Acme Corp", "Société Générale"))
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
