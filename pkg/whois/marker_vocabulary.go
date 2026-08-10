package whois

// Redaction-marker vocabulary.
//
// This is the load-bearing half of ENG-5420. The ticket attributed non-ASCII
// redaction wordings escaping detection to strutil.Tokenize keeping only ASCII
// [a-z0-9], but the tokenizer is not what blocks the match: this vocabulary was
// English-only, so a French registrar's "Données protégées" failed to match
// whether it arrived shattered ([donn, es, prot, g, es]) or intact
// ([donnees, protegees]). Repairing tokenization alone fixes 0 of 18 real
// local-language wordings; it rescues only accented English ("RÉDACTED"), which
// no registry emits. Normalization (marker_normalize.go) is necessary but only
// so that the entries below can be reached.
//
// ── Review status ────────────────────────────────────────────────────────────
// The non-English entries are conventional dictionary renderings of the
// redaction wordings a registry in each locale would plausibly emit. They are
// NOT transcribed from observed registrar output: pius's five embedded
// denylists contain zero non-ASCII bytes, so no local-language wording has yet
// been captured in this codebase. Prevalence therefore remains unmeasured, and
// two standards actively push against this class existing at all — RFC 9537
// forbids placeholder text in RDAP field values outright ("The use of
// placeholder text for the values of the RDAP fields, such as 'XXXX', MUST NOT
// be used"), and ICANN's Temporary Specification requires gTLD redactions to
// carry text substantially similar to the English "REDACTED FOR PRIVACY".
//
// Consequences for maintenance:
//
//   - Entries are weighted toward MULTI-WORD phrases. A phrase cannot collide
//     with a real company name by accident the way a bare adjective can, and
//     "protected"/"private"/"hidden" are all ordinary words in a trading name.
//     Single tokens appear only where the word is a redaction participle with no
//     plausible use in an org name.
//   - Before ADDING entries, get native-speaker review and, preferably, an
//     observed registrar response. A wrong entry here is a false positive that
//     silently rewrites a real registrant to PrivacyRedaction, which is worse
//     than the miss it fixes.
//   - Every entry is asserted fold-stable by TestMarkerVocabularyIsFoldStable,
//     so an entry typed with its original accents ("protégées") fails the build
//     rather than sitting dead in the list forever. Write entries in the folded
//     spelling that foldForMarkers produces.

// markerTokens are single tokens whose presence as a whole token indicates
// redaction. Only the action itself qualifies — "privacy" is excluded because
// legitimate orgs carry it ("Privacy International"), and whole-token matching
// is what keeps "Redactron Systems" from matching "redact".
var markerTokens = map[string]bool{
	// English.
	"redacted": true, "redaction": true, "redact": true,
	"withheld": true, "masked": true, "masking": true,

	// German: geschwärzt — literally "blackened", the standard term for a
	// redacted document. No use in a trading name.
	"geschwarzt": true,

	// Italian: oscurato — "obscured", used by IIT-adjacent tooling.
	"oscurato": true,

	// Spanish / Portuguese: ocultado — "hidden" as a completed action.
	"ocultado": true,

	// Dutch: afgeschermd — "screened off".
	"afgeschermd": true,

	// Turkish: gizlenmiş — "has been hidden".
	"gizlenmis": true,

	// Norwegian / Danish: skjult — "hidden".
	"skjult": true,

	// Czech / Slovak: skryto — "hidden".
	"skryto": true,

	// Icelandic: þagnarskylda — "duty of confidentiality". Folded via
	// atomicLatinFolds ("þ" → "th"), since NFKD cannot decompose thorn. This is
	// the weakest entry in the list: it names the legal obligation rather than
	// the act of redaction, so it is the first candidate to drop if native-speaker
	// review disagrees.
	"thagnarskylda": true,

	// Russian: скрыто — "hidden". Cyrillic survives markerTokenize intact;
	// it is only strutil.Tokenize that would delete it.
	"скрыто": true,
}

// markerPhrases are consecutive token runs that indicate redaction when the
// individual words are too generic to match alone. Matched against the joined
// token stream, so intervening punctuation in the source value is irrelevant.
var markerPhrases = [][]string{
	// English.
	{"data", "protected"},
	{"not", "disclosed"},

	// French: "données protégées", "non divulgué", "informations masquées".
	{"donnees", "protegees"},
	{"non", "divulgue"},
	{"informations", "masquees"},

	// German: "nicht offengelegt", "nicht veröffentlicht", "Daten geschützt".
	{"nicht", "offengelegt"},
	{"nicht", "veroffentlicht"},
	{"daten", "geschutzt"},
	// "geschützt nach DSGVO" / "geschützt nach Art. 6" — the participle without
	// a preceding "Daten". Anchored on "nach" rather than accepting bare
	// "geschutzt", which is an ordinary word a trading name could carry
	// ("Geschützte Werkstätten"); "geschutzt nach" is not.
	{"geschutzt", "nach"},

	// Spanish: "datos protegidos", "no divulgado".
	{"datos", "protegidos"},
	{"no", "divulgado"},

	// Portuguese: "dados protegidos", "não divulgado".
	{"dados", "protegidos"},
	{"nao", "divulgado"},

	// Italian: "dati protetti", "non divulgato".
	{"dati", "protetti"},
	{"non", "divulgato"},

	// Dutch: "niet vrijgegeven", "gegevens beschermd".
	{"niet", "vrijgegeven"},
	{"gegevens", "beschermd"},

	// Polish: "dane zastrzeżone", "dane ukryte". Note "zastrzeżone" is NOT a
	// standalone token — it appears in "wszelkie prawa zastrzeżone" ("all
	// rights reserved"), which a footer-scraped org value could carry.
	{"dane", "zastrzezone"},
	{"dane", "ukryte"},

	// Swedish: "skyddade uppgifter". "skyddad" alone is too generic.
	{"skyddade", "uppgifter"},

	// Czech: "chráněná data".
	{"chranena", "data"},

	// Greek: "απόκρυψη δεδομένων" — "concealment of data". Stored folded: the
	// tonos is a combining mark after NFKD, so it is stripped.
	{"αποκρυψη", "δεδομενων"},

	// Russian: "данные защищены", "не раскрывается".
	{"данные", "защищены"},
	{"не", "раскрывается"},
}

// markerSubstrings are matched by CONTAINMENT rather than as whole tokens,
// because they are written in scripts that do not separate words with spaces.
// "データ保護のため非公開" is a single token to any whitespace-based tokenizer, so
// requiring a whole-token match would never fire.
//
// Containment is safe here ONLY because these entries contain no Latin letters:
// a CJK sequence cannot occur inside a Latin trading name, so the substring pass
// cannot reproduce the "Redactron Systems" false positive that whole-token
// matching exists to prevent. That property is not incidental — it is enforced
// by TestMarkerSubstringsCarryNoLatin, which fails if a Latin-script entry is
// added here instead of to markerTokens or markerPhrases.
var markerSubstrings = []string{
	// Japanese.
	"データ保護", // data protection
	"非公開",   // not public
	"情報非開示", // information not disclosed

	// Chinese (Simplified).
	"隐私保护", // privacy protection
	"已隐藏",  // already hidden
	"不公开",  // not public

	// Korean.
	"비공개", // not public
}
