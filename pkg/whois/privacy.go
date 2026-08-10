package whois

import (
	"slices"
	"strings"

	"github.com/praetorian-inc/pius/pkg/whois/data"
)

// PrivacyRedaction is the sentinel value persisted when WHOIS data is redacted
// behind a privacy/proxy service rather than genuinely absent.
const PrivacyRedaction = "Privacy Redaction"
const substringMinLen = 8

// IsPrivacy reports whether a value is a known WHOIS privacy/proxy string.
// Works for org names, person names, and email addresses — it combines
// prefix/suffix matching (catches email domains like @withheldforprivacy.com),
// exact-match lists, and redaction marker tokens.
func IsPrivacy(value string) bool {
	if value == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(value))

	// Tier 0: prefix/suffix matching from embedded denylist files.
	if matchesPrefix(lower) || matchesSuffix(lower) {
		return true
	}

	// Tier 1: exact match against known org and name privacy strings.
	if data.PrivacyOrgs[lower] || data.PrivacyNames[lower] {
		return true
	}

	// Tier 2: substring containment against known org guard phrases.
	// Privacy orgs often append per-customer suffixes like "(customer 12345)".
	for phrase := range data.PrivacyOrgs {
		if len(phrase) >= substringMinLen && strings.Contains(lower, phrase) {
			return true
		}
	}

	// Tier 3: redaction marker tokens — catches placeholder wordings like
	// "DATA REDACTED" that aren't in any exact-match list.
	return hasMarkerToken(lower)
}

// NormalizePrivacy maps a raw WHOIS field value: empty stays empty, privacy
// values collapse to PrivacyRedaction, real values pass through unchanged.
func NormalizePrivacy(value string) string {
	if value == "" {
		return ""
	}
	if IsPrivacy(value) {
		return PrivacyRedaction
	}
	return value
}

func matchesPrefix(lower string) bool {
	for _, prefix := range data.NoisyPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func matchesSuffix(lower string) bool {
	for _, suffix := range data.NoisySuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// hasMarkerToken reports whether a value carries redaction-placeholder
// vocabulary. It tokenizes with markerTokenize rather than strutil.Tokenize so
// that non-ASCII wordings survive to be compared against the vocabulary at all
// — see marker_normalize.go for why the two tokenizers are deliberately
// separate, and marker_vocabulary.go for the vocabulary itself (ENG-5420).
func hasMarkerToken(lower string) bool {
	tokens := markerTokenize(lower)
	for _, t := range tokens {
		if markerTokens[t] {
			return true
		}
	}

	for _, phrase := range markerPhrases {
		if containsTokenRun(tokens, phrase) {
			return true
		}
	}

	// Scripts without word separators, matched by containment because a
	// whole-token match could never fire. See markerSubstrings for why
	// containment is safe here, and cjkCorporateForms for the guard.
	joined := strings.Join(tokens, " ")
	if !hasCJKCorporateForm(joined) {
		for _, sub := range markerSubstrings {
			if strings.Contains(joined, sub) {
				return true
			}
		}
	}
	return false
}

// containsTokenRun reports whether phrase appears in tokens as a run of
// complete, consecutive tokens.
//
// This is deliberately not strings.Contains over the joined token stream, which
// anchors neither end of the run: "Data ProtectedX" tokenizes to
// [data, protectedx], joins to "data protectedx", and matches the
// {"data", "protected"} phrase on a prefix of its final token. Whole-token
// matching is the property that keeps "Redactron Systems" from matching
// "redact", and phrases must honour it too or the vocabulary's safest entries
// become its leakiest.
func containsTokenRun(tokens, phrase []string) bool {
	if len(phrase) == 0 || len(phrase) > len(tokens) {
		return false
	}
	for start := 0; start+len(phrase) <= len(tokens); start++ {
		if slices.Equal(tokens[start:start+len(phrase)], phrase) {
			return true
		}
	}
	return false
}

// hasCJKCorporateForm reports whether a value carries a CJK legal-entity or
// company-form term, marking it a trading name rather than a redaction
// placeholder.
//
// markerSubstrings matches by containment, which cannot distinguish a registry
// placeholder from a company that happens to be named after the same concept.
// The no-Latin invariant bounds that risk for Latin trading names but says
// nothing about CJK ones, and the collision is real in both directions:
// "非公開会社" is the Japanese legal term for a close corporation, and
// "…隐私保护科技有限公司" is an ordinary name for a Chinese privacy-tech firm.
//
// Suppressing the containment pass on these values trades recall for precision
// deliberately. A registry that emits a placeholder alongside a company form
// ("データ保護のため非公開 — 株式会社X") is missed, which costs a de-ranked candidate;
// a false positive rewrites a real registrant to PrivacyRedaction, which
// destroys information. The company-form terms are broad (会社/公司/회사 rather
// than only 株式会社/有限公司) for the same reason.
func hasCJKCorporateForm(value string) bool {
	for _, form := range cjkCorporateForms {
		if strings.Contains(value, form) {
			return true
		}
	}
	return false
}
