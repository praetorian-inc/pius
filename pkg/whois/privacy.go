package whois

import (
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

	joined := strings.Join(tokens, " ")
	for _, phrase := range markerPhrases {
		if strings.Contains(joined, strings.Join(phrase, " ")) {
			return true
		}
	}

	// Scripts without word separators, matched by containment. Safe only
	// because every entry is non-Latin; see markerSubstrings.
	for _, sub := range markerSubstrings {
		if strings.Contains(joined, sub) {
			return true
		}
	}
	return false
}
