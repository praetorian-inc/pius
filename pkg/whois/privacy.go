package whois

import (
	"cmp"
	"slices"
	"strings"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/whois/data"
)

// PrivacyRedaction is the sentinel value persisted when WHOIS data is redacted
// behind a privacy/proxy service rather than genuinely absent.
const PrivacyRedaction = "Privacy Redaction"
const substringMinLen = 8

// markerTokens are single tokens whose presence as a whole token indicates
// redaction. Only the action itself qualifies — "privacy" is excluded because
// legitimate orgs carry it ("Privacy International").
var markerTokens = map[string]bool{
	"redacted": true, "redaction": true, "redact": true,
	"withheld": true, "masked": true, "masking": true,
}

// markerPhrases are consecutive token runs that indicate redaction when the
// individual words are too generic to match alone.
var markerPhrases = [][]string{
	{"data", "protected"},
	{"not", "disclosed"},
}

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

func normalizePrivacy(v string) string {
	v = strings.TrimSpace(v)
	if IsPrivacy(v) {
		return PrivacyRedaction
	}
	return v
}

func preferNonPrivacy(base, other string) string {
	if base == PrivacyRedaction {
		return cmp.Or(other, base)
	}
	return cmp.Or(base, other)
}

func matchesPrefix(lower string) bool {
	return slices.ContainsFunc(data.NoisyPrefixes, func(prefix string) bool {
		return strings.HasPrefix(lower, prefix)
	})
}

func matchesSuffix(lower string) bool {
	return slices.ContainsFunc(data.NoisySuffixes, func(suffix string) bool {
		return strings.HasSuffix(lower, suffix)
	})
}

func hasMarkerToken(lower string) bool {
	tokens := strutil.Tokenize(lower)
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
	return false
}

func trimStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}
