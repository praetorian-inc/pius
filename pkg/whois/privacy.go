package whois

import (
	"embed"
	"strings"
)

// PrivacyRedaction is the sentinel value persisted when WHOIS data is redacted
// behind a privacy/proxy service rather than genuinely absent.
const PrivacyRedaction = "Privacy Redaction"

//go:embed data
var dataFS embed.FS

var (
	noisyPrefixes map[string]bool
	noisySuffixes map[string]bool
	privacyOrgs   map[string]bool
	privacyNames  map[string]bool
)

func init() {
	noisyPrefixes = loadDataFile("data/prefixes.txt")
	noisySuffixes = loadDataFile("data/suffixes.txt")
	privacyOrgs = loadDataFile("data/privacy_orgs.txt")
	privacyNames = loadDataFile("data/privacy_names.txt")
}

func loadDataFile(name string) map[string]bool {
	raw, err := dataFS.ReadFile(name)
	if err != nil {
		panic("whois: missing embedded data file: " + name)
	}
	return loadLines(string(raw))
}

func loadLines(raw string) map[string]bool {
	m := make(map[string]bool)
	for line := range strings.SplitSeq(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			m[strings.ToLower(line)] = true
		}
	}
	return m
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
	if privacyOrgs[lower] || privacyNames[lower] {
		return true
	}

	// Tier 2: substring containment against known org guard phrases.
	// Privacy orgs often append per-customer suffixes like "(customer 12345)".
	for phrase := range privacyOrgs {
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
	for i := 1; i <= len(lower); i++ {
		if noisyPrefixes[lower[:i]] {
			return true
		}
	}
	return false
}

func matchesSuffix(lower string) bool {
	for i := len(lower) - 1; i >= 0; i-- {
		if noisySuffixes[lower[i:]] {
			return true
		}
	}
	return false
}

const substringMinLen = 8

// hasMarkerToken checks for whole redaction-action tokens. "Redactron Systems"
// tokenizes to ["redactron","systems"] — no token equals a marker, so it stays
// unmasked. Only the action itself ("redacted", "masked", "withheld") qualifies.
func hasMarkerToken(lower string) bool {
	tokens := Tokenize(lower)
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
	return false
}

func containsTokenRun(tokens, run []string) bool {
	if len(run) > len(tokens) {
		return false
	}
	for i := 0; i <= len(tokens)-len(run); i++ {
		match := true
		for j, t := range run {
			if tokens[i+j] != t {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

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
