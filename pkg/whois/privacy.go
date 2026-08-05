package whois

import (
	_ "embed"
	"strings"
)

// PrivacyRedaction is the sentinel value persisted when WHOIS data is redacted
// behind a privacy/proxy service rather than genuinely absent.
const PrivacyRedaction = "Privacy Redaction"

//go:embed prefixes.txt
var prefixesRaw string

//go:embed suffixes.txt
var suffixesRaw string

var (
	noisyPrefixes map[string]bool
	noisySuffixes map[string]bool
)

func init() {
	noisyPrefixes = loadLines(prefixesRaw)
	noisySuffixes = loadLines(suffixesRaw)
}

func loadLines(raw string) map[string]bool {
	m := make(map[string]bool)
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			m[strings.ToLower(line)] = true
		}
	}
	return m
}

// IsPrivacy reports whether a value is a known WHOIS privacy/proxy string.
// Works for org names, person names, and email addresses — it combines
// prefix/suffix matching (catches email domains like @withheldforprivacy.com),
// exact-match maps, and redaction marker tokens.
func IsPrivacy(value string) bool {
	if value == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(value))

	// Tier 0: prefix/suffix matching — catches email domains and common
	// full-string patterns from the embedded denylist files.
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

// substringMinLen avoids matching incidental substrings of legitimate orgs.
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

// privacyOrgs are organization names used by WHOIS privacy services.
var privacyOrgs = map[string]bool{
	"domains by proxy, llc":              true,
	"domains by proxy":                   true,
	"whoisguard, inc.":                   true,
	"whoisguard protected":               true,
	"whoisguard":                         true,
	"privacy protect, llc":               true,
	"contact privacy inc.":               true,
	"contact privacy inc. customer":      true,
	"privacyprotect.org":                 true,
	"whois privacy corp.":                true,
	"perfect privacy, llc":               true,
	"data protected":                     true,
	"identity protection service":        true,
	"withheld for privacy":               true,
	"redacted for privacy":               true,
	"statutory masking enabled":          true,
	"super privacy service ltd":          true,
	"privacy service provided by withheld for privacy ehf": true,
	"domain protection services, inc.":                     true,
	"contactprivacy.com":                                   true,
	"private by design, llc":                               true,
	"domain privacy group, inc.":                           true,
	"whoisprivacyprotect.com":                              true,
	"gandi sas":                                            true,
	"tucows domains inc.":                                  true,
	"privacy hero, inc.":                                   true,
	"proxy protection llc":                                 true,
	"id shield":                                            true,
}

// privacyNames are name-field values used by WHOIS privacy services.
var privacyNames = map[string]bool{
	"registration private":                  true,
	"domain admin":                          true,
	"domain administrator":                  true,
	"whois agent":                           true,
	"whois privacy":                         true,
	"data protected":                        true,
	"redacted for privacy":                  true,
	"withheld for privacy":                  true,
	"contact privacy inc. customer":         true,
	"identity protection service":           true,
	"domain privacy group":                  true,
	"private registration":                  true,
	"not disclosed":                         true,
	"statutory masking enabled":             true,
	"admin":                                 true,
	"hostmaster":                            true,
	"dns admin":                             true,
	"domain hostmaster":                     true,
	"abuse":                                 true,
	"postmaster":                            true,
	"super privacy service ltd c/o migadu": true,
}

// markerTokens are single tokens whose presence as a whole token indicates
// redaction. Only the action itself qualifies — "privacy" is excluded because
// legitimate orgs carry it ("Privacy International").
var markerTokens = map[string]bool{
	"redacted":  true,
	"redaction": true,
	"redact":    true,
	"withheld":  true,
	"masked":    true,
	"masking":   true,
}

// markerPhrases are consecutive token runs that indicate redaction when the
// individual words are too generic to match alone.
var markerPhrases = [][]string{
	{"data", "protected"},
	{"not", "disclosed"},
}
