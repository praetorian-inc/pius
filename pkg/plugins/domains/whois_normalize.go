package domains

import (
	_ "embed"
	"log/slog"
	"net/mail"
	"regexp"
	"slices"
	"strings"

	whoisparser "github.com/likexian/whois-parser"
)

// PrivacyRedaction is the sentinel persisted when WHOIS data is redacted behind
// a privacy/proxy service rather than genuinely absent.
const PrivacyRedaction = "Privacy Redaction"

//go:embed whois-prefixes.txt
var whoisPrefixesRaw string

//go:embed whois-suffixes.txt
var whoisSuffixesRaw string

var (
	noisyPrefixes map[string]bool
	noisySuffixes map[string]bool
)

func init() {
	noisyPrefixes = make(map[string]bool)
	noisySuffixes = make(map[string]bool)
	for _, line := range strings.Split(whoisPrefixesRaw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			noisyPrefixes[strings.ToLower(line)] = true
		}
	}
	for _, line := range strings.Split(whoisSuffixesRaw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			noisySuffixes[strings.ToLower(line)] = true
		}
	}
}

// isNoisyWhoisParam returns true if the value is a known WHOIS privacy/proxy string.
func isNoisyWhoisParam(param string) bool {
	param = strings.ToLower(param)
	return paramHasPrefix(param) || paramHasSuffix(param)
}

func paramHasPrefix(param string) bool {
	for i := 1; i <= len(param); i++ {
		if noisyPrefixes[param[:i]] {
			return true
		}
	}
	return false
}

func paramHasSuffix(param string) bool {
	for i := len(param) - 1; i >= 0; i-- {
		if noisySuffixes[param[i:]] {
			return true
		}
	}
	return false
}

// normalizeRedacted maps a raw WHOIS field value: empty stays empty,
// privacy/proxy values collapse to PrivacyRedaction, real values pass through.
func normalizeRedacted(value string) string {
	if value == "" {
		return ""
	}
	if isNoisyWhoisParam(value) {
		return PrivacyRedaction
	}
	return value
}

// classifyEmail returns PrivacyRedaction for proxy emails, the address itself
// if valid, or "" otherwise.
func classifyEmail(raw string) string {
	if raw == "" {
		return ""
	}
	if isNoisyWhoisParam(raw) {
		return PrivacyRedaction
	}
	if isValidEmail(raw) {
		return raw
	}
	return ""
}

func isValidEmail(s string) bool {
	_, err := mail.ParseAddress(s)
	return err == nil
}

// registrantNameCCTLDs are ccTLDs whose registries publish the domain holder
// in the registrant NAME field with no distinct Organization field. For these,
// the parsed Name IS the holder org.
var registrantNameCCTLDs = []string{
	".cn", ".hr", ".jp", ".kr",
	".fr", ".re", ".pm", ".tf", ".wf", ".yt",
	".ca", ".dk", ".ee", ".fi", ".gg",
	".xn--fiqs8s",
	".cl",
}

func holderInRegistrantName(dns string) bool {
	dns = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dns), "."))
	for _, suffix := range registrantNameCCTLDs {
		if strings.HasSuffix(dns, suffix) {
			return true
		}
	}
	return false
}

// registryOperatorArtifacts maps ccTLD → registry operator strings that the
// parser mis-maps into Registrant.Organization. These are NOT domain holders.
var registryOperatorArtifacts = map[string][]string{
	".uk": {"nominet uk"},
	".es": {"red.es"},
	".ch": {"switch the swiss education & research network"},
	".cl": {"nic chile (university of chile)"},
	".za": {"za domain name authority"},
	".ph": {"ph domain foundation"},
	".vn": {"viet nam internet network information center (vnnic)"},
}

var registryHandleCCTLDs = []string{".se", ".ar"}

var opaqueRegistrantHandle = regexp.MustCompile(`^([0-9]{6,}|[A-Za-z0-9]+-[0-9]+)$`)

func normalizeArtifact(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// isRegistryArtifact reports whether org is a registry operator name or opaque
// handle that the parser mis-mapped into Registrant.Organization.
func isRegistryArtifact(org, dns string) bool {
	trimmedOrg := strings.TrimSpace(org)
	if trimmedOrg == "" {
		return false
	}
	dns = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dns), "."))
	norm := normalizeArtifact(org)
	for suffix, artifacts := range registryOperatorArtifacts {
		if strings.HasSuffix(dns, suffix) && slices.Contains(artifacts, norm) {
			return true
		}
	}
	for _, suffix := range registryHandleCCTLDs {
		if strings.HasSuffix(dns, suffix) && opaqueRegistrantHandle.MatchString(trimmedOrg) {
			return true
		}
	}
	return false
}

// registrantOrg resolves the organization identity from a WHOIS registrant contact.
// Prefers Organization; falls back to Name for ccTLDs that carry the holder only
// in the name field.
func registrantOrg(registrant *whoisparser.Contact, dns string) string {
	if registrant == nil {
		return ""
	}
	if registrant.Organization != "" && !isRegistryArtifact(registrant.Organization, dns) {
		return registrant.Organization
	}
	if holderInRegistrantName(dns) {
		return registrant.Name
	}
	return ""
}

// contactEmail resolves the contact email from a WhoisResult. Prefers registrant,
// falls back across admin/tech/billing. Returns the email and whether a proxy
// address was seen.
func contactEmail(result WhoisResult) (email string, sawProxy bool) {
	for _, c := range []*whoisparser.Contact{
		result.Registrant, result.Administrative, result.Technical, result.Billing,
	} {
		if c == nil {
			continue
		}
		switch classified := classifyEmail(c.Email); {
		case classified == PrivacyRedaction:
			sawProxy = true
		case classified != "":
			return classified, sawProxy
		}
	}
	return "", sawProxy
}

// normalizeRegistrar strips Nominet-style "[Tag = X]" suffixes.
var nominetTagPattern = regexp.MustCompile(`^(.*?)\s*\[\s*(?i:tag)\s*=\s*([^\]]*)\]$`)

func normalizeRegistrar(name string) string {
	name = strings.TrimSpace(name)
	match := nominetTagPattern.FindStringSubmatch(name)
	if match == nil {
		return name
	}
	if tag := strings.TrimSpace(match[2]); tag != "" {
		return tag
	}
	return strings.TrimSpace(match[1])
}

// redactionMarkers indicate a registry deliberately redacted contact data.
var redactionMarkers = []string{
	"redacted for privacy",
	"redacted for gdpr",
	"statutory masking",
}

func containsRedactionMarker(raw string) bool {
	if raw == "" {
		return false
	}
	lower := strings.ToLower(raw)
	for _, marker := range redactionMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// --- Corroboration helpers (from reverse_whois_verify.go) ---

// orgLegalSuffixes are stripped before comparison so "Walmart Inc." and
// "Walmart" compare equal.
var orgLegalSuffixes = map[string]bool{
	"inc": true, "llc": true, "ltd": true, "corp": true, "gmbh": true,
	"sas": true, "co": true, "plc": true, "bv": true, "nv": true,
	"pty": true, "oy": true, "ab": true, "as": true, "kk": true,
	"pte": true, "sa": true, "srl": true, "spa": true, "ag": true,
	"kg": true, "aps": true, "oyj": true,
	"corporation": true, "incorporated": true, "company": true, "limited": true,
}

// normalizeOrg lowercases, tokenizes, and strips legal-suffix tokens.
func normalizeOrg(s string) string {
	tokens := tokenize(s)
	kept := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if !orgLegalSuffixes[t] {
			kept = append(kept, t)
		}
	}
	return strings.Join(kept, " ")
}

// tokenize and tokenSimilarity are defined in github_org.go and shared across
// the domains package. normalizeOrgSimilarity wraps tokenSimilarity with
// legal-suffix stripping for org comparison.
func normalizeOrgSimilarity(a, b string) float64 {
	return tokenSimilarity(normalizeOrg(a), normalizeOrg(b))
}

// whoisPrivacyNames contains name-field values used by WHOIS privacy services.
var whoisPrivacyNames = map[string]bool{
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

// whoisPrivacyGuards contains organization names used by WHOIS privacy services.
var whoisPrivacyGuards = map[string]bool{
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

// whoisPrivacyMarkerTokens are single tokens whose presence as a whole token
// indicates redaction.
var whoisPrivacyMarkerTokens = map[string]bool{
	"redacted":  true,
	"redaction": true,
	"redact":    true,
	"withheld":  true,
	"masked":    true,
	"masking":   true,
}

// whoisPrivacyMarkerPhrases are consecutive token runs indicating redaction.
var whoisPrivacyMarkerPhrases = [][]string{
	{"data", "protected"},
	{"not", "disclosed"},
}

const maskedSubstringMinLen = 8

// isMaskedOrg reports whether v is a known WHOIS privacy/proxy org or name.
// Three tiers: exact match, substring containment, marker tokens/phrases.
func isMaskedOrg(v string) bool {
	lower := strings.ToLower(v)

	// Tier 1: exact match
	if whoisPrivacyGuards[lower] || whoisPrivacyNames[lower] {
		return true
	}

	// Tier 2: substring containment against guard phrases
	for guard := range whoisPrivacyGuards {
		if len(guard) >= maskedSubstringMinLen && strings.Contains(lower, guard) {
			return true
		}
	}

	// Tier 3: marker tokens/phrases
	return hasPrivacyMarker(lower)
}

func hasPrivacyMarker(lower string) bool {
	tokens := tokenize(lower)

	// Single-token markers
	for _, t := range tokens {
		if whoisPrivacyMarkerTokens[t] {
			return true
		}
	}

	// Multi-token marker phrases (consecutive tokens)
	for _, phrase := range whoisPrivacyMarkerPhrases {
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

// isPlausibleDomain filters garbage domains from reverse-whois results.
func isPlausibleDomain(domain string) bool {
	if domain == "" {
		return false
	}
	// Must have at least one dot
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	// TLD must be at least 2 chars
	tld := parts[len(parts)-1]
	if len(tld) < 2 {
		return false
	}
	return true
}

// corroborate compares a resolved registrant org against a pivot org and returns
// a corroboration verdict: "match", "mismatch", or "unverifiable".
func corroborate(pivotOrg, resolvedOrg string) string {
	if pivotOrg == "" {
		return ""
	}
	if resolvedOrg == "" || isMaskedOrg(resolvedOrg) {
		return "unverifiable"
	}
	sim := normalizeOrgSimilarity(pivotOrg, resolvedOrg)
	if sim >= 0.60 {
		return "match"
	}
	if sim < 0.30 {
		return "mismatch"
	}
	return "unverifiable"
}

// extractWhoisResultFromParsed populates a WhoisResult from a parsed WHOIS record.
func extractWhoisResultFromParsed(parsed whoisparser.WhoisInfo, raw string) WhoisResult {
	result := WhoisResult{
		Domain:         parsed.Domain,
		Registrar:      parsed.Registrar,
		Registrant:     parsed.Registrant,
		Administrative: parsed.Administrative,
		Technical:      parsed.Technical,
		Billing:        parsed.Billing,
		Raw:            raw,
	}
	return result
}

// logNormalizationIssue logs when a normalization helper encounters unexpected data.
// Kept as a function so it can be silenced in tests.
var logNormalizationIssue = func(msg string, args ...any) {
	slog.Warn(msg, args...)
}
