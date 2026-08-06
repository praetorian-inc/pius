package whois

import (
	"net"
	"net/mail"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RegistrantOrg resolves the organization identity from a registrant contact,
// handling ccTLD name-field promotion and registry artifact filtering.
// Returns "" when nothing usable is present.
func RegistrantOrg(c Contact, domain string) string {
	if c.Organization != "" && !isRegistryArtifact(c.Organization, domain) {
		return c.Organization
	}
	if holderInRegistrantName(domain) {
		return c.Name
	}
	return ""
}

// ContactEmail finds the best non-privacy email across a result's contacts.
// Prefers registrant, then admin, tech, billing.
func ContactEmail(r Result) (email string, sawProxy bool) {
	for _, c := range r.AllContacts() {
		classified := classifyEmail(c.Email)
		switch {
		case classified == PrivacyRedaction:
			sawProxy = true
		case classified != "":
			return classified, sawProxy
		}
	}
	return "", sawProxy
}

func classifyEmail(raw string) string {
	if raw == "" {
		return ""
	}
	if IsPrivacy(raw) {
		return PrivacyRedaction
	}
	if IsEmail(raw) {
		return raw
	}
	return ""
}

// IsEmail reports whether s is a syntactically valid email address.
func IsEmail(s string) bool {
	_, err := mail.ParseAddress(s)
	return err == nil
}

// NormalizeRegistrar cleans up registrar names. Strips Nominet-style
// "[Tag = X]" suffixes, keeping only the IPS tag when present.
func NormalizeRegistrar(name string) string {
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

var nominetTagPattern = regexp.MustCompile(`^(.*?)\s*\[\s*(?i:tag)\s*=\s*([^\]]*)\]$`)

// Corroborate compares a resolved registrant org against a pivot org.
// Returns "match", "mismatch", or "unverifiable".
func Corroborate(pivotOrg, resolvedOrg string) string {
	if pivotOrg == "" {
		return ""
	}
	if resolvedOrg == "" || IsPrivacy(resolvedOrg) {
		return "unverifiable"
	}
	sim := OrgSimilarity(pivotOrg, resolvedOrg)
	if sim >= 0.60 {
		return "match"
	}
	if sim < 0.30 {
		return "mismatch"
	}
	return "unverifiable"
}

// OrgSimilarity compares two organization names with legal-suffix stripping.
func OrgSimilarity(a, b string) float64 {
	return TokenSimilarity(normalizeOrg(a), normalizeOrg(b))
}

var legalSuffixes map[string]bool

func init() {
	legalSuffixes = loadDataFile("data/legal_suffixes.txt")
}

func normalizeOrg(s string) string {
	tokens := Tokenize(s)
	kept := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if !legalSuffixes[t] {
			kept = append(kept, t)
		}
	}
	return strings.Join(kept, " ")
}

// RootDomain extracts the registrable domain (eTLD+1) from a hostname using
// the public suffix list. Falls back to last-two-labels for hostnames the PSL
// doesn't cover.
func RootDomain(hostname string) string {
	hostname = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(hostname)), ".")
	if hostname == "" || net.ParseIP(hostname) != nil {
		return ""
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		// Fallback for hostnames not in the PSL (e.g. internal TLDs).
		parts := strings.Split(hostname, ".")
		if len(parts) < 2 {
			return ""
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return etld1
}

// IsPlausibleDomain filters garbage from reverse-whois results. Checks for
// a syntactically valid hostname with at least one dot, no URL/authority
// punctuation, and within DNS length limits.
func IsPlausibleDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	for _, r := range domain {
		if r <= ' ' || r == 0x7f || r == '/' || r == ':' || r == '@' || r == '?' || r == '#' {
			return false
		}
	}
	return true
}

// ContainsRedactionMarker reports whether raw WHOIS text carries an explicit
// redaction marker (useful when no structured contact data is present).
func ContainsRedactionMarker(raw string) bool {
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

var redactionMarkers []string

func init() {
	raw, err := dataFS.ReadFile("data/redaction_markers.txt")
	if err != nil {
		panic("whois: missing embedded data file: data/redaction_markers.txt")
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			redactionMarkers = append(redactionMarkers, strings.ToLower(line))
		}
	}
}

// --- Text utilities ---

// Tokenize lowercases s and splits on non-alphanumeric characters.
func Tokenize(s string) []string {
	s = strings.ToLower(s)
	var buf strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			buf.WriteRune(c)
		} else {
			buf.WriteByte(' ')
		}
	}
	return strings.Fields(buf.String())
}

// TokenSimilarity computes the ratio of shared tokens between two strings.
// Uses the shorter set as the denominator so partial matches score well.
func TokenSimilarity(a, b string) float64 {
	aT := Tokenize(a)
	bT := Tokenize(b)
	if len(aT) == 0 || len(bT) == 0 {
		return 0
	}
	shorter, longer := aT, bT
	if len(aT) > len(bT) {
		shorter, longer = bT, aT
	}
	inLonger := make(map[string]bool, len(longer))
	for _, t := range longer {
		inLonger[t] = true
	}
	matches := 0
	for _, t := range shorter {
		if inLonger[t] {
			matches++
		}
	}
	return float64(matches) / float64(len(shorter))
}

// --- ccTLD and registry artifact rules ---

// registrantNameCCTLDs are loaded from data/cctld_name_promotion.txt if we
// ever need to externalize; for now the list is small and stable.
var registrantNameCCTLDs = []string{
	".cn", ".hr", ".jp", ".kr",
	".fr", ".re", ".pm", ".tf", ".wf", ".yt",
	".ca", ".dk", ".ee", ".fi", ".gg",
	".xn--fiqs8s", ".cl",
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
// parser mis-maps into Registrant.Organization. Loaded from embedded file.
var registryOperatorArtifacts map[string][]string

// registryHandleCCTLDs are ccTLDs where the parser mis-maps opaque NIC
// handles or national tax IDs into Registrant.Organization (.se publishes
// NIC handles like "DIDEP2435-002435", .ar publishes CUIT tax IDs).
var registryHandleCCTLDs = []string{".se", ".ar"}

var opaqueRegistrantHandle = regexp.MustCompile(`^([0-9]{6,}|[A-Za-z0-9]+-[0-9]+)$`)

func init() {
	registryOperatorArtifacts = make(map[string][]string)
	raw, err := dataFS.ReadFile("data/registry_artifacts.txt")
	if err != nil {
		panic("whois: missing embedded data file: data/registry_artifacts.txt")
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		suffix := strings.TrimSpace(parts[0])
		value := strings.ToLower(strings.TrimSpace(parts[1]))
		registryOperatorArtifacts[suffix] = append(registryOperatorArtifacts[suffix], value)
	}
}

func isRegistryArtifact(org, dns string) bool {
	trimmedOrg := strings.TrimSpace(org)
	if trimmedOrg == "" {
		return false
	}
	dns = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dns), "."))
	norm := strings.Join(strings.Fields(strings.ToLower(org)), " ")
	for suffix, artifacts := range registryOperatorArtifacts {
		if strings.HasSuffix(dns, suffix) {
			if slices.Contains(artifacts, norm) {
				return true
			}
		}
	}
	for _, suffix := range registryHandleCCTLDs {
		if strings.HasSuffix(dns, suffix) && opaqueRegistrantHandle.MatchString(trimmedOrg) {
			return true
		}
	}
	return false
}
