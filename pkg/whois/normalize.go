package whois

import (
	"net"
	"net/mail"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/whois/data"
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
	return strutil.TokenSimilarity(normalizeOrg(a), normalizeOrg(b))
}

func normalizeOrg(s string) string {
	tokens := strutil.Tokenize(s)
	kept := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if !data.LegalSuffixes[t] {
			kept = append(kept, t)
		}
	}
	return strings.Join(kept, " ")
}

func RootDomain(hostname string) string {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return ""
	}

	// IPs are not domains.
	if net.ParseIP(hostname) != nil {
		return ""
	}

	// Repeatedly compute eTLD+1 until the result sits under an ICANN-managed
	// suffix. For normal domains this returns on the first iteration
	// (e.g., app.praetorian.com → praetorian.com). For cloud infrastructure
	// under private PSL suffixes it walks up via the suffix until it reaches
	// the ICANN-level registrable domain (e.g., mybucket.s3.amazonaws.com →
	// amazonaws.com, while d2xxx.cloudfront.net → cloudfront.net).
	domain := hostname
	for range strings.Count(hostname, ".") + 1 {
		etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			_, remainder, ok := strings.Cut(domain, ".")
			if !ok {
				return ""
			}
			if tld, icann := publicsuffix.PublicSuffix(remainder); icann && tld == remainder {
				return domain
			}
			domain = remainder
			continue
		}

		tld, icann := publicsuffix.PublicSuffix(etld1)
		if icann {
			return etld1
		}
		if tld == domain {
			return domain
		}
		domain = tld
	}
	return ""
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
	for _, marker := range data.RedactionMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// --- ISOC-IL (.il) fallback ---

// applyISOCILFallback fills empty Registrant org/email for .il domains from
// the raw RPSL descr/e-mail block, which likexian/whois-parser does not map
// onto Registrant.
func applyISOCILFallback(r *Result) {
	dns := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), "."))
	if !strings.HasSuffix(dns, ".il") {
		return
	}
	if r.Registrant.Organization != "" && r.Registrant.Email != "" {
		return
	}

	var holder map[string]string
	for _, p := range parseRPSLParagraphs(r.Raw) {
		if p["first_descr"] != "" {
			holder = p
			break
		}
	}
	if holder == nil {
		return
	}

	if r.Registrant.Organization == "" {
		org := strings.TrimSpace(holder["first_descr"])
		if runes := []rune(org); len(runes) > 255 {
			org = strings.TrimSpace(string(runes[:255]))
		}
		r.Registrant.Organization = org
	}

	if r.Registrant.Email == "" {
		deobfuscated := strings.ReplaceAll(holder["e-mail"], " AT ", "@")
		if classifyEmail(deobfuscated) != "" {
			r.Registrant.Email = deobfuscated
		}
	}
}

// parseRPSLParagraphs splits raw WHOIS/RPSL text into key:value paragraph
// maps. Used for ISOC-IL fallback and IP WHOIS (future). No third-party
// library exists for RPSL paragraph parsing — it's a niche wire format.
func parseRPSLParagraphs(raw string) []map[string]string {
	var paragraphs []map[string]string
	current := map[string]string{}

	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if len(current) > 0 {
				paragraphs = append(paragraphs, current)
				current = map[string]string{}
			}
			continue
		}
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if key == "descr" {
			if _, seen := current["first_descr"]; !seen {
				current["first_descr"] = value
			}
		}
		current[key] = value
	}
	if len(current) > 0 {
		paragraphs = append(paragraphs, current)
	}
	return paragraphs
}

// --- ccTLD and registry artifact rules ---

// registrantNameCCTLDs lists ccTLDs where the holder org is placed in the
// Name field instead of Organization.
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

// registryHandleCCTLDs are ccTLDs where the parser mis-maps opaque NIC
// handles or national tax IDs into Registrant.Organization (.se publishes
// NIC handles like "DIDEP2435-002435", .ar publishes CUIT tax IDs).
var registryHandleCCTLDs = []string{".se", ".ar"}

var opaqueRegistrantHandle = regexp.MustCompile(`^([0-9]{6,}|[A-Za-z0-9]+-[0-9]+)$`)

func isRegistryArtifact(org, dns string) bool {
	trimmedOrg := strings.TrimSpace(org)
	if trimmedOrg == "" {
		return false
	}
	dns = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dns), "."))
	norm := strings.Join(strings.Fields(strings.ToLower(org)), " ")
	for suffix, artifacts := range data.RegistryArtifacts {
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
