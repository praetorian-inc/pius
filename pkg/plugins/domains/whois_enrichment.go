package domains

import (
	"bufio"
	_ "embed"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"

	whoisparser "github.com/likexian/whois-parser"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

const privacyRedaction = "Privacy Redaction"

var registrantNameCCTLDs = []string{
	".cn", ".hr", ".jp", ".kr",
	".fr", ".re", ".pm", ".tf", ".wf", ".yt",
	".ca", ".dk", ".ee", ".fi", ".gg",
	".xn--fiqs8s", ".cl",
}

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
var nominetTagPattern = regexp.MustCompile(`^(.*?)\s*\[\s*(?i:tag)\s*=\s*([^\]]*)\]$`)
var redactionMarkers = []string{"redacted for privacy", "redacted for gdpr", "statutory masking"}

//go:embed whois-prefixes.txt
var noisyPrefixesText string

//go:embed whois-suffixes.txt
var noisySuffixesText string

var (
	noisyOnce     sync.Once
	noisyPrefixes []string
	noisySuffixes []string
)

func enrichWhoisRecord(record *whoisRecord, domain string) {
	info := &record.info
	applyISOCILFallback(info, record.raw, domain)
	marker := containsRedactionMarker(record.raw)
	email, sawProxy := contactEmail(*info)
	if info.Registrant == nil && (marker || email != "" || sawProxy) {
		info.Registrant = &whoisparser.Contact{}
	}
	if info.Registrant != nil {
		org := normalizeRedacted(registrantOrganization(info.Registrant, domain))
		if org == "" && marker {
			org = privacyRedaction
		}
		info.Registrant.Organization = org
		info.Registrant.Country = normalizeRedacted(info.Registrant.Country)
		info.Registrant.Province = normalizeRedacted(info.Registrant.Province)
		info.Registrant.City = normalizeRedacted(info.Registrant.City)

		switch {
		case email != "":
			info.Registrant.Email = email
		case sawProxy || marker:
			info.Registrant.Email = privacyRedaction
		default:
			info.Registrant.Email = ""
		}
	}
	if info.Registrar != nil {
		info.Registrar.Name = normalizeRegistrar(info.Registrar.Name)
	}
}

func extractRichPreseeds(info whoisparser.WhoisInfo, domain, source string) []plugins.Finding {
	type param struct {
		name  string
		value string
	}

	seen := make(map[param]bool)
	var findings []plugins.Finding
	for _, contact := range whoisContacts(info) {
		if contact == nil {
			continue
		}
		organization := contact.Organization
		if contact == info.Registrant {
			organization = registrantOrganization(contact, domain)
		} else if isRegistryArtifact(organization, domain) {
			organization = ""
		}
		for _, candidate := range []param{
			{name: "company", value: organization},
			{name: "name", value: contact.Name},
			{name: "email", value: contact.Email},
		} {
			if candidate.value == "" || seen[candidate] || isNoisyWhoisParam(candidate.value) {
				continue
			}
			if candidate.name == "email" && !isEmail(candidate.value) {
				continue
			}
			seen[candidate] = true
			findings = append(findings, preseedFinding("whois+"+candidate.name, candidate.value, source))
			if candidate.name == "company" {
				findings = append(findings, preseedFinding("edgar+company", candidate.value, source))
			}
		}
	}
	return findings
}

func preseedFinding(preseedType, value, source string) plugins.Finding {
	return plugins.Finding{
		Type:   plugins.FindingPreseed,
		Value:  value,
		Source: source,
		Data: map[string]any{
			"preseed_type":  preseedType,
			"preseed_title": value,
		},
	}
}

func applyISOCILFallback(info *whoisparser.WhoisInfo, raw, domain string) {
	if !strings.HasSuffix(normalizeDomain(domain), ".il") {
		return
	}
	haveOrg := info.Registrant != nil && info.Registrant.Organization != ""
	haveEmail := info.Registrant != nil && info.Registrant.Email != ""
	if haveOrg && haveEmail {
		return
	}

	var holder map[string]string
	for _, paragraph := range parseWhoisParagraphs(raw) {
		if paragraph["first_descr"] != "" {
			holder = paragraph
			break
		}
	}
	if holder == nil {
		return
	}
	if info.Registrant == nil {
		info.Registrant = &whoisparser.Contact{}
	}
	if info.Registrant.Organization == "" {
		org := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, holder["first_descr"])
		org = strings.TrimSpace(org)
		if runes := []rune(org); len(runes) > 255 {
			org = strings.TrimSpace(string(runes[:255]))
		}
		info.Registrant.Organization = org
	}
	if info.Registrant.Email == "" {
		email := strings.ReplaceAll(holder["e-mail"], " AT ", "@")
		if classifyEmail(email) != "" {
			info.Registrant.Email = email
		}
	}
}

func parseWhoisParagraphs(raw string) []map[string]string {
	var paragraphs []map[string]string
	current := map[string]string{}
	flush := func() {
		if len(current) > 0 {
			paragraphs = append(paragraphs, current)
			current = map[string]string{}
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "descr" && current["first_descr"] == "" {
			current["first_descr"] = value
		}
		current[key] = value
	}
	flush()
	return paragraphs
}

func registrantOrganization(registrant *whoisparser.Contact, domain string) string {
	if registrant == nil {
		return ""
	}
	if registrant.Organization != "" && !isRegistryArtifact(registrant.Organization, domain) {
		return registrant.Organization
	}
	if holderInRegistrantName(domain) {
		return registrant.Name
	}
	return ""
}

func contactEmail(info whoisparser.WhoisInfo) (string, bool) {
	sawProxy := false
	for _, contact := range whoisContacts(info) {
		if contact == nil {
			continue
		}
		classified := classifyEmail(contact.Email)
		switch classified {
		case privacyRedaction:
			sawProxy = true
		case "":
		default:
			return classified, sawProxy
		}
	}
	return "", sawProxy
}

func classifyEmail(value string) string {
	if value == "" {
		return ""
	}
	if isNoisyWhoisParam(value) {
		return privacyRedaction
	}
	if _, err := mail.ParseAddress(value); err == nil {
		return value
	}
	return ""
}

func normalizeRedacted(value string) string {
	if value == "" {
		return ""
	}
	if isNoisyWhoisParam(value) {
		return privacyRedaction
	}
	return value
}

func containsRedactionMarker(raw string) bool {
	lower := strings.ToLower(raw)
	return slices.ContainsFunc(redactionMarkers, func(marker string) bool {
		return strings.Contains(lower, marker)
	})
}

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

func holderInRegistrantName(domain string) bool {
	domain = normalizeDomain(domain)
	return slices.ContainsFunc(registrantNameCCTLDs, func(suffix string) bool {
		return strings.HasSuffix(domain, suffix)
	})
}

func isRegistryArtifact(org, domain string) bool {
	trimmedOrg := strings.TrimSpace(org)
	if trimmedOrg == "" {
		return false
	}
	domain = normalizeDomain(domain)
	normalizedOrg := strings.Join(strings.Fields(strings.ToLower(org)), " ")
	for suffix, artifacts := range registryOperatorArtifacts {
		if strings.HasSuffix(domain, suffix) && slices.Contains(artifacts, normalizedOrg) {
			return true
		}
	}
	return slices.ContainsFunc(registryHandleCCTLDs, func(suffix string) bool {
		return strings.HasSuffix(domain, suffix) && opaqueRegistrantHandle.MatchString(trimmedOrg)
	})
}

func isNoisyWhoisParam(value string) bool {
	noisyOnce.Do(loadNoisyParams)
	value = strings.ToLower(value)
	if value == strings.ToLower(privacyRedaction) {
		return true
	}
	return slices.ContainsFunc(noisyPrefixes, func(prefix string) bool {
		return strings.HasPrefix(value, prefix)
	}) || slices.ContainsFunc(noisySuffixes, func(suffix string) bool {
		return strings.HasSuffix(value, suffix)
	})
}

func loadNoisyParams() {
	noisyPrefixes = nonemptyLines(noisyPrefixesText)
	noisySuffixes = nonemptyLines(noisySuffixesText)
}

func nonemptyLines(value string) []string {
	var lines []string
	for line := range strings.SplitSeq(value, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
