package whois

import "strings"

type tcp43Fallback func(*DomainResult, string)

var tcp43Fallbacks = map[string]tcp43Fallback{
	".il": applyISOCILFallback,
	".pt": applyDNSPTFallback,
}

func applyTCP43RegistryFallback(result *DomainResult, raw string) {
	fallback, ok := tcp43Fallbacks[domainTLD(result.Domain)]
	if !ok {
		return
	}
	fallback(result, raw)
}

func domainTLD(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if dot := strings.LastIndexByte(domain, '.'); dot >= 0 {
		return domain[dot:]
	}
	return ""
}

// applyISOCILFallback parses the RPSL descr/e-mail holder block that
// likexian/whois-parser does not map onto Registrant.
func applyISOCILFallback(result *DomainResult, raw string) {
	if result.Registrant.Organization != "" && result.Registrant.Email != "" {
		return
	}

	var holder map[string]string
	for _, paragraph := range parseRPSLParagraphs(raw) {
		if paragraph["first_descr"] != "" {
			holder = paragraph
			break
		}
	}
	if holder == nil {
		return
	}

	if result.Registrant.Organization == "" {
		organization := strings.TrimSpace(holder["first_descr"])
		if runes := []rune(organization); len(runes) > 255 {
			organization = strings.TrimSpace(string(runes[:255]))
		}
		result.Registrant.Organization = organization
	}

	if result.Registrant.Email == "" {
		email := strings.ReplaceAll(holder["e-mail"], " AT ", "@")
		if classifyEmail(email) != "" {
			result.Registrant.Email = email
		}
	}
}

// applyDNSPTFallback parses the Owner Name field that likexian/whois-parser
// does not map onto Registrant.
func applyDNSPTFallback(result *DomainResult, raw string) {
	if result.Registrant.Name != "" {
		return
	}
	result.Registrant.Name = firstField(parseTCP43Fields(raw), "owner name")
}

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
		if isComment(line) {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
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

func parseTCP43Fields(raw string) map[string][]string {
	fields := make(map[string][]string)
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || isComment(line) {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		fields[key] = append(fields[key], strings.TrimSpace(value))
	}
	return fields
}

func firstField(fields map[string][]string, keys ...string) string {
	for _, key := range keys {
		if values := fields[key]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func isComment(line string) bool {
	return strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#")
}
