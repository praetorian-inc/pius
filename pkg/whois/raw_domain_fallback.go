package whois

import (
	"cmp"
	"strings"
)

var rawDomainFallbacks = map[string]func(*DomainResult, rawDomainRecord){
	"cl": applyNICChileFallback, // NIC Chile uses registry-specific labels rejected by the primary parser.
	"il": applyISOCILFallback,   // ISOC-IL publishes holder data in RPSL fields the primary parser ignores.
	"pt": applyDNSPTFallback,    // DNS.PT publishes registrant data under "Owner" fields the primary parser ignores.
}

func applyRawDomainFallback(result *DomainResult, record rawDomainRecord) {
	fallback, ok := rawDomainFallbacks[topLevelDomain(result.Domain)]
	if ok {
		fallback(result, record)
	}
}

func topLevelDomain(domain string) string {
	domain = strings.TrimRight(strings.ToLower(strings.TrimSpace(domain)), ".")
	if i := strings.LastIndexByte(domain, '.'); i >= 0 {
		return domain[i+1:]
	}
	return domain
}

// applyISOCILFallback fills empty registrant fields from the RPSL holder block.
func applyISOCILFallback(result *DomainResult, record rawDomainRecord) {
	if result.Registrant.Organization != "" && result.Registrant.Email != "" {
		return
	}

	var holder map[string]string
	for _, paragraph := range parseRPSLParagraphs(record.raw) {
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
		if IsEmail(email) {
			result.Registrant.Email = email
		}
	}
}

func applyNICChileFallback(result *DomainResult, record rawDomainRecord) {
	fields := record.fields
	result.Registrant.Name = cmp.Or(result.Registrant.Name, firstField(fields, "registrant name"))
	result.Registrant.Organization = cmp.Or(result.Registrant.Organization, firstField(fields, "registrant organisation"))
	result.Registrar = cmp.Or(result.Registrar, firstField(fields, "registrar name"))
	result.Created = cmp.Or(result.Created, firstField(fields, "creation date"))
	result.Expiration = cmp.Or(result.Expiration, firstField(fields, "expiration date"))
	if len(result.NameServers) == 0 {
		result.NameServers = append([]string(nil), fields["name server"]...)
	}
}

// applyDNSPTFallback fills fields from DNS.PT's Owner and Admin labels.
func applyDNSPTFallback(result *DomainResult, record rawDomainRecord) {
	fields := record.fields
	fillDNSPTContact(&result.Registrant, fields, "owner")
	fillDNSPTContact(&result.Admin, fields, "admin")
}

func fillDNSPTContact(contact *Contact, fields map[string][]string, prefix string) {
	contact.Name = cmp.Or(contact.Name, firstField(fields, prefix+" name"))
	contact.Street = cmp.Or(contact.Street, firstField(fields, prefix+" address"))
	contact.City = cmp.Or(contact.City, firstField(fields, prefix+" locality zipcode"))
	contact.Province = cmp.Or(contact.Province, firstField(fields, prefix+" locality"))
	contact.PostalCode = cmp.Or(contact.PostalCode, firstField(fields, prefix+" zipcode"))
	contact.Country = cmp.Or(contact.Country, firstField(fields, prefix+" country code"))
}

func parseRPSLParagraphs(raw string) []map[string]string {
	var paragraphs []map[string]string
	currentParagraph := -1
	for field := range scanTCP43Fields(raw) {
		if field.paragraph != currentParagraph {
			paragraphs = append(paragraphs, make(map[string]string))
			currentParagraph = field.paragraph
		}
		current := paragraphs[len(paragraphs)-1]
		if field.key == "descr" && current["first_descr"] == "" {
			current["first_descr"] = field.value
		}
		current[field.key] = field.value
	}
	return paragraphs
}
