package whois

import (
	"cmp"
	"errors"
	"strings"

	whoisparser "github.com/likexian/whois-parser"
)

var (
	errBootstrapDomainResponse = errors.New("whois: bootstrap response is not a domain record")
	errRegistryAccessDenied    = errors.New("whois: registry denied access")
)

type rawDomainRecord struct {
	raw    string
	fields map[string][]string
}

func newRawDomainRecord(raw string) rawDomainRecord {
	return rawDomainRecord{raw: raw, fields: parseTCP43Fields(raw)}
}

func parseRawDomainResult(domain, raw string) (DomainResult, error) {
	if err := validateRawDomainResponse(raw); err != nil {
		return DomainResult{}, err
	}

	result := DomainResult{Domain: domain}
	parsed, parseErr := whoisparser.Parse(raw)
	if parseErr == nil {
		result = mapParsedToResult(domain, parsed)
	}

	record := newRawDomainRecord(raw)
	applyRawDomainFields(&result, record.fields)
	applyRawDomainFallback(&result, record)
	result.Normalize()

	if parseErr == nil {
		return result, nil
	}
	// Registry-specific fallbacks may recover substantive data from formats the
	// primary parser rejects, but never override a definitive not-found result.
	if errors.Is(parseErr, whoisparser.ErrNotFoundDomain) || !result.hasRegistrationData() {
		return DomainResult{}, parseErr
	}
	return result, nil
}

func validateRawDomainResponse(raw string) error {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "% iana whois server"):
		return errBootstrapDomainResponse
	case strings.Contains(lower, "requests of this client are not permitted"):
		return errRegistryAccessDenied
	default:
		return nil
	}
}

func applyRawDomainFields(result *DomainResult, fields map[string][]string) {
	// whoisparser reduces DNSSEC to a bool; preserve the registry's exact value.
	if dnssec := firstField(fields, "dnssec"); dnssec != "" {
		result.DNSSEC = dnssec
	}
	result.WhoisServer = cmp.Or(result.WhoisServer, firstField(fields, "registry whois"))
}

func mapParsedToResult(domain string, info whoisparser.WhoisInfo) DomainResult {
	result := DomainResult{Domain: domain}

	if info.Domain != nil {
		result.Created = info.Domain.CreatedDate
		result.Updated = info.Domain.UpdatedDate
		result.Expiration = info.Domain.ExpirationDate
		result.NameServers = info.Domain.NameServers
		result.Status = info.Domain.Status
		result.WhoisServer = info.Domain.WhoisServer
		if info.Domain.DNSSec {
			result.DNSSEC = "signed"
		}
	}
	if info.Registrar != nil {
		result.Registrar = info.Registrar.Name
	}
	result.Registrant = contactFromParsed(info.Registrant)
	result.Admin = contactFromParsed(info.Administrative)
	result.Tech = contactFromParsed(info.Technical)
	result.Billing = contactFromParsed(info.Billing)
	return result
}

func contactFromParsed(contact *whoisparser.Contact) Contact {
	if contact == nil {
		return Contact{}
	}
	return Contact{
		Organization: contact.Organization,
		Name:         contact.Name,
		Email:        contact.Email,
		Country:      contact.Country,
		Province:     contact.Province,
		City:         contact.City,
		Street:       contact.Street,
		PostalCode:   contact.PostalCode,
		Phone:        contact.Phone,
	}
}
