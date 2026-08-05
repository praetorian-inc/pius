package domains

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
)

// rdapLookup performs an RDAP domain lookup and returns a WhoisResult.
// It follows registrar "related" links to fetch full contact info when
// the registry response lacks registrant data (common with GDPR redaction).
func rdapLookup(httpClient *http.Client, domain string) (WhoisResult, error) {
	client := &rdap.Client{}
	if httpClient != nil {
		client.HTTP = httpClient
	}

	req := &rdap.Request{
		Type:       rdap.DomainRequest,
		Query:      domain,
		FetchRoles: []string{"all"},
	}

	resp, err := client.Do(req)
	if err != nil {
		return WhoisResult{}, fmt.Errorf("RDAP lookup failed for %s: %w", domain, err)
	}

	domainResp, ok := resp.Object.(*rdap.Domain)
	if !ok {
		return WhoisResult{}, fmt.Errorf("unexpected RDAP response type for %s", domain)
	}

	result := mapRDAPToResult(domain, domainResp)

	// Try registrar fallback if registrant data is missing
	if result.Registrant == nil {
		enrichFromRegistrar(client, &result, domainResp)
	}

	return result, nil
}

// isDomainNotFound reports whether err means the domain is definitively
// unregistered. Matches openrdap's ObjectDoesNotExist (RDAP 404) and
// whoisparser's ErrNotFoundDomain.
func isDomainNotFound(err error) bool {
	if err == nil {
		return false
	}
	if isErr(err, whoisparser.ErrNotFoundDomain) {
		return true
	}
	var ce *rdap.ClientError
	if errAs(err, &ce) {
		return ce.Type == rdap.ObjectDoesNotExist
	}
	return false
}

// Seams for testing.
var (
	isErr = func(err, target error) bool {
		return err == target || strings.Contains(err.Error(), target.Error())
	}
	errAs = func(err error, target any) bool {
		// Use type assertion approach for the concrete case
		if ce, ok := target.(**rdap.ClientError); ok {
			// Walk the error chain manually
			for err != nil {
				if v, ok := err.(*rdap.ClientError); ok {
					*ce = v
					return true
				}
				if u, ok := err.(interface{ Unwrap() error }); ok {
					err = u.Unwrap()
				} else {
					return false
				}
			}
		}
		return false
	}
)

func mapRDAPToResult(domain string, resp *rdap.Domain) WhoisResult {
	result := WhoisResult{
		Domain: &whoisparser.Domain{
			Domain:      resp.LDHName,
			Status:      resp.Status,
			NameServers: make([]string, 0),
		},
	}

	for _, event := range resp.Events {
		switch event.Action {
		case "registration":
			result.Domain.CreatedDate = event.Date
		case "expiration":
			result.Domain.ExpirationDate = event.Date
		case "last changed":
			result.Domain.UpdatedDate = event.Date
		}
	}

	for _, ns := range resp.Nameservers {
		if ns.LDHName != "" {
			result.Domain.NameServers = append(result.Domain.NameServers, ns.LDHName)
		}
	}

	result.Registrar = extractRegistrarEntity(resp.Entities)
	result.Registrant = extractRegistrantEntity(resp.Entities)
	result.Raw = formatRDAPText(&result, domain)

	return result
}

func enrichFromRegistrar(client *rdap.Client, result *WhoisResult, domainResp *rdap.Domain) {
	registrarDomain := followRegistrarLink(client, domainResp)
	if registrarDomain == nil {
		return
	}
	registrant := extractRegistrantEntity(registrarDomain.Entities)
	if registrant == nil {
		return
	}
	result.Registrant = registrant
	result.Raw = formatRDAPText(result, result.Domain.Domain)
}

func followRegistrarLink(client *rdap.Client, domainResp *rdap.Domain) *rdap.Domain {
	var registrarURL string
	for _, link := range domainResp.Links {
		if link.Rel == "related" && link.Type == "application/rdap+json" {
			registrarURL = link.Href
			break
		}
	}
	if registrarURL == "" {
		return nil
	}

	parsed, err := url.Parse(registrarURL)
	if err != nil {
		return nil
	}

	req := &rdap.Request{
		Type:   rdap.RawRequest,
		Server: parsed,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	d, ok := resp.Object.(*rdap.Domain)
	if !ok {
		return nil
	}
	return d
}

func extractRegistrantEntity(entities []rdap.Entity) *whoisparser.Contact {
	for _, e := range entities {
		if !hasRole(e.Roles, "registrant") {
			continue
		}
		c := &whoisparser.Contact{}
		if e.VCard == nil {
			return c
		}
		c.Name = e.VCard.Name()
		c.Organization = extractOrgFromVCard(e.VCard)
		c.Country, c.Province = extractAddressFromVCard(e.VCard)
		return c
	}
	return nil
}

func extractRegistrarEntity(entities []rdap.Entity) *whoisparser.Contact {
	for _, e := range entities {
		if !hasRole(e.Roles, "registrar") {
			continue
		}
		c := &whoisparser.Contact{}
		if e.VCard != nil {
			c.Name = e.VCard.Name()
			c.Organization = e.VCard.Name()
		} else {
			c.Name = e.Handle
		}
		return c
	}
	return nil
}

func extractOrgFromVCard(vcard *rdap.VCard) string {
	if vcard == nil {
		return ""
	}
	props := vcard.Get("org")
	if len(props) == 0 {
		return ""
	}
	if v, ok := props[0].Value.(string); ok {
		return v
	}
	return ""
}

func extractAddressFromVCard(vcard *rdap.VCard) (country, province string) {
	if vcard == nil {
		return "", ""
	}
	adrProps := vcard.Get("adr")
	if len(adrProps) == 0 {
		return vcard.Country(), ""
	}
	if params := adrProps[0].Parameters; params != nil {
		if cc, ok := params["cc"]; ok && len(cc) > 0 {
			country = cc[0]
		}
	}
	if addrSlice, ok := adrProps[0].Value.([]interface{}); ok && len(addrSlice) > 4 {
		if region, ok := addrSlice[4].(string); ok {
			province = region
		}
	}
	if country == "" {
		country = vcard.Country()
	}
	return country, province
}

func hasRole(roles []string, target string) bool {
	for _, r := range roles {
		if r == target {
			return true
		}
	}
	return false
}

func formatRDAPText(result *WhoisResult, domain string) string {
	var sb strings.Builder
	sb.WriteString("Domain Name: ")
	sb.WriteString(domain)
	sb.WriteString("\n")

	if result.Domain != nil {
		if result.Domain.CreatedDate != "" {
			sb.WriteString("Creation Date: ")
			sb.WriteString(result.Domain.CreatedDate)
			sb.WriteString("\n")
		}
		if result.Domain.UpdatedDate != "" {
			sb.WriteString("Updated Date: ")
			sb.WriteString(result.Domain.UpdatedDate)
			sb.WriteString("\n")
		}
		if result.Domain.ExpirationDate != "" {
			sb.WriteString("Expiration Date: ")
			sb.WriteString(result.Domain.ExpirationDate)
			sb.WriteString("\n")
		}
		if len(result.Domain.NameServers) > 0 {
			sb.WriteString("\nName Servers:\n")
			for _, ns := range result.Domain.NameServers {
				sb.WriteString("   ")
				sb.WriteString(ns)
				sb.WriteString("\n")
			}
		}
	}

	if result.Registrar != nil {
		sb.WriteString("\nRegistrar: ")
		sb.WriteString(result.Registrar.Name)
		sb.WriteString("\n")
	}

	if result.Registrant != nil {
		sb.WriteString("\nRegistrant:\n")
		if result.Registrant.Organization != "" {
			sb.WriteString("   Organization: ")
			sb.WriteString(result.Registrant.Organization)
			sb.WriteString("\n")
		}
		if result.Registrant.Name != "" {
			sb.WriteString("   Name: ")
			sb.WriteString(result.Registrant.Name)
			sb.WriteString("\n")
		}
		if result.Registrant.Country != "" {
			sb.WriteString("   Country: ")
			sb.WriteString(result.Registrant.Country)
			sb.WriteString("\n")
		}
		if result.Registrant.Province != "" {
			sb.WriteString("   State/Province: ")
			sb.WriteString(result.Registrant.Province)
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n>>> Data retrieved via RDAP (Registration Data Access Protocol)\n")
	return sb.String()
}

// hasContacts reports whether a WhoisResult has any usable contact identity.
func hasContacts(result WhoisResult) bool {
	contacts := []*whoisparser.Contact{result.Registrant, result.Administrative, result.Technical, result.Billing}
	for _, c := range contacts {
		if c == nil {
			continue
		}
		if c.Email != "" || c.Name != "" || c.Organization != "" {
			return true
		}
	}
	return false
}

// parseExpirationTime attempts to parse the expiration date string into a time.Time.
func parseExpirationTime(s string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
