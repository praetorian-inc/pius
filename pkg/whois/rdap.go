package whois

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/openrdap/rdap"
)

// rdapLookup performs an RDAP domain lookup, following registrar "related"
// links when the registry response lacks registrant data (common under GDPR).
func rdapLookup(ctx context.Context, httpClient *http.Client, domain string) (Result, error) {
	client := &rdap.Client{}
	if httpClient != nil {
		client.HTTP = httpClient
	}

	req := &rdap.Request{
		Type:       rdap.DomainRequest,
		Query:      domain,
		FetchRoles: []string{"all"},
	}
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("RDAP lookup failed for %s: %w", domain, err)
	}
	domainResp, ok := resp.Object.(*rdap.Domain)
	if !ok {
		return Result{}, fmt.Errorf("unexpected RDAP response type for %s", domain)
	}

	result := mapRDAPToResult(domain, domainResp)

	// Follow registrar link if registrant data is missing.
	if result.Registrant.IsEmpty() {
		enrichFromRegistrar(ctx, client, &result, domainResp)
	}

	return result, nil
}

func mapRDAPToResult(domain string, resp *rdap.Domain) Result {
	r := Result{Domain: domain}

	for _, event := range resp.Events {
		switch event.Action {
		case "registration":
			r.Created = event.Date
		case "expiration":
			r.Expiration = event.Date
		case "last changed":
			r.Updated = event.Date
		}
	}

	for _, ns := range resp.Nameservers {
		if ns.LDHName != "" {
			r.NameServers = append(r.NameServers, ns.LDHName)
		}
	}
	r.Status = resp.Status

	if c := extractEntity(resp.Entities, "registrar"); c != nil {
		if c.VCard != nil {
			r.Registrar = c.VCard.Name()
		} else {
			r.Registrar = c.Handle
		}
	}

	r.Registrant = extractContact(resp.Entities, "registrant")
	r.Admin = extractContact(resp.Entities, "administrative")
	r.Tech = extractContact(resp.Entities, "technical")
	r.Billing = extractContact(resp.Entities, "billing")

	return r
}

func enrichFromRegistrar(ctx context.Context, client *rdap.Client, result *Result, domainResp *rdap.Domain) {
	var registrarURL string
	for _, link := range domainResp.Links {
		if link.Rel == "related" && link.Type == "application/rdap+json" {
			registrarURL = link.Href
			break
		}
	}
	if registrarURL == "" {
		return
	}
	parsed, err := url.Parse(registrarURL)
	if err != nil {
		return
	}

	req := &rdap.Request{Type: rdap.RawRequest, Server: parsed}
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	d, ok := resp.Object.(*rdap.Domain)
	if !ok {
		return
	}

	registrant := extractContact(d.Entities, "registrant")
	if !registrant.IsEmpty() {
		result.Registrant = registrant
	}
}

func extractEntity(entities []rdap.Entity, role string) *rdap.Entity {
	for i := range entities {
		if slices.Contains(entities[i].Roles, role) {
			return &entities[i]
		}
	}
	return nil
}

func extractContact(entities []rdap.Entity, role string) Contact {
	e := extractEntity(entities, role)
	if e == nil || e.VCard == nil {
		return Contact{}
	}
	c := Contact{
		Name:         e.VCard.Name(),
		Organization: extractOrgFromVCard(e.VCard),
	}
	c.Country, c.Province, c.City = extractAddressFromVCard(e.VCard)
	return c
}

func extractOrgFromVCard(vcard *rdap.VCard) string {
	props := vcard.Get("org")
	if len(props) == 0 {
		return ""
	}
	if v, ok := props[0].Value.(string); ok {
		return v
	}
	return ""
}

func extractAddressFromVCard(vcard *rdap.VCard) (country, province, city string) {
	adrProps := vcard.Get("adr")
	if len(adrProps) == 0 {
		return vcard.Country(), "", ""
	}
	if params := adrProps[0].Parameters; params != nil {
		if cc, ok := params["cc"]; ok && len(cc) > 0 {
			country = cc[0]
		}
	}
	// RFC 6350 adr structured value: [pobox, ext, street, locality, region, postal, country]
	if addrSlice, ok := adrProps[0].Value.([]any); ok {
		if len(addrSlice) > 3 {
			if v, ok := addrSlice[3].(string); ok {
				city = v
			}
		}
		if len(addrSlice) > 4 {
			if v, ok := addrSlice[4].(string); ok {
				province = v
			}
		}
	}
	if country == "" {
		country = vcard.Country()
	}
	return country, province, city
}

