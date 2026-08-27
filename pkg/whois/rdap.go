package whois

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/openrdap/rdap"
)

// RDAPClient implements the RDAP registration lookup. It satisfies
// WHOISClient so tests can substitute a fake without touching the network.
//
// RDAP leads the cascade because it returns structured fields and standardized
// dates. Later legs fill missing registration fields when its record is incomplete.
type RDAPClient struct {
	httpClient *http.Client
}

// NewRDAPClient returns an RDAP resolver. A nil httpClient uses the rdap
// package's default.
func NewRDAPClient(httpClient *http.Client) *RDAPClient {
	return &RDAPClient{httpClient: httpClient}
}

func (r *RDAPClient) Name() string { return SourceRDAP }

func (r *RDAPClient) LookupDomain(ctx context.Context, domain string) (result DomainResult, err error) {
	defer logLookup(r.Name(), domain, time.Now(), &result, &err)

	result, err = rdapLookup(ctx, r.httpClient, domain)
	if err != nil {
		return DomainResult{}, err
	}
	result.Sources = []string{SourceRDAP}
	return result, nil
}

// rdapLookup performs an RDAP domain lookup, following registrar "related"
// links when the registry response lacks registrant data (common under GDPR).
func rdapLookup(ctx context.Context, httpClient *http.Client, domain string) (DomainResult, error) {
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
		return DomainResult{}, fmt.Errorf("RDAP lookup failed for %s: %w", domain, err)
	}
	domainResp, ok := resp.Object.(*rdap.Domain)
	if !ok {
		return DomainResult{}, fmt.Errorf("unexpected RDAP response type for %s", domain)
	}

	result := mapRDAPToResult(domain, domainResp)

	// Follow registrar link if registrant data is missing.
	if result.Registrant.IsEmpty() {
		enrichFromRegistrar(ctx, client, &result, domainResp)
	}
	result.Normalize()

	return result, nil
}

func mapRDAPToResult(domain string, resp *rdap.Domain) DomainResult {
	r := DomainResult{Domain: domain}

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

func enrichFromRegistrar(ctx context.Context, client *rdap.Client, result *DomainResult, domainResp *rdap.Domain) {
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
	return contactFromVCard(e.VCard)
}

func (r *RDAPClient) LookupNetwork(ctx context.Context, query string) (NetworkResult, error) {
	target, err := parseNetworkTarget(query)
	if err != nil {
		return NetworkResult{}, err
	}
	return rdapNetworkLookup(ctx, r.httpClient, target)
}

func rdapNetworkLookup(ctx context.Context, httpClient *http.Client, target networkTarget) (NetworkResult, error) {
	client := &rdap.Client{}
	if httpClient != nil {
		client.HTTP = httpClient
	}

	request := rdap.NewIPRequest(net.IP(target.prefix.Addr().AsSlice())).WithContext(ctx)
	request.FetchRoles = []string{"all"}
	response, err := client.Do(request)
	if err != nil {
		return NetworkResult{}, fmt.Errorf("RDAP lookup failed for %s: %w", target.query, err)
	}

	network, ok := response.Object.(*rdap.IPNetwork)
	if !ok {
		return NetworkResult{}, fmt.Errorf("unexpected RDAP response type for %s", target.query)
	}

	result := mapRDAPToNetworkResult(target.query, network)
	result.Server = rdapResponseServer(response)
	result.RDAPServer = result.Server
	result.Normalize()
	if err := requireContainingAllocation(result, target); err != nil {
		return NetworkResult{}, err
	}
	return result, nil
}

func rdapResponseServer(response *rdap.Response) string {
	for _, httpResponse := range response.HTTP {
		parsed, err := url.Parse(httpResponse.URL)
		if err == nil && parsed.Host != "" {
			return parsed.Host
		}
	}
	return ""
}

func mapRDAPToNetworkResult(query string, network *rdap.IPNetwork) NetworkResult {
	return NetworkResult{
		Query:        query,
		StartAddress: network.StartAddress,
		EndAddress:   network.EndAddress,
		Handle:       network.Handle,
		Name:         network.Name,
		Type:         network.Type,
		Status:       slices.Clone(network.Status),
		Country:      network.Country,
		ParentHandle: network.ParentHandle,
		Registry:     network.Port43,
		Contacts:     rdapNetworkContacts(network.Entities),
		Sources:      []string{"rdap"},
	}
}

func rdapNetworkContacts(entities []rdap.Entity) []NetworkContact {
	var contacts []NetworkContact
	var visit func([]rdap.Entity, bool)
	visit = func(current []rdap.Entity, direct bool) {
		for i := range current {
			entity := &current[i]
			contact := networkContactFromEntity(entity, direct)
			if !contact.IsEmpty() {
				contacts = append(contacts, contact)
			}
			visit(entity.Entities, false)
		}
	}
	visit(entities, true)
	return mergeNetworkContacts(nil, contacts)
}

func networkContactFromEntity(entity *rdap.Entity, direct bool) NetworkContact {
	contact := NetworkContact{
		Handle: entity.Handle,
		Roles:  entity.Roles,
		Status: slices.Clone(entity.Status),
		Direct: direct,
	}
	if len(contact.Roles) == 0 {
		contact.Roles = []string{"unknown"}
	}
	if entity.VCard == nil {
		return contact
	}

	contact.Contact = contactFromVCard(entity.VCard)
	contact.Kind = firstVCardValue(entity.VCard, "kind")
	contact.Email = entity.VCard.Email()
	contact.Phone = strings.TrimPrefix(entity.VCard.Tel(), "tel:")
	return contact
}

func firstVCardValue(vcard *rdap.VCard, name string) string {
	properties := vcard.Get(name)
	if len(properties) == 0 {
		return ""
	}
	values := properties[0].Values()
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func contactFromVCard(vcard *rdap.VCard) Contact {
	contact := Contact{
		Name:         vcard.Name(),
		Organization: extractOrgFromVCard(vcard),
		Street:       vcard.StreetAddress(),
		PostalCode:   vcard.PostalCode(),
	}
	contact.Country, contact.Province, contact.City = extractAddressFromVCard(vcard)
	if contact.Street == "" && contact.City == "" && contact.Province == "" && contact.PostalCode == "" {
		contact.Street = addressLabelFromVCard(vcard)
	}
	return contact.Normalize()
}

func addressLabelFromVCard(vcard *rdap.VCard) string {
	for _, property := range vcard.Get("adr") {
		for _, label := range property.Parameters["label"] {
			lines := make([]string, 0, strings.Count(label, "\n")+1)
			for line := range strings.Lines(label) {
				if line = strings.TrimSpace(line); line != "" {
					lines = append(lines, line)
				}
			}
			if len(lines) > 0 {
				return strings.Join(lines, ", ")
			}
		}
	}
	return ""
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
