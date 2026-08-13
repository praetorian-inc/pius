package whois

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/openrdap/rdap"
)

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
			if entity.VCard != nil {
				contact := networkContactFromVCard(entity.Handle, entity.Roles, entity.VCard, direct)
				if !contact.IsEmpty() {
					contacts = append(contacts, contact)
				}
			}
			visit(entity.Entities, false)
		}
	}
	visit(entities, true)
	return mergeNetworkContacts(nil, contacts)
}

func networkContactFromVCard(handle string, roles []string, vcard *rdap.VCard, direct bool) NetworkContact {
	base := contactFromVCard(vcard).Scrub()
	contact := NetworkContact{
		Handle:       handle,
		Roles:        roles,
		Kind:         firstVCardValue(vcard, "kind"),
		Direct:       direct,
		Organization: base.Organization,
		Name:         base.Name,
		Email:        clearIfPrivacy(vcard.Email()),
		Phone:        clearIfPrivacy(strings.TrimPrefix(vcard.Tel(), "tel:")),
		Country:      base.Country,
		Province:     base.Province,
		City:         base.City,
		Street:       clearIfPrivacy(vcard.StreetAddress()),
		PostalCode:   clearIfPrivacy(vcard.PostalCode()),
	}
	if len(contact.Roles) == 0 {
		contact.Roles = []string{"unknown"}
	}
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
