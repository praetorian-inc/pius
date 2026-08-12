package whois

import (
	"context"
	"fmt"
	"net"
	"net/http"
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
	if err := requireContainingAllocation(result, target); err != nil {
		return NetworkResult{}, err
	}
	return result, nil
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
	var visit func([]rdap.Entity)
	visit = func(current []rdap.Entity) {
		for i := range current {
			entity := &current[i]
			if entity.VCard != nil {
				contact := networkContactFromVCard(entity.Roles, entity.VCard)
				if !contact.IsEmpty() {
					contacts = append(contacts, contact)
				}
			}
			visit(entity.Entities)
		}
	}
	visit(entities)
	return mergeNetworkContacts(nil, contacts)
}

func networkContactFromVCard(roles []string, vcard *rdap.VCard) NetworkContact {
	base := contactFromVCard(vcard).Scrub()
	contact := NetworkContact{
		Roles:        roles,
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
