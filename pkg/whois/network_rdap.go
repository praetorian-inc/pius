package whois

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
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
