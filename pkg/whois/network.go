package whois

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ErrAllocationDoesNotContainTarget means applying the returned registration
// to the complete input range would make an unsafe ownership claim.
var ErrAllocationDoesNotContainTarget = errors.New("allocation does not contain target")

// NetworkResult is the structured registration record for an IP allocation.
type NetworkResult struct {
	Query        string           `json:"query"`
	StartAddress string           `json:"start_address,omitempty"`
	EndAddress   string           `json:"end_address,omitempty"`
	Handle       string           `json:"handle,omitempty"`
	Name         string           `json:"name,omitempty"`
	Type         string           `json:"type,omitempty"`
	Status       []string         `json:"status,omitempty"`
	Country      string           `json:"country,omitempty"`
	ParentHandle string           `json:"parent_handle,omitempty"`
	Registry     string           `json:"registry,omitempty"`
	Server       string           `json:"server,omitempty"`
	RDAPServer   string           `json:"rdap_server,omitempty"`
	RDAPURL      string           `json:"rdap_url,omitempty"`
	RDAPResponse json.RawMessage  `json:"rdap_response,omitempty"`
	WhoisServer  string           `json:"whois_server,omitempty"`
	Contacts     []NetworkContact `json:"contacts,omitempty"`
	Sources      []string         `json:"sources,omitempty"`
	Raw          string           `json:"raw,omitempty"`
}

// NetworkContact is an organization or person named by a network registration.
type NetworkContact struct {
	Handle       string   `json:"handle,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Status       []string `json:"status,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	Direct       bool     `json:"direct,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Name         string   `json:"name,omitempty"`
	Email        string   `json:"email,omitempty"`
	Phone        string   `json:"phone,omitempty"`
	Country      string   `json:"country,omitempty"`
	Province     string   `json:"province,omitempty"`
	City         string   `json:"city,omitempty"`
	Street       string   `json:"street,omitempty"`
	PostalCode   string   `json:"postal_code,omitempty"`
}

func (c NetworkContact) IsEmpty() bool {
	return c.Organization == "" && c.Name == "" && c.Email == "" && len(c.Status) == 0
}

func (c NetworkContact) HasRole(role string) bool {
	return slices.Contains(c.Roles, role)
}

func (c NetworkContact) IsMaintainer() bool {
	return strings.HasSuffix(strings.ToUpper(c.Handle), "-MNT")
}

// IsPrivacyProtected recognizes the entity statuses RFC 9083 defines for
// withheld or altered contact data.
// https://www.rfc-editor.org/rfc/rfc9083.html#section-13
func (c NetworkContact) IsPrivacyProtected() bool {
	for _, status := range c.Status {
		switch strings.ToLower(status) {
		case "private", "removed", "obscured":
			return true
		}
	}
	return false
}

func PreferredNetworkRole(contacts []NetworkContact) string {
	for _, contact := range contacts {
		if contact.Direct && !contact.IsPrivacyProtected() && contact.HasRole("customer") {
			return "customer"
		}
	}
	return "registrant"
}

// ValidateNetworkTarget checks that query is an IP address or CIDR.
func ValidateNetworkTarget(query string) error {
	_, err := parseNetworkTarget(query)
	return err
}

// LookupNetwork resolves an IP or CIDR through RDAP and TCP-43, merging both
// protocol responses when available.
func LookupNetwork(ctx context.Context, query string, opts ...Option) (NetworkResult, error) {
	target, err := parseNetworkTarget(query)
	if err != nil {
		return NetworkResult{}, err
	}

	cfg := config{}
	for _, option := range opts {
		option(&cfg)
	}

	rdapResult, rdapErr := rdapNetworkLookup(ctx, cfg.httpClient, target)
	tcpResult, tcpErr := tcp43NetworkLookup(ctx, target)
	if rdapErr == nil {
		if tcpErr == nil {
			mergeTCP43NetworkResult(&rdapResult, tcpResult)
		}
		return rdapResult, nil
	}
	if tcpErr == nil {
		return tcpResult, nil
	}

	return NetworkResult{}, fmt.Errorf("whois: all methods failed for %s: %w", target.query, errors.Join(rdapErr, tcpErr))
}

type networkTarget struct {
	query  string
	prefix netip.Prefix
}

func parseNetworkTarget(query string) (networkTarget, error) {
	if prefix, err := netip.ParsePrefix(query); err == nil {
		prefix = prefix.Masked()
		return networkTarget{query: prefix.String(), prefix: prefix}, nil
	}

	addr, err := netip.ParseAddr(query)
	if err != nil {
		return networkTarget{}, fmt.Errorf("whois: invalid IP or CIDR %q", query)
	}
	return networkTarget{
		query:  addr.String(),
		prefix: netip.PrefixFrom(addr, addr.BitLen()),
	}, nil
}

func allocationContainsTarget(start, end netip.Addr, target networkTarget) bool {
	if !start.IsValid() || !end.IsValid() || start.BitLen() != target.prefix.Addr().BitLen() || end.BitLen() != start.BitLen() {
		return false
	}
	return start.Compare(target.prefix.Addr()) <= 0 && end.Compare(lastAddress(target.prefix)) >= 0
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	bytes := addr.AsSlice()
	for bit := prefix.Bits(); bit < addr.BitLen(); bit++ {
		bytes[bit/8] |= 1 << (7 - bit%8)
	}
	last, _ := netip.AddrFromSlice(bytes)
	return last.Unmap()
}

func requireContainingAllocation(result NetworkResult, target networkTarget) error {
	start, startErr := netip.ParseAddr(result.StartAddress)
	end, endErr := netip.ParseAddr(result.EndAddress)
	if startErr != nil || endErr != nil {
		return fmt.Errorf("whois: response has no usable allocation range")
	}
	if !allocationContainsTarget(start.Unmap(), end.Unmap(), target) {
		return fmt.Errorf("%w: %s-%s does not contain %s", ErrAllocationDoesNotContainTarget, start, end, target.query)
	}
	return nil
}

func hasUsefulNetworkIdentity(contacts []NetworkContact) bool {
	preferredRole := PreferredNetworkRole(contacts)
	for _, contact := range contacts {
		if !contact.Direct || contact.IsPrivacyProtected() {
			continue
		}
		if !contact.HasRole(preferredRole) || contact.IsMaintainer() {
			continue
		}

		identity := contact.Organization
		switch contact.Kind {
		case "org":
			if identity == "" {
				identity = contact.Name
			}
		case "individual":
			identity = contact.Name
		default:
			identity = ""
		}
		if identity != "" || IsEmail(contact.Email) {
			return true
		}
	}
	return false
}

func mergeTCP43NetworkResult(rdapResult *NetworkResult, tcpResult NetworkResult) {
	rdapResult.Contacts = mergeNetworkContacts(rdapResult.Contacts, tcpResult.Contacts)
	rdapResult.Sources = append(rdapResult.Sources, "whois")
	rdapResult.WhoisServer = tcpResult.WhoisServer
	rdapResult.Raw = tcpResult.Raw
	if rdapResult.Registry == "" {
		rdapResult.Registry = tcpResult.Registry
	}
}

func mergeNetworkContacts(base, other []NetworkContact) []NetworkContact {
	seen := make(map[string]bool, len(base)+len(other))
	out := make([]NetworkContact, 0, len(base)+len(other))
	for _, contact := range append(append([]NetworkContact(nil), base...), other...) {
		key := fmt.Sprintf("%s\x00%v\x00%s\x00%t\x00%s\x00%s\x00%s", contact.Handle, contact.Roles, contact.Kind, contact.Direct, contact.Organization, contact.Name, contact.Email)
		if contact.IsEmpty() || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, contact)
	}
	return out
}
