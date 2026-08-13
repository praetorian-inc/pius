package whois

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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
	Country      string           `json:"country,omitempty"`
	ParentHandle string           `json:"parent_handle,omitempty"`
	Registry     string           `json:"registry,omitempty"`
	Server       string           `json:"server,omitempty"`
	Contacts     []NetworkContact `json:"contacts,omitempty"`
	Sources      []string         `json:"sources,omitempty"`
	Raw          string           `json:"raw,omitempty"`
}

// NetworkContact is an organization or person named by a network registration.
type NetworkContact struct {
	Handle       string   `json:"handle,omitempty"`
	Roles        []string `json:"roles,omitempty"`
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
	return c.Organization == "" && c.Name == "" && c.Email == ""
}

// ValidateNetworkTarget checks that query is an IP address or CIDR.
func ValidateNetworkTarget(query string) error {
	_, err := parseNetworkTarget(query)
	return err
}

// LookupNetwork resolves an IP or CIDR through RDAP with TCP-43 fallback.
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
	if rdapErr == nil && len(rdapResult.Contacts) > 0 {
		return rdapResult, nil
	}

	tcpResult, tcpErr := tcp43NetworkLookup(ctx, target)
	if rdapErr == nil {
		if tcpErr == nil {
			rdapResult.Contacts = mergeNetworkContacts(rdapResult.Contacts, tcpResult.Contacts)
			rdapResult.Sources = append(rdapResult.Sources, "whois")
			rdapResult.Server = tcpResult.Server
			rdapResult.Raw = tcpResult.Raw
			if rdapResult.Registry == "" {
				rdapResult.Registry = tcpResult.Registry
			}
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
