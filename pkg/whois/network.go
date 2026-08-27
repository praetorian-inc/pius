package whois

import (
	"context"
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

func (r *NetworkResult) Clean() {
	r.Query = strings.TrimSpace(r.Query)
	r.StartAddress = strings.TrimSpace(r.StartAddress)
	r.EndAddress = strings.TrimSpace(r.EndAddress)
	r.Handle = strings.TrimSpace(r.Handle)
	r.Name = strings.TrimSpace(r.Name)
	r.Type = strings.TrimSpace(r.Type)
	r.Status = trimStrings(r.Status)
	r.Country = strings.TrimSpace(r.Country)
	r.ParentHandle = strings.TrimSpace(r.ParentHandle)
	r.Registry = strings.TrimSpace(r.Registry)
	r.Server = strings.TrimSpace(r.Server)
	r.RDAPServer = strings.TrimSpace(r.RDAPServer)
	r.WhoisServer = strings.TrimSpace(r.WhoisServer)
	r.Sources = trimStrings(r.Sources)

	contacts := make([]NetworkContact, 0, len(r.Contacts))
	for _, contact := range r.Contacts {
		contacts = append(contacts, contact.Clean())
	}
	r.Contacts = mergeNetworkContacts(nil, contacts)
}

func (c NetworkContact) Clean() NetworkContact {
	c.Handle = strings.TrimSpace(c.Handle)
	c.Roles = trimStrings(c.Roles)
	c.Status = trimStrings(c.Status)
	c.Kind = strings.TrimSpace(c.Kind)
	c.Organization = clearIfPrivacy(c.Organization)
	c.Name = clearIfPrivacy(c.Name)
	c.Email = clearIfPrivacy(c.Email)
	c.Phone = clearIfPrivacy(c.Phone)
	c.Country = clearIfPrivacy(c.Country)
	c.Province = clearIfPrivacy(c.Province)
	c.City = clearIfPrivacy(c.City)
	c.Street = clearIfPrivacy(c.Street)
	c.PostalCode = clearIfPrivacy(c.PostalCode)
	return c
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

// LookupNetwork resolves an IP or CIDR using the default WHOIS cascade.
// It is retained as a compatibility wrapper around WHOIS.LookupNetwork.
func LookupNetwork(ctx context.Context, query string, opts ...Option) (NetworkResult, error) {
	return New(opts...).LookupNetwork(ctx, query)
}

// networkLookupState holds the mutable state for one network cascade walk.
type networkLookupState struct {
	target   networkTarget
	result   NetworkResult
	errs     []error
	resolved bool
}

// LookupNetwork resolves an IP or CIDR through the configured RDAP and TCP-43
// network clients.
func (w *Domain) LookupNetwork(ctx context.Context, query string) (NetworkResult, error) {
	target, err := parseNetworkTarget(query)
	if err != nil {
		return NetworkResult{}, err
	}

	state := networkLookupState{target: target}
	if w.doNetworkLookup(ctx, w.RDAPClient, &state) {
		return state.finish()
	}
	if w.doNetworkLookup(ctx, w.TCP43Client, &state) {
		return state.finish()
	}
	return state.finish()
}

// doNetworkLookup runs one network leg, validates its allocation and merges it
// into state. A useful RDAP identity ends the cascade before TCP-43 is needed.
func (w *Domain) doNetworkLookup(ctx context.Context, client WHOISClient, state *networkLookupState) (stop bool) {
	if err := ctx.Err(); err != nil {
		state.errs = append(state.errs, err)
		return true
	}

	result, err := client.LookupNetwork(ctx, state.target.query)
	if err != nil {
		state.errs = append(state.errs, err)
		return ctx.Err() != nil
	}

	result.Query = state.target.query
	result.Clean()
	if err := requireContainingAllocation(result, state.target); err != nil {
		state.errs = append(state.errs, fmt.Errorf("%s network lookup: %w", client.Name(), err))
		return false
	}

	state.result.Merge(result)
	state.resolved = true
	return client.Name() == SourceRDAP && hasUsefulNetworkIdentity(result.Contacts)
}

func (state *networkLookupState) finish() (NetworkResult, error) {
	if state.resolved {
		state.result.Query = state.target.query
		state.result.Clean()
		return state.result, nil
	}
	if joined := errors.Join(state.errs...); joined != nil {
		return NetworkResult{}, fmt.Errorf("whois: all methods failed for %s: %w", state.target.query, joined)
	}
	return NetworkResult{}, fmt.Errorf("whois: no source had a record for %s", state.target.query)
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

// Merge fills gaps from other while preserving the receiver as the base
// allocation. This keeps RDAP authoritative when it ran first while retaining
// TCP-43 contacts, provenance, server attribution, and raw evidence.
func (r *NetworkResult) Merge(other NetworkResult) {
	fill := func(base *string, value string) {
		if *base == "" {
			*base = value
		}
	}

	fill(&r.Query, other.Query)
	fill(&r.StartAddress, other.StartAddress)
	fill(&r.EndAddress, other.EndAddress)
	fill(&r.Handle, other.Handle)
	fill(&r.Name, other.Name)
	fill(&r.Type, other.Type)
	if len(r.Status) == 0 {
		r.Status = slices.Clone(other.Status)
	}
	fill(&r.Country, other.Country)
	fill(&r.ParentHandle, other.ParentHandle)
	fill(&r.Registry, other.Registry)
	fill(&r.Server, other.Server)
	fill(&r.RDAPServer, other.RDAPServer)
	fill(&r.WhoisServer, other.WhoisServer)
	fill(&r.Raw, other.Raw)
	r.Contacts = mergeNetworkContacts(r.Contacts, other.Contacts)
	r.Sources = mergeNetworkSources(r.Sources, other.Sources)
}

func mergeNetworkSources(base, other []string) []string {
	seen := make(map[string]bool, len(base)+len(other))
	out := make([]string, 0, len(base)+len(other))
	for _, source := range append(append([]string(nil), base...), other...) {
		source = strings.TrimSpace(source)
		if source == "" || seen[source] {
			continue
		}
		seen[source] = true
		out = append(out, source)
	}
	return out
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
