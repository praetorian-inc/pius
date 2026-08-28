package whois

import (
	"cmp"
	"slices"
	"strings"
)

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

func (r *NetworkResult) Normalize() {
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
		contacts = append(contacts, contact.normalize())
	}
	r.Contacts = mergeNetworkContacts(nil, contacts)
}

// Merge fills gaps from other while preserving the receiver as the base
// allocation. This keeps RDAP authoritative when it ran first while retaining
// TCP-43 contacts, provenance, server attribution, and raw evidence.
func (r *NetworkResult) Merge(other NetworkResult) {
	r.Normalize()
	other.Normalize()

	r.Query = cmp.Or(r.Query, other.Query)
	r.StartAddress = cmp.Or(r.StartAddress, other.StartAddress)
	r.EndAddress = cmp.Or(r.EndAddress, other.EndAddress)
	r.Handle = cmp.Or(r.Handle, other.Handle)
	r.Name = cmp.Or(r.Name, other.Name)
	r.Type = cmp.Or(r.Type, other.Type)
	if len(r.Status) == 0 {
		r.Status = slices.Clone(other.Status)
	}
	r.Country = cmp.Or(r.Country, other.Country)
	r.ParentHandle = cmp.Or(r.ParentHandle, other.ParentHandle)
	r.Registry = cmp.Or(r.Registry, other.Registry)
	r.Server = cmp.Or(r.Server, other.Server)
	r.RDAPServer = cmp.Or(r.RDAPServer, other.RDAPServer)
	r.WhoisServer = cmp.Or(r.WhoisServer, other.WhoisServer)
	r.Raw = cmp.Or(r.Raw, other.Raw)
	r.Contacts = mergeNetworkContacts(r.Contacts, other.Contacts)
	r.Sources = mergeNetworkSources(r.Sources, other.Sources)
}

// PreferredContacts returns direct, usable contacts for the most specific ownership role.
func (r NetworkResult) PreferredContacts() []NetworkContact {
	return r.ContactsForRole(r.preferredContactRole())
}

// ContactsForRole returns direct, usable contacts for role.
func (r NetworkResult) ContactsForRole(role string) []NetworkContact {
	contacts := make([]NetworkContact, 0, len(r.Contacts))
	for _, contact := range r.Contacts {
		if contact.eligibleForRole(role) {
			contacts = append(contacts, contact)
		}
	}
	return contacts
}

func (r NetworkResult) preferredContactRole() string {
	for _, contact := range r.Contacts {
		if contact.eligibleForRole("customer") {
			return "customer"
		}
	}
	return "registrant"
}

func (r NetworkResult) hasAllocation() bool {
	return r.StartAddress != "" && r.EndAddress != ""
}

func (r NetworkResult) hasUsefulIdentity() bool {
	return len(r.PreferredContacts()) > 0
}

// NetworkContact is an organization or person named by a network registration.
type NetworkContact struct {
	Handle string   `json:"handle,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Status []string `json:"status,omitempty"`
	Kind   string   `json:"kind,omitempty"`
	Direct bool     `json:"direct,omitempty"`
	Contact
}

func (c NetworkContact) normalize() NetworkContact {
	c.Handle = strings.TrimSpace(c.Handle)
	c.Roles = trimStrings(c.Roles)
	c.Status = trimStrings(c.Status)
	c.Kind = strings.TrimSpace(c.Kind)
	c.Contact = c.Contact.Normalize()
	return c
}

func (c NetworkContact) IsEmpty() bool {
	return c.Contact == (Contact{}) && len(c.Status) == 0
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

// Identity returns the usable organization or person represented by the contact.
func (c NetworkContact) Identity() string {
	identity := ""
	switch c.Kind {
	case "org":
		identity = preferNonPrivacy(c.Organization, c.Name)
	case "individual":
		identity = c.Name
	default:
		identity = c.Organization
	}
	if identity == PrivacyRedaction {
		return ""
	}
	return identity
}

func (c NetworkContact) eligibleForRole(role string) bool {
	if !c.Direct || !c.HasRole(role) || c.IsMaintainer() || c.IsPrivacyProtected() {
		return false
	}
	return c.Identity() != "" || IsEmail(c.Email) && c.Email != PrivacyRedaction
}

func mergeNetworkSources(base, other []string) []string {
	seen := make(map[string]bool, len(base)+len(other))
	out := make([]string, 0, len(base)+len(other))
	for _, source := range append(slices.Clone(base), other...) {
		source = strings.TrimSpace(source)
		if source == "" || seen[source] {
			continue
		}
		seen[source] = true
		out = append(out, source)
	}
	return out
}

type networkContactKey struct {
	handle  string
	roles   string
	status  string
	kind    string
	direct  bool
	contact Contact
}

func mergeNetworkContacts(base, other []NetworkContact) []NetworkContact {
	seen := make(map[networkContactKey]bool, len(base)+len(other))
	out := make([]NetworkContact, 0, len(base)+len(other))
	for _, contact := range append(slices.Clone(base), other...) {
		key := networkContactKey{
			handle:  contact.Handle,
			roles:   strings.Join(contact.Roles, "\x00"),
			status:  strings.Join(contact.Status, "\x00"),
			kind:    contact.Kind,
			direct:  contact.Direct,
			contact: contact.Contact,
		}
		if contact.IsEmpty() || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, contact)
	}
	return out
}
