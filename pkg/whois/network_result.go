package whois

import (
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

// Normalize trims provider data and preserves privacy markers.
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
	c.Contact = c.Contact.normalize()
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

func (c NetworkContact) hasUsefulIdentity() bool {
	if c.IsPrivacyProtected() {
		return false
	}

	identity := c.Organization
	switch c.Kind {
	case "org":
		if identity == "" {
			identity = c.Name
		}
	case "individual":
		identity = c.Name
	default:
		identity = ""
	}
	hasIdentity := identity != "" && !IsPrivacy(identity)
	hasEmail := IsEmail(c.Email) && !IsPrivacy(c.Email)
	return hasIdentity || hasEmail
}
