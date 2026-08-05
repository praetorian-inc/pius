// Package whois provides domain registration lookups via RDAP and TCP port-43.
//
// Lookup is the primary entry point: it cascades through RDAP (structured data,
// standardized dates) then TCP-43 (broader email coverage, raw text) and merges
// the best fields from each source into a single Result.
package whois

// Result is the merged output of a domain WHOIS/RDAP lookup.
type Result struct {
	Domain       string
	Registrar    string
	Registrant   Contact
	Admin        Contact
	Tech         Contact
	Billing      Contact
	Created      string // RFC3339 or registry-native format
	Updated      string
	Expiration   string
	NameServers  []string
	Status       []string
	Raw          string // raw WHOIS text (TCP-43 when available, else formatted RDAP)
	Unregistered bool
}

// Contact holds registration contact information.
type Contact struct {
	Organization string
	Name         string
	Email        string
	Country      string
	Province     string
	City         string
}

// IsEmpty reports whether the contact has no usable identity.
func (c Contact) IsEmpty() bool {
	return c.Organization == "" && c.Name == "" && c.Email == ""
}

// AllContacts returns the four contact roles in order: registrant, admin, tech, billing.
func (r Result) AllContacts() [4]Contact {
	return [4]Contact{r.Registrant, r.Admin, r.Tech, r.Billing}
}

// HasRegistrant reports whether the result has a non-empty registrant identity
// (org or name). Email alone doesn't count — it identifies a mailbox, not an entity.
func (r Result) HasRegistrant() bool {
	return r.Registrant.Organization != "" || r.Registrant.Name != ""
}
