// Package whois provides domain registration lookups via RDAP and TCP port-43.
//
// Lookup is the primary entry point: it cascades through RDAP (structured data,
// standardized dates) then TCP-43 (broader email coverage, raw text) and merges
// the best fields from each source into a single Result.
package whois

import "cmp"

// Result is the structured WHOIS record for a domain. It is serialized as JSON
// to the whois/<domain> file in Guard and is designed to be incrementally
// filled by multiple providers (RDAP, TCP-43, Whoxy, WhoisFreaks, etc.).
type Result struct {
	Domain       string   `json:"domain"`
	Registrar    string   `json:"registrar,omitempty"`
	Registrant   Contact  `json:"registrant,omitempty"`
	Admin        Contact  `json:"admin,omitempty"`
	Tech         Contact  `json:"tech,omitempty"`
	Billing      Contact  `json:"billing,omitempty"`
	Created      string   `json:"created,omitempty"`
	Updated      string   `json:"updated,omitempty"`
	Expiration   string   `json:"expiration,omitempty"`
	NameServers  []string `json:"nameservers,omitempty"`
	Status       []string `json:"status,omitempty"`
	DNSSEC       string   `json:"dnssec,omitempty"`
	WhoisServer  string   `json:"whois_server,omitempty"`
	Sources      []string `json:"sources,omitempty"`
	Unregistered bool     `json:"unregistered,omitempty"`
}

// Contact holds registration contact information for a single role.
type Contact struct {
	Organization string `json:"organization,omitempty"`
	Name         string `json:"name,omitempty"`
	Email        string `json:"email,omitempty"`
	Country      string `json:"country,omitempty"`
	Province     string `json:"province,omitempty"`
	City         string `json:"city,omitempty"`
	Street       string `json:"street,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	Phone        string `json:"phone,omitempty"`
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

// hasSubstance reports whether the record carries actual registration data
// rather than just a domain name echoed back by the provider. It is what
// distinguishes "this source has an answer" from "this source acknowledged the
// query and had nothing", which decides whether a fallback route continues.
func (r Result) hasSubstance() bool {
	return r.Registrar != "" ||
		r.Created != "" || r.Updated != "" || r.Expiration != "" ||
		r.WhoisServer != "" || r.DNSSEC != "" ||
		len(r.NameServers) > 0 || len(r.Status) > 0 ||
		!r.Registrant.IsEmpty() || !r.Admin.IsEmpty() ||
		!r.Tech.IsEmpty() || !r.Billing.IsEmpty()
}

// Merge fills empty fields on r from other, used to chain providers.
// Non-empty fields on r are never overwritten. Sources are accumulated.
func (r *Result) Merge(other Result) {
	r.Registrar = cmp.Or(r.Registrar, other.Registrar)
	r.Created = cmp.Or(r.Created, other.Created)
	r.Updated = cmp.Or(r.Updated, other.Updated)
	r.Expiration = cmp.Or(r.Expiration, other.Expiration)
	r.DNSSEC = cmp.Or(r.DNSSEC, other.DNSSEC)
	r.WhoisServer = cmp.Or(r.WhoisServer, other.WhoisServer)

	if len(r.NameServers) == 0 {
		r.NameServers = other.NameServers
	}
	if len(r.Status) == 0 {
		r.Status = other.Status
	}

	r.Registrant = mergeContact(r.Registrant, other.Registrant)
	r.Admin = mergeContact(r.Admin, other.Admin)
	r.Tech = mergeContact(r.Tech, other.Tech)
	r.Billing = mergeContact(r.Billing, other.Billing)

	r.Sources = append(r.Sources, other.Sources...)
}

// clearIfPrivacy returns "" if the value is a known WHOIS privacy placeholder.
func clearIfPrivacy(v string) string {
	if IsPrivacy(v) {
		return ""
	}
	return v
}

// Scrub clears privacy/redaction placeholder values from all fields,
// leaving only real data. Returns the scrubbed contact.
func (c Contact) Scrub() Contact {
	return Contact{
		Organization: clearIfPrivacy(c.Organization),
		Name:         clearIfPrivacy(c.Name),
		Email:        clearIfPrivacy(c.Email),
		Country:      clearIfPrivacy(c.Country),
		Province:     clearIfPrivacy(c.Province),
		City:         clearIfPrivacy(c.City),
		Street:       clearIfPrivacy(c.Street),
		PostalCode:   clearIfPrivacy(c.PostalCode),
		Phone:        clearIfPrivacy(c.Phone),
	}
}

// ScrubContacts scrubs all four contact roles on a Result.
func (r *Result) ScrubContacts() {
	r.Registrant = r.Registrant.Scrub()
	r.Admin = r.Admin.Scrub()
	r.Tech = r.Tech.Scrub()
	r.Billing = r.Billing.Scrub()
}

func mergeContact(base, other Contact) Contact {
	return Contact{
		Organization: cmp.Or(base.Organization, other.Organization),
		Name:         cmp.Or(base.Name, other.Name),
		Email:        cmp.Or(base.Email, other.Email),
		Country:      cmp.Or(base.Country, other.Country),
		Province:     cmp.Or(base.Province, other.Province),
		City:         cmp.Or(base.City, other.City),
		Street:       cmp.Or(base.Street, other.Street),
		PostalCode:   cmp.Or(base.PostalCode, other.PostalCode),
		Phone:        cmp.Or(base.Phone, other.Phone),
	}
}
