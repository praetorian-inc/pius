// Package whois provides domain and IP registration lookups via RDAP and TCP port 43.
package whois

import (
	"cmp"
	"strings"
)

// Result is the structured WHOIS record for a domain. It is serialized as JSON
// to the whois/<domain> file in Guard and is designed to be incrementally
// filled by multiple providers (RDAP, TCP-43, Whoxy, WhoisFreaks, etc.).
type Result struct {
	Domain       string   `json:"domain"`
	Registrar    string   `json:"registrar,omitempty"`
	Registrant   Contact  `json:"registrant"`
	Admin        Contact  `json:"admin"`
	Tech         Contact  `json:"tech"`
	Billing      Contact  `json:"billing"`
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
	v = strings.TrimSpace(v)
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

func (r *Result) Clean() {
	r.Domain = strings.TrimSpace(r.Domain)
	r.Registrar = strings.TrimSpace(r.Registrar)
	r.Created = strings.TrimSpace(r.Created)
	r.Updated = strings.TrimSpace(r.Updated)
	r.Expiration = strings.TrimSpace(r.Expiration)
	r.DNSSEC = strings.TrimSpace(r.DNSSEC)
	r.WhoisServer = strings.TrimSpace(r.WhoisServer)
	r.Status = trimStrings(r.Status)
	r.NameServers = trimStrings(r.NameServers)
	r.Sources = trimStrings(r.Sources)
	r.ScrubContacts()
}

func trimStrings(arr []string) []string {
	res := make([]string, 0, len(arr))
	for i := range arr {
		v := strings.TrimSpace(arr[i])
		if v != "" {
			res = append(res, v)
		}
	}
	return res
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
