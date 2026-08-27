package whois

import (
	"cmp"
	"strings"
)

type DomainResult struct {
	Domain             string   `json:"domain"`
	Registrar          string   `json:"registrar,omitempty"`
	Registrant         Contact  `json:"registrant"`
	Admin              Contact  `json:"admin"`
	Tech               Contact  `json:"tech"`
	Billing            Contact  `json:"billing"`
	Created            string   `json:"created,omitempty"`
	Updated            string   `json:"updated,omitempty"`
	Expiration         string   `json:"expiration,omitempty"`
	NameServers        []string `json:"nameservers,omitempty"`
	Status             []string `json:"status,omitempty"`
	DNSSEC             string   `json:"dnssec,omitempty"`
	WhoisServer        string   `json:"whois_server,omitempty"`
	Sources            []string `json:"sources,omitempty"`
	Unregistered       bool     `json:"unregistered,omitempty"`
	RegistrantIdentity string   `json:"registrant_identity,omitempty"`
	ContactEmail       string   `json:"contact_email,omitempty"`
	ContactEmailRole   string   `json:"contact_email_role,omitempty"`
}

func (r *DomainResult) AllContacts() [4]Contact {
	return [4]Contact{r.Registrant, r.Admin, r.Tech, r.Billing}
}

// Reports whether the record has enough information to be considered complete.
func (r *DomainResult) isComplete() bool {
	return (r.Registrant.Organization != "" || r.Registrant.Name != "") &&
		r.Registrant.Email != "" &&
		r.Registrar != "" &&
		r.Expiration != "" &&
		len(r.NameServers) > 0
}

// hasSubstance reports whether the record carries actual registration data
// rather than just a domain name echoed back by the provider. It is what
// distinguishes "this source has an answer" from "this source acknowledged the
// query and had nothing", which decides whether Lookup continues.
func (r *DomainResult) hasSubstance() bool {
	return r.Registrar != "" ||
		r.Created != "" || r.Updated != "" || r.Expiration != "" ||
		r.WhoisServer != "" || r.DNSSEC != "" ||
		len(r.NameServers) > 0 || len(r.Status) > 0 ||
		!r.Registrant.IsEmpty() || !r.Admin.IsEmpty() ||
		!r.Tech.IsEmpty() || !r.Billing.IsEmpty()
}

// Merge fills empty fields on r from other, used to chain providers.
// Non-empty fields on r are never overwritten. Sources are accumulated.
func (r *DomainResult) Merge(other DomainResult) {
	r.Normalize()
	other.Normalize()

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
	r.populateDerivedFields()
}

func (r *DomainResult) Normalize() {
	r.Domain = strings.TrimSpace(r.Domain)
	r.Registrar = NormalizeRegistrar(r.Registrar)
	r.Created = strings.TrimSpace(r.Created)
	r.Updated = strings.TrimSpace(r.Updated)
	r.Expiration = strings.TrimSpace(r.Expiration)
	r.DNSSEC = strings.TrimSpace(r.DNSSEC)
	r.WhoisServer = strings.TrimSpace(r.WhoisServer)
	r.Status = trimStrings(r.Status)
	r.NameServers = trimStrings(r.NameServers)
	r.Sources = trimStrings(r.Sources)
	r.Registrant = r.Registrant.Normalize()
	r.Admin = r.Admin.Normalize()
	r.Tech = r.Tech.Normalize()
	r.Billing = r.Billing.Normalize()
	if isRegistryArtifact(r.Registrant.Organization, r.Domain) {
		r.Registrant.Organization = ""
	}
	r.populateDerivedFields()
}

func (r *DomainResult) populateDerivedFields() {
	r.RegistrantIdentity = preferNonPrivacy(r.Registrant.Organization, r.Registrant.Name)
	r.ContactEmail, r.ContactEmailRole = preferredContactEmail(*r)
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

func (c Contact) Normalize() Contact {
	return Contact{
		Organization: normalizePrivacy(c.Organization),
		Name:         normalizePrivacy(c.Name),
		Email:        normalizePrivacy(c.Email),
		Country:      normalizePrivacy(c.Country),
		Province:     normalizePrivacy(c.Province),
		City:         normalizePrivacy(c.City),
		Street:       normalizePrivacy(c.Street),
		PostalCode:   normalizePrivacy(c.PostalCode),
		Phone:        normalizePrivacy(c.Phone),
	}
}

func mergeContact(base, other Contact) Contact {
	return Contact{
		Organization: preferNonPrivacy(base.Organization, other.Organization),
		Name:         preferNonPrivacy(base.Name, other.Name),
		Email:        preferNonPrivacy(base.Email, other.Email),
		Country:      preferNonPrivacy(base.Country, other.Country),
		Province:     preferNonPrivacy(base.Province, other.Province),
		City:         preferNonPrivacy(base.City, other.City),
		Street:       preferNonPrivacy(base.Street, other.Street),
		PostalCode:   preferNonPrivacy(base.PostalCode, other.PostalCode),
		Phone:        preferNonPrivacy(base.Phone, other.Phone),
	}
}
