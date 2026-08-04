package domains

import (
	"context"
	"errors"
	"fmt"
	"strings"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
)

// rdapRecordSource is the single method the WHOIS cascade needs from the RDAP
// stage. Narrowing to an interface gives tests a seam that drives the cascade
// without real network I/O, the same shape rdapDoer gives extractRDAPRegistrantOrg.
type rdapRecordSource interface {
	rdapRecord(ctx context.Context, domain string) (whoisRecord, error)
}

// rdapRecord is the cascade's RDAP stage. It borrows a client from the SAME
// pre-filled pool the reverse-whois verifier uses (see viaRDAP for why a shared
// client and a sync.Pool are both wrong here — ENG-5376); a second pool would
// double the bootstrap fetches this one exists to avoid.
func (r *rdapWhoisResolver) rdapRecord(ctx context.Context, domain string) (whoisRecord, error) {
	client := r.acquireClient()
	var (
		rec      whoisRecord
		panicked bool
		err      error
	)
	defer func() { r.releaseClient(client, panicked) }()
	rec, panicked, err = rdapDomainRecord(ctx, client, domain)
	return rec, err
}

// rdapDomainRecord fetches one domain over RDAP and renders it as a WHOIS
// record. Like extractRDAPRegistrantOrg it recovers a panic anywhere in the
// extraction: the jCard walk runs over attacker-influenced registry data inside
// an errgroup goroutine with no framework-level recover. The panicked flag tells
// the caller to DISCARD rather than pool the client, since one that panicked
// mid-Lookup may hold a half-written registries map.
func rdapDomainRecord(ctx context.Context, doer rdapDoer, domain string) (rec whoisRecord, panicked bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			panicked = true
			rec, err = whoisRecord{}, fmt.Errorf("rdap: recovered panic resolving %q: %v", domain, p)
		}
	}()
	req := rdap.NewDomainRequest(domain).WithContext(ctx)
	resp, err := doer.Do(req)
	if err != nil {
		return whoisRecord{}, false, err
	}
	if resp == nil {
		return whoisRecord{}, false, fmt.Errorf("rdap: nil response for %q", domain)
	}
	dom, ok := resp.Object.(*rdap.Domain)
	if !ok || dom == nil {
		return whoisRecord{}, false, fmt.Errorf("rdap: unexpected response object for %q", domain)
	}
	info := rdapWhoisInfo(domain, dom)
	return whoisRecord{method: whoisMethodRDAP, raw: formatRDAPRecord(domain, info), info: info}, false, nil
}

// isDomainNotFound reports a definitive registry "no such domain" answer, as
// opposed to a transport or parse failure. The distinction drives the cascade's
// unregistered verdict, which the consumer persists as a real cacheable result
// rather than an error.
func isDomainNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, whoisparser.ErrNotFoundDomain) {
		return true
	}
	var ce *rdap.ClientError
	if errors.As(err, &ce) {
		return ce.Type == rdap.ObjectDoesNotExist
	}
	return false
}

// rdapWhoisInfo maps an RDAP domain response onto the parsed WHOIS shape the
// rest of the cascade adjudicates on. The mapping is direct rather than a
// render-then-reparse round trip: formatRDAPRecord's output is for the
// consumer's raw field, and whoisparser cannot read it back losslessly.
func rdapWhoisInfo(domain string, dom *rdap.Domain) whoisparser.WhoisInfo {
	d := &whoisparser.Domain{
		ID:     dom.Handle,
		Domain: dom.LDHName,
		Status: dom.Status,
	}
	if d.Domain == "" {
		d.Domain = domain
	}
	for _, ns := range dom.Nameservers {
		if ns.LDHName != "" {
			d.NameServers = append(d.NameServers, ns.LDHName)
		}
	}
	for _, ev := range dom.Events {
		switch strings.ToLower(ev.Action) {
		case "registration":
			d.CreatedDate = ev.Date
		case "expiration":
			d.ExpirationDate = ev.Date
		case "last changed":
			d.UpdatedDate = ev.Date
		}
	}
	return whoisparser.WhoisInfo{
		Domain:         d,
		Registrar:      rdapContact(dom.Entities, "registrar"),
		Registrant:     rdapContact(dom.Entities, "registrant"),
		Administrative: rdapContact(dom.Entities, "administrative"),
		Technical:      rdapContact(dom.Entities, "technical"),
		Billing:        rdapContact(dom.Entities, "billing"),
	}
}

// rdapContact builds a WHOIS contact from the first entity carrying the given
// RFC 9083 role.
func rdapContact(entities []rdap.Entity, role string) *whoisparser.Contact {
	for i := range entities {
		e := &entities[i]
		if !hasRole(e.Roles, role) || e.VCard == nil {
			continue
		}
		return &whoisparser.Contact{
			ID:           e.Handle,
			Name:         vcardValue(e.VCard, "fn"),
			Organization: vcardValue(e.VCard, "org"),
			Email:        vcardValue(e.VCard, "email"),
			Phone:        vcardValue(e.VCard, "tel"),
			Street:       strings.TrimSpace(e.VCard.StreetAddress()),
			City:         strings.TrimSpace(e.VCard.Locality()),
			Province:     strings.TrimSpace(e.VCard.Region()),
			PostalCode:   strings.TrimSpace(e.VCard.PostalCode()),
			Country:      vcardCountry(e.VCard),
		}
	}
	return nil
}

// vcardCountry prefers the structured adr country field, falling back to the
// "cc" parameter — many registries publish the ISO code there and leave the
// address component empty.
func vcardCountry(vc *rdap.VCard) string {
	if c := strings.TrimSpace(vc.Country()); c != "" {
		return c
	}
	if p := vc.GetFirst("adr"); p != nil {
		if cc := p.Parameters["cc"]; len(cc) > 0 {
			return strings.TrimSpace(cc[0])
		}
	}
	return ""
}

// formatRDAPRecord renders an RDAP answer as WHOIS-style text so every record
// finding carries a raw form regardless of which source answered.
func formatRDAPRecord(domain string, info whoisparser.WhoisInfo) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Domain Name: %s\n", domain)

	if d := info.Domain; d != nil {
		writeWhoisField(&sb, "", "Creation Date", d.CreatedDate)
		writeWhoisField(&sb, "", "Updated Date", d.UpdatedDate)
		writeWhoisField(&sb, "", "Expiration Date", d.ExpirationDate)
		writeWhoisField(&sb, "", "Domain Status", strings.Join(d.Status, ", "))
		if len(d.NameServers) > 0 {
			sb.WriteString("\nName Servers:\n")
			for _, ns := range d.NameServers {
				fmt.Fprintf(&sb, "   %s\n", ns)
			}
		}
	}
	if r := info.Registrar; r != nil {
		writeWhoisField(&sb, "\n", "Registrar", r.Name)
	}
	if c := info.Registrant; c != nil {
		sb.WriteString("\nRegistrant:\n")
		writeWhoisField(&sb, "   ", "Organization", c.Organization)
		writeWhoisField(&sb, "   ", "Name", c.Name)
		writeWhoisField(&sb, "   ", "Email", c.Email)
		writeWhoisField(&sb, "   ", "Country", c.Country)
		writeWhoisField(&sb, "   ", "State/Province", c.Province)
		writeWhoisField(&sb, "   ", "City", c.City)
	}

	sb.WriteString("\n>>> Data retrieved via RDAP (Registration Data Access Protocol)\n")
	return sb.String()
}

func writeWhoisField(sb *strings.Builder, indent, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(sb, "%s%s: %s\n", indent, label, value)
}
