package whois

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"

	"github.com/praetorian-inc/pius/pkg/lib/netutil"
)

const (
	whoisPort        = "43"
	defaultServer    = "whois.iana.org"
	dialTimeout      = 10 * time.Second
	maxReferrals     = 5
	maxResponseBytes = 1 << 20 // 1 MiB
)

// TCP43Client implements the port-43 registration lookup.
//
// It follows RDAP because its records are unstructured text and its referral
// chains are fragile, but it carries registrant email far more often, which is
// exactly the field RDAP tends to withhold.
type TCP43Client struct{}

// NewTCP43Client returns a port-43 resolver. It takes no HTTP client: this
// leg speaks the WHOIS wire protocol directly.
func NewTCP43Client() *TCP43Client { return &TCP43Client{} }

func (r *TCP43Client) Name() string { return SourceTCP43 }

// LookupDomain owns the ISOC-IL fallback. That fallback re-parses the raw WHOIS text
// as RPSL, so it can only run where the raw text is in scope — which is here,
// and no longer in the orchestrator. Keeping it in the leg that produced the
// text is why WHOISClient can return just (Result, error) without plumbing raw
// string through the whole cascade.
func (r *TCP43Client) LookupDomain(ctx context.Context, domain string) (result DomainResult, err error) {
	defer logLookup(r.Name(), domain, time.Now(), &result, &err)

	result, raw, err := tcp43Lookup(ctx, domain)
	if err != nil {
		return DomainResult{}, err
	}
	applyISOCILFallback(&result, raw)
	result.Sources = []string{SourceTCP43}
	return result, nil
}

// tcp43Lookup performs a raw TCP port-43 WHOIS lookup with referral following,
// then parses the result into a Result.
// tcp43Lookup returns both the parsed Result and the raw WHOIS text. The raw
// text is needed for ISOC-IL fallback parsing but is not persisted on Result.
func tcp43Lookup(ctx context.Context, domain string) (DomainResult, string, error) {
	raw, server, err := tcp43Raw(ctx, domain)
	if err != nil {
		return DomainResult{}, "", err
	}
	if err := ctx.Err(); err != nil {
		return DomainResult{}, "", err
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return DomainResult{}, "", fmt.Errorf("whois parse failed for %s: %w", domain, err)
	}
	result := mapParsedToResult(domain, parsed)
	result.WhoisServer = server
	result.Normalize()
	return result, raw, nil
}

func mapParsedToResult(domain string, info whoisparser.WhoisInfo) DomainResult {
	r := DomainResult{Domain: domain}

	if info.Domain != nil {
		r.Created = info.Domain.CreatedDate
		r.Updated = info.Domain.UpdatedDate
		r.Expiration = info.Domain.ExpirationDate
		r.NameServers = info.Domain.NameServers
		r.Status = info.Domain.Status
	}
	if info.Registrar != nil {
		r.Registrar = info.Registrar.Name
	}
	r.Registrant = contactFromParsed(info.Registrant)
	r.Admin = contactFromParsed(info.Administrative)
	r.Tech = contactFromParsed(info.Technical)
	r.Billing = contactFromParsed(info.Billing)
	return r
}

func contactFromParsed(c *whoisparser.Contact) Contact {
	if c == nil {
		return Contact{}
	}
	return Contact{
		Organization: c.Organization,
		Name:         c.Name,
		Email:        c.Email,
		Country:      c.Country,
		Province:     c.Province,
		City:         c.City,
	}
}

func (r *TCP43Client) LookupNetwork(ctx context.Context, query string) (NetworkResult, error) {
	target, err := parseNetworkTarget(query)
	if err != nil {
		return NetworkResult{}, err
	}
	return tcp43NetworkLookup(ctx, target)
}

func tcp43NetworkLookup(ctx context.Context, target networkTarget) (NetworkResult, error) {
	raw, server, err := tcp43Raw(ctx, target.prefix.Addr().String())
	if err != nil {
		return NetworkResult{}, err
	}
	result, err := parseTCP43NetworkResult(target, raw, server)
	if err != nil {
		return NetworkResult{}, err
	}
	return result, nil
}

func parseTCP43NetworkResult(target networkTarget, raw, server string) (NetworkResult, error) {
	fields := parseTCP43Fields(raw)
	start, end, ok := containingTCP43Range(fields, target)
	if !ok {
		return NetworkResult{}, fmt.Errorf("whois: response has no allocation containing %s", target.query)
	}

	result := NetworkResult{
		Query:        target.query,
		StartAddress: start.String(),
		EndAddress:   end.String(),
		Handle:       firstField(fields, "nethandle", "handle"),
		Name:         firstField(fields, "netname", "network name"),
		Type:         firstField(fields, "nettype", "status"),
		Country:      firstField(fields, "country"),
		ParentHandle: firstField(fields, "parent", "parenthandle"),
		Registry:     server,
		Server:       server,
		WhoisServer:  server,
		Contacts:     tcp43NetworkContacts(fields),
		Sources:      []string{"whois"},
		Raw:          raw,
	}
	result.Clean()
	if err := requireContainingAllocation(result, target); err != nil {
		return NetworkResult{}, err
	}
	return result, nil
}

func parseTCP43Fields(raw string) map[string][]string {
	fields := make(map[string][]string)
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		fields[key] = append(fields[key], strings.TrimSpace(value))
	}
	return fields
}

func containingTCP43Range(fields map[string][]string, target networkTarget) (netip.Addr, netip.Addr, bool) {
	if start, end, ok := addressFieldRange(fields, target); ok {
		return start, end, true
	}
	if start, end, ok := dashedFieldRange(fields, target); ok {
		return start, end, true
	}
	return prefixFieldRange(fields, target)
}

func addressFieldRange(fields map[string][]string, target networkTarget) (netip.Addr, netip.Addr, bool) {
	start, startErr := netip.ParseAddr(firstField(fields, "startaddress"))
	end, endErr := netip.ParseAddr(firstField(fields, "endaddress"))
	if startErr != nil || endErr != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	return containingRange(start, end, target)
}

func dashedFieldRange(fields map[string][]string, target networkTarget) (netip.Addr, netip.Addr, bool) {
	for _, key := range []string{"netrange", "inetnum"} {
		for _, value := range fields[key] {
			start, end, ok := parseDashedRange(value)
			if ok && allocationContainsTarget(start, end, target) {
				return start, end, true
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

func parseDashedRange(value string) (netip.Addr, netip.Addr, bool) {
	startText, endText, ok := strings.Cut(value, "-")
	if !ok {
		return netip.Addr{}, netip.Addr{}, false
	}
	start, startErr := netip.ParseAddr(strings.TrimSpace(startText))
	end, endErr := netip.ParseAddr(strings.TrimSpace(endText))
	if startErr != nil || endErr != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	return start.Unmap(), end.Unmap(), true
}

func prefixFieldRange(fields map[string][]string, target networkTarget) (netip.Addr, netip.Addr, bool) {
	for _, key := range []string{"cidr", "route", "route6", "inetnum", "inet6num"} {
		for _, value := range fields[key] {
			for prefixText := range strings.SplitSeq(value, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(prefixText))
				if err != nil {
					continue
				}
				prefix = prefix.Masked()
				start, end := prefix.Addr(), lastAddress(prefix)
				if allocationContainsTarget(start, end, target) {
					return start, end, true
				}
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

func containingRange(start, end netip.Addr, target networkTarget) (netip.Addr, netip.Addr, bool) {
	start, end = start.Unmap(), end.Unmap()
	return start, end, allocationContainsTarget(start, end, target)
}

func tcp43NetworkContacts(fields map[string][]string) []NetworkContact {
	contacts := organizationContacts(fields)
	contacts = append(contacts, individualContacts(fields)...)
	contacts = append(contacts, emailContacts(fields)...)
	return mergeNetworkContacts(nil, contacts)
}

func organizationContacts(fields map[string][]string) []NetworkContact {
	organizations := []struct {
		role  string
		value string
	}{
		{"customer", firstField(fields, "custname", "customer")},
		{"registrant", firstField(fields, "orgname", "org-name", "organization", "owner")},
	}

	contacts := make([]NetworkContact, 0, len(organizations))
	for _, organization := range organizations {
		if organization.value == "" {
			continue
		}
		contacts = append(contacts, NetworkContact{
			Roles:        []string{organization.role},
			Kind:         "org",
			Direct:       true,
			Organization: normalizePrivacy(organization.value),
		})
	}
	return contacts
}

func individualContacts(fields map[string][]string) []NetworkContact {
	contactFields := []struct {
		key  string
		role string
	}{
		{"person", "unknown"},
		{"personname", "unknown"},
		{"contact", "unknown"},
	}

	var contacts []NetworkContact
	for _, field := range contactFields {
		for _, value := range fields[field.key] {
			contacts = append(contacts, NetworkContact{
				Roles:  []string{field.role},
				Kind:   "individual",
				Direct: true,
				Name:   normalizePrivacy(value),
			})
		}
	}
	return contacts
}

func emailContacts(fields map[string][]string) []NetworkContact {
	emailFields := []struct {
		key  string
		role string
	}{
		{"orgabuseemail", "abuse"},
		{"abuse-mailbox", "abuse"},
		{"orgtechemail", "technical"},
		{"orgnocemail", "noc"},
		{"e-mail", "unknown"},
		{"email", "unknown"},
	}

	var contacts []NetworkContact
	for _, field := range emailFields {
		for _, value := range fields[field.key] {
			email := firstEmail(value)
			if email == "" || IsPrivacy(email) {
				continue
			}
			contacts = append(contacts, NetworkContact{
				Roles: []string{field.role}, Direct: true, Email: email,
			})
		}
	}
	return contacts
}

func firstEmail(value string) string {
	for token := range strings.FieldsSeq(value) {
		token = strings.Trim(token, "<>,;()")
		if IsEmail(token) {
			return token
		}
	}
	return ""
}

func firstField(fields map[string][]string, keys ...string) string {
	for _, key := range keys {
		if values := fields[key]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// tcp43Raw follows the WHOIS referral chain from whois.iana.org down to the
// registrar. Returns the deepest non-bootstrap record obtained along with the
// server that answered it, so callers can attribute the record to its source.
//
// Test seam: override tcp43RawFn to drive the referral state machine without
// real network I/O.
var tcp43RawFn = tcp43RawDial

func tcp43Raw(ctx context.Context, domain string) (string, string, error) {
	server := defaultServer
	var lastRaw, lastServer string

	for range maxReferrals {
		if err := ctx.Err(); err != nil {
			if lastRaw != "" {
				return lastRaw, lastServer, nil // salvage partial chain
			}
			return "", "", err
		}

		raw, err := tcp43RawFn(ctx, domain, server)
		if err != nil {
			if lastRaw != "" {
				slog.Debug("whois referral hop failed, returning last record",
					"server", server, "error", err)
				return lastRaw, lastServer, nil
			}
			return "", "", fmt.Errorf("whois query to %s: %w", server, err)
		}

		// Only keep records from post-bootstrap servers. Compared by DNS
		// identity, not raw string equality: a referral naming
		// "whois.iana.org." is still the bootstrap server, and salvaging its
		// seed record would return the TLD registry operator as though it
		// were the queried domain's registrant.
		if !sameServer(server, defaultServer) {
			lastRaw = raw
			lastServer = server
		}

		refer := extractReferral(raw)
		// Also DNS identity: a self-referral differing only by a trailing
		// root dot must end the chain here rather than burn another hop.
		if refer == "" || sameServer(refer, server) {
			break
		}
		server = refer
	}

	if lastRaw == "" {
		return "", "", fmt.Errorf("whois: no record beyond bootstrap for %s", domain)
	}
	return lastRaw, lastServer, nil
}

// tcp43RawDial sends a single WHOIS query over a raw TCP socket on port 43.
// WHOIS (RFC 3912) is a line-oriented text protocol over raw TCP — there is no
// higher-level abstraction (no HTTP, no TLS). The SSRF guard on the dialer
// prevents untrusted referral servers from directing us to internal networks.
func tcp43RawDial(ctx context.Context, domain, server string) (string, error) {
	addr := dialAddr(server)
	dialer := net.Dialer{Timeout: dialTimeout, Control: netutil.SSRFSafeControl}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(dialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := fmt.Fprintf(conn, "%s\r\n", domain); err != nil {
		return "", err
	}

	resp, err := io.ReadAll(io.LimitReader(conn, maxResponseBytes))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", err
	}
	return string(resp), nil
}

// dialAddr normalizes a WHOIS referral server string into host:43.
//
// We don't use url.Parse here because WHOIS referral values are bare hostnames
// (e.g. "whois.nic.uk"), not URLs. url.Parse("whois.nic.uk") misparses the
// hostname as a path. Some referrals carry a scheme prefix ("http://...") or
// an explicit port — we strip both since WHOIS is always tcp/43.
func dialAddr(server string) string {
	server = strings.TrimPrefix(server, "http://")
	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimSuffix(server, "/")
	if host, _, err := net.SplitHostPort(server); err == nil {
		server = host
	} else {
		server = strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
	}
	return net.JoinHostPort(server, whoisPort)
}

// sameServer reports whether two WHOIS server names denote the same host.
// DNS names are equal under a trailing root dot and are case-insensitive,
// neither of which strings.EqualFold alone accounts for.
func sameServer(a, b string) bool {
	return strings.EqualFold(
		strings.TrimRight(strings.TrimSpace(a), "."),
		strings.TrimRight(strings.TrimSpace(b), "."),
	)
}

func extractReferral(raw string) string {
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		var value string
		switch {
		case strings.HasPrefix(lower, "refer:"):
			value = strings.TrimSpace(line[len("refer:"):])
		case strings.HasPrefix(lower, "registrar whois server:"):
			value = strings.TrimSpace(line[len("registrar whois server:"):])
		case strings.HasPrefix(lower, "whois:"):
			value = strings.TrimSpace(line[len("whois:"):])
		}
		if value != "" {
			value = strings.TrimPrefix(value, "http://")
			value = strings.TrimPrefix(value, "https://")
			value = strings.TrimSuffix(value, "/")
			return value
		}
	}
	return ""
}
