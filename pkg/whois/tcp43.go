package whois

import (
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/lib/netutil"
)

const (
	whoisPort        = "43"
	defaultServer    = "whois.iana.org"
	dialTimeout      = 10 * time.Second
	maxReferrals     = 5
	maxResponseBytes = 1 << 20 // 1 MiB
)

type TCP43Client struct{}

func NewTCP43Client() *TCP43Client { return &TCP43Client{} }

func (r *TCP43Client) Name() string { return SourceTCP43 }

func (r *TCP43Client) LookupDomain(ctx context.Context, domain string) (result DomainResult, err error) {
	result, err = tcp43Lookup(ctx, domain)
	if err != nil {
		return DomainResult{}, err
	}
	result.Sources = []string{SourceTCP43}
	return result, nil
}

// tcp43Lookup performs a raw TCP port-43 WHOIS lookup with referral following,
// then parses the result into a Result.
func tcp43Lookup(ctx context.Context, domain string) (DomainResult, error) {
	raw, server, err := tcp43Raw(ctx, domain)
	if err != nil {
		return DomainResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return DomainResult{}, err
	}

	result, err := parseRawDomainResult(domain, raw)
	if err != nil {
		return DomainResult{}, fmt.Errorf("whois parse failed for %s: %w", domain, err)
	}
	result.WhoisServer = server
	return result, nil
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
	result.Normalize()
	if err := requireContainingAllocation(result, target); err != nil {
		return NetworkResult{}, err
	}
	return result, nil
}

func parseTCP43Fields(raw string) map[string][]string {
	fields := make(map[string][]string)
	for field := range scanTCP43Fields(raw) {
		if field.value != "" {
			fields[field.key] = append(fields[field.key], field.value)
		}
	}
	return fields
}

type tcp43Field struct {
	paragraph int
	key       string
	value     string
}

func scanTCP43Fields(raw string) iter.Seq[tcp43Field] {
	return func(yield func(tcp43Field) bool) {
		paragraph := 0
		paragraphHasFields := false
		for line := range strings.SplitSeq(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				if paragraphHasFields {
					paragraph++
					paragraphHasFields = false
				}
				continue
			}
			if isTCP43Comment(line) {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			paragraphHasFields = true
			field := tcp43Field{
				paragraph: paragraph,
				key:       strings.ToLower(strings.TrimSpace(key)),
				value:     strings.TrimSpace(value),
			}
			if !yield(field) {
				return
			}
		}
	}
}

func isTCP43Comment(line string) bool {
	return strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#")
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
			Roles:  []string{organization.role},
			Kind:   "org",
			Direct: true,
			Contact: Contact{
				Organization: organization.value,
			},
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
				Contact: Contact{
					Name: value,
				},
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
			if email == "" {
				continue
			}
			contacts = append(contacts, NetworkContact{
				Roles:   []string{field.role},
				Direct:  true,
				Contact: Contact{Email: email},
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

// tcp43Raw follows the WHOIS referral chain from the TLD's DNS-advertised
// WHOIS server, falling back to whois.iana.org, down to the registrar. Returns
// the deepest non-bootstrap record obtained along with the server that answered
// it, so callers can attribute the record to its source.
//
// Test seams: override these functions to avoid real DNS and TCP requests.
var tcp43RawFn = tcp43RawDial
var lookupWhoisSRVFn = lookupWhoisSRV

func tcp43Raw(ctx context.Context, domain string) (string, string, error) {
	server, err := initialTCP43Server(ctx, domain)
	if err != nil {
		return "", "", err
	}
	var lastRaw, lastServer string

	slog.Info("using TCP43 server", "hostname", server)

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

func initialTCP43Server(ctx context.Context, domain string) (string, error) {
	if net.ParseIP(domain) != nil {
		return defaultServer, nil
	}

	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	records, err := lookupWhoisSRVFn(ctx, tld)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return defaultServer, nil
	}
	if len(records) == 0 {
		return defaultServer, nil
	}

	record := records[0]
	target := strings.TrimSuffix(record.Target, ".")
	if target == "" || target == "." {
		return "", fmt.Errorf("whois: TCP43 service unavailable for .%s", tld)
	}
	if record.Port == 43 {
		return target, nil
	}
	return net.JoinHostPort(target, fmt.Sprint(record.Port)), nil
}

// DNS SRV records locate the server for a service by querying
// _<service>._<protocol>.<domain>. For TCP43 WHOIS, the registered service name
// is "nicname", so _nicname._tcp.<tld> identifies the TLD's WHOIS server.
func lookupWhoisSRV(ctx context.Context, tld string) ([]*net.SRV, error) {
	_, records, err := net.DefaultResolver.LookupSRV(ctx, "nicname", "tcp", tld)
	return records, err
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

// dialAddr normalizes a WHOIS server string into host:port, defaulting to 43.
//
// We don't use url.Parse here because WHOIS referral values are bare hostnames
// (e.g. "whois.nic.uk"), not URLs. url.Parse("whois.nic.uk") misparses the
// hostname as a path.
func dialAddr(server string) string {
	server = strings.TrimPrefix(server, "http://")
	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimSuffix(server, "/")
	if host, port, err := net.SplitHostPort(server); err == nil {
		return net.JoinHostPort(host, port)
	}
	server = strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
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
