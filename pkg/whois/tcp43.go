package whois

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	whoisparser "github.com/likexian/whois-parser"
)

const (
	whoisPort        = "43"
	defaultServer    = "whois.iana.org"
	dialTimeout      = 10 * time.Second
	maxReferrals     = 5
	maxResponseBytes = 1 << 20 // 1 MiB
)

// tcp43Lookup performs a raw TCP port-43 WHOIS lookup with referral following,
// then parses the result into a Result.
func tcp43Lookup(ctx context.Context, domain string) (Result, error) {
	raw, err := tcp43Raw(ctx, domain)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return Result{}, fmt.Errorf("whois parse failed for %s: %w", domain, err)
	}

	return mapParsedToResult(domain, parsed, raw), nil
}

func mapParsedToResult(domain string, info whoisparser.WhoisInfo, raw string) Result {
	r := Result{Domain: domain, Raw: raw}

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

// tcp43Raw follows the WHOIS referral chain from whois.iana.org down to the
// registrar. Returns the deepest non-bootstrap record obtained.
//
// Test seam: override tcp43RawFn to drive the referral state machine without
// real network I/O.
var tcp43RawFn = tcp43RawDial

func tcp43Raw(ctx context.Context, domain string) (string, error) {
	server := defaultServer
	var lastRaw string

	for range maxReferrals {
		if err := ctx.Err(); err != nil {
			if lastRaw != "" {
				return lastRaw, nil // salvage partial chain
			}
			return "", err
		}

		raw, err := tcp43RawFn(ctx, domain, server)
		if err != nil {
			if lastRaw != "" {
				slog.Debug("whois referral hop failed, returning last record",
					"server", server, "error", err)
				return lastRaw, nil
			}
			return "", fmt.Errorf("whois query to %s: %w", server, err)
		}

		// Only keep records from post-bootstrap servers.
		if !strings.EqualFold(server, defaultServer) {
			lastRaw = raw
		}

		refer := extractReferral(raw)
		if refer == "" || strings.EqualFold(refer, server) {
			break
		}
		server = refer
	}

	if lastRaw == "" {
		return "", fmt.Errorf("whois: no record beyond bootstrap for %s", domain)
	}
	return lastRaw, nil
}

// tcp43RawDial sends a single WHOIS query over a raw TCP socket on port 43.
// WHOIS (RFC 3912) is a line-oriented text protocol over raw TCP — there is no
// higher-level abstraction (no HTTP, no TLS). The SSRF guard on the dialer
// prevents untrusted referral servers from directing us to internal networks.
func tcp43RawDial(ctx context.Context, domain, server string) (string, error) {
	addr := dialAddr(server)
	dialer := net.Dialer{Timeout: dialTimeout, Control: ssrfSafeControl}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

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

// --- SSRF guard ---

// ssrfSafeControl rejects connections to non-public addresses, preventing
// untrusted WHOIS referrals from probing internal networks.
func ssrfSafeControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf guard: malformed address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf guard: non-IP address %q", host)
	}
	if IsDisallowedIP(ip) {
		return fmt.Errorf("ssrf guard: refusing non-public address %s", ip)
	}
	return nil
}

var v6GlobalUnicast = netip.MustParsePrefix("2000::/3")

var disallowedPrefixes = func() []netip.Prefix {
	cidrs := []string{
		// IPv4 special-purpose
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		// IPv6 special-purpose
		"::1/128", "::/128", "::ffff:0:0/96", "::/96",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64",
		"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
		"5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(c))
	}
	return prefixes
}()

// IsDisallowedIP reports whether ip is non-public (loopback, private, CGNAT,
// link-local, etc.) and must not be dialed when following an untrusted referral.
// Exported so other packages that follow untrusted network references can reuse
// the same guard.
func IsDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return true
	}
	if addr.Is6() && !v6GlobalUnicast.Contains(addr) {
		return true
	}
	for _, p := range disallowedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
