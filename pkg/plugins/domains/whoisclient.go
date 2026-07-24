package domains

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
)

const (
	whoisPort     = "43"
	defaultServer = "whois.iana.org"
	queryTimeout  = 10 * time.Second

	// maxWhoisResponseBytes caps a single WHOIS response. A raw WHOIS record is a
	// few KB; 1 MiB is generous headroom for verbose registries while bounding the
	// worst case. The reverse-whois verifier drives this read for up to
	// maxReverseWhoisCandidates domains at reverseWhoisWorkers concurrency, so an
	// unbounded io.ReadAll here is a memory-amplification vector: a hostile or
	// broken WHOIS server could stream unbounded data on each of the concurrent
	// sockets. The cap turns that into a bounded, per-read ceiling (ENG-5123
	// review, Codex — broader whoisclient hardening tracked as ENG-5167).
	maxWhoisResponseBytes = 1 << 20
)

// disallowedDialPrefixes is the full set of non-public IP ranges we must never
// dial when following an untrusted WHOIS referral. It is a strict "public
// unicast only" allowlist expressed as its complement: every IANA
// special-purpose / non-routable prefix from the IPv4 Special-Purpose Address
// Registry and its IPv6 counterpart. Earlier rounds spot-added ranges to a
// byte-switch one reviewer finding at a time (CGNAT, benchmarking, Class E,
// TEST-NETs, the IPv6 transition prefixes, then local-use NAT64, then
// 0.0.0.0/8); enumerating the registries in full is the durable shape and stops
// the whack-a-mole (ENG-5123 review — Codex, Gemini, CodeRabbit).
//
// The IPv6 transition prefixes (6to4 2002::/16, Teredo 2001::/32, and NAT64
// 64:ff9b::/96 + the RFC 8215 local-use 64:ff9b:1::/48) each EMBED an IPv4
// address, so denying them stops an internal v4 target (e.g. 169.254.169.254 or
// an RFC1918 host) from being smuggled past the v4 guard as a v6 literal.
// Legitimate public-registry WHOIS servers resolve to routable public IPs, so
// this is a no-op for real lookups.
var disallowedDialPrefixes = func() []netip.Prefix {
	cidrs := []string{
		// IPv4 — IANA IPv4 Special-Purpose Address Registry (complete).
		"0.0.0.0/8",       // "this network" (RFC 1122) — IsUnspecified only catches 0.0.0.0
		"10.0.0.0/8",      // RFC1918 private
		"100.64.0.0/10",   // CGNAT (RFC 6598)
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local (incl. cloud metadata 169.254.169.254)
		"172.16.0.0/12",   // RFC1918 private
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1 (documentation)
		"192.88.99.0/24",  // 6to4 relay anycast
		"192.168.0.0/16",  // RFC1918 private
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2 (documentation)
		"203.0.113.0/24",  // TEST-NET-3 (documentation)
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved/Class E (incl. 255.255.255.255 broadcast)
		// IPv6 — special-purpose ranges (incl. the v4-embedding transition prefixes).
		"::1/128",        // loopback
		"::/128",         // unspecified
		"::ffff:0:0/96",  // IPv4-mapped (defense-in-depth; Unmap normalizes these to v4 first)
		"64:ff9b::/96",   // well-known NAT64 (embeds IPv4)
		"64:ff9b:1::/48", // local-use NAT64, RFC 8215 (embeds IPv4)
		"100::/64",       // discard-only
		"2001::/23",      // IETF protocol assignments (incl. Teredo 2001::/32)
		"2001:db8::/32",  // documentation
		"2002::/16",      // 6to4 (embeds IPv4)
		"fc00::/7",       // unique local (IPv6 ULA)
		"fe80::/10",      // link-local unicast
		"ff00::/8",       // multicast
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(c))
	}
	return prefixes
}()

// isDisallowedDialIP reports whether ip is in a range we must never dial when
// following an untrusted WHOIS referral. It denies anything matching
// disallowedDialPrefixes, so only genuine public-unicast addresses pass.
func isDisallowedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true // unparseable length — fail closed
	}
	// Normalize IPv4-mapped IPv6 (::ffff:a.b.c.d) to its v4 form so the IPv4
	// special-purpose prefixes catch an internal target wrapped as a v6 literal.
	addr = addr.Unmap()
	for _, p := range disallowedDialPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ssrfSafeControl is a net.Dialer.Control hook that refuses to connect to a
// non-public address. It runs after DNS resolution and immediately before the
// connect syscall, so the address it sees is the one the socket will actually
// use — closing the DNS-rebinding TOCTOU window a resolve-then-check guard would
// leave open (ENG-5123 review, Gemini).
func ssrfSafeControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf guard: malformed dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf guard: non-IP dial address %q", host)
	}
	if isDisallowedDialIP(ip) {
		return fmt.Errorf("ssrf guard: refusing to dial non-public address %s", ip)
	}
	return nil
}

// whoisQuery performs a raw WHOIS lookup, following server referrals.
// It starts at whois.iana.org and follows "refer:" or "whois:" directives
// until it reaches the authoritative registrar server.
//
// Every hop is bounded by ctx: the referral loop bails as soon as ctx is
// cancelled or its deadline passes, and whoisRaw honors ctx on the socket read.
// This keeps the fallback path inside the overall verification budget instead of
// letting 5 referrals x queryTimeout stack past it (ENG-5123 review).
func whoisQuery(ctx context.Context, domain string) (string, error) {
	server := defaultServer
	var lastRaw string

	for i := 0; i < 5; i++ { // max 5 referrals to prevent loops
		if err := ctx.Err(); err != nil {
			if lastRaw != "" {
				return lastRaw, nil // return last successful result
			}
			return "", err
		}
		raw, err := whoisRaw(ctx, domain, server)
		if err != nil {
			if lastRaw != "" {
				return lastRaw, nil // return last successful result
			}
			return "", fmt.Errorf("whois query to %s: %w", server, err)
		}
		lastRaw = raw

		// Look for referral to a more specific server
		refer := extractReferral(raw)
		if refer == "" || strings.EqualFold(refer, server) {
			break
		}
		server = refer
	}

	return lastRaw, nil
}

// whoisDialAddr normalizes a (possibly untrusted) referral server string into a
// host:port dial target: it strips any URL scheme / trailing slash and honors an
// explicit port when the referral already carries one (e.g.
// "whois.example.com:43"), otherwise appends the standard WHOIS port. Without the
// explicit-port check, a port-qualified referral would be double-appended into a
// malformed "host:43:43" address that never dials (ENG-5123 review, Gemini).
func whoisDialAddr(server string) string {
	server = strings.TrimPrefix(server, "http://")
	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimSuffix(server, "/")
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server // already host:port — don't double-append
	}
	return net.JoinHostPort(server, whoisPort)
}

// whoisRaw sends a single WHOIS query to the given server and returns the raw response.
func whoisRaw(ctx context.Context, domain, server string) (string, error) {
	addr := whoisDialAddr(server)

	// SSRF guard: the reverse-whois verifier now follows WHOIS referrals for up to
	// maxReverseWhoisCandidates domains pulled from third-party APIs (ViewDNS /
	// Whoxy), and a referral server is read straight out of that untrusted WHOIS
	// text (extractReferral). Without a guard an attacker could seed a domain whose
	// WHOIS record refers to an internal address (RFC1918 / loopback / link-local),
	// turning the runner into a blind internal prober. The Control hook rejects the
	// connection AFTER DNS resolution and immediately BEFORE connect, so it is safe
	// against DNS-rebinding TOCTOU and covers hostname referrals that resolve to
	// internal IPs, not just literal-IP referrals (ENG-5123 review, Gemini).
	dialer := net.Dialer{Timeout: queryTimeout, Control: ssrfSafeControl}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	// Bound the write by the same ctx-aware deadline the read uses, so a server
	// that accepts the connection but never drains our query can't hang here
	// past the budget either.
	_ = conn.SetDeadline(boundedDeadline(ctx))

	_, err = fmt.Fprintf(conn, "%s\r\n", domain)
	if err != nil {
		return "", err
	}

	resp, err := readAllWithContext(ctx, conn)
	if err != nil {
		return "", err
	}

	return string(resp), nil
}

// boundedDeadline returns the earlier of now+queryTimeout and the caller's ctx
// deadline (if any), so a single WHOIS socket operation can never outrun the
// overall verification budget carried on ctx (ENG-5123 review).
func boundedDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(queryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return deadline
}

// readAllWithContext reads the full WHOIS response, bounding the read by BOTH
// the fixed queryTimeout and ctx. SetDeadline covers a ctx that carries a
// deadline; the watcher goroutine covers a ctx cancelled WITHOUT one (a parent
// cancel, or the pass-wide budget context firing), closing the socket so the
// blocked io.ReadAll unwinds immediately instead of waiting out the full
// deadline. On any error the ctx cause is preferred, so callers see
// cancellation/deadline rather than a generic "closed network connection"
// (ENG-5123 review — the WHOIS fallback must honor the budget, not just a fixed
// per-read timer). The read is byte-capped at maxWhoisResponseBytes so a hostile
// or broken server can't amplify memory across the concurrent reverse-whois
// sockets; further whoisclient hardening is tracked as ENG-5167.
func readAllWithContext(ctx context.Context, conn net.Conn) ([]byte, error) {
	_ = conn.SetDeadline(boundedDeadline(ctx))

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close() // unblock a read parked past ctx cancellation
		case <-stop:
		}
	}()

	resp, err := io.ReadAll(io.LimitReader(conn, maxWhoisResponseBytes))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	// A read that lands exactly on the cap was (almost certainly) truncated. Log it
	// so a verbose registry record that then fails to parse is distinguishable from
	// a whoisparser bug rather than failing silently (ENG-5123 review, Gemini).
	if len(resp) == maxWhoisResponseBytes {
		slog.Warn("whois: response reached size cap and may be truncated",
			"cap_bytes", maxWhoisResponseBytes)
	}
	return resp, nil
}

// extractReferral finds a WHOIS server referral in raw WHOIS output.
// Looks for "refer:" (IANA format) or "Registrar WHOIS Server:" (ICANN format).
func extractReferral(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
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
