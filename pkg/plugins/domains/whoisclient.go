package domains

import (
	"context"
	"fmt"
	"io"
	"net"
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

// isDisallowedDialIP reports whether ip is in a range we must never dial when
// following an untrusted WHOIS referral. Following attacker-influenced referral
// text, the guard is a strict "public unicast only" filter, not a spot-check:
// the method checks cover loopback, link-local (incl. the cloud metadata address
// 169.254.169.254), private (RFC1918 / IPv6 ULA), unspecified, and multicast;
// the explicit ranges below add every other IANA special-use / non-routable
// block the method checks miss — CGNAT, benchmarking, reserved/Class E, IETF
// protocol assignments, 6to4-relay anycast, and the TEST-NET / documentation
// ranges (ENG-5123 review, Codex). Legitimate public-registry WHOIS servers
// resolve to routable public IPs, so this is a no-op for real lookups.
func isDisallowedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127: // 100.64.0.0/10 CGNAT
			return true
		case ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19): // 198.18.0.0/15 benchmarking
			return true
		case ip4[0] >= 240: // 240.0.0.0/4 reserved/Class E (+255.255.255.255 broadcast)
			return true
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0: // 192.0.0.0/24 IETF protocol assignments
			return true
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2: // 192.0.2.0/24 TEST-NET-1
			return true
		case ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100: // 198.51.100.0/24 TEST-NET-2
			return true
		case ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113: // 203.0.113.0/24 TEST-NET-3
			return true
		case ip4[0] == 192 && ip4[1] == 88 && ip4[2] == 99: // 192.88.99.0/24 6to4 relay anycast
			return true
		}
		return false
	}
	// Genuine IPv6 (To4()==nil) special-use ranges not caught by the method checks:
	// documentation (2001:db8::/32) and the discard-only prefix (100::/64).
	if len(ip) == net.IPv6len {
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 { // 2001:db8::/32
			return true
		}
		if ip[0] == 0x01 && ip[1] == 0x00 &&
			ip[2] == 0 && ip[3] == 0 && ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 { // 100::/64
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

// whoisRaw sends a single WHOIS query to the given server and returns the raw response.
func whoisRaw(ctx context.Context, domain, server string) (string, error) {
	server = strings.TrimPrefix(server, "http://")
	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimSuffix(server, "/")

	addr := net.JoinHostPort(server, whoisPort)

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
