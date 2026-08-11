package netutil

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// ErrSSRFRefused marks an error as a refusal by the SSRF guard. Callers that
// follow untrusted referrals match it with errors.Is to tell "the guard stopped
// a probe at a non-public address" apart from an ordinary unreachable-server
// error: every other transport failure has a benign explanation, a refusal does
// not. Matching structurally rather than on message text keeps that
// classification intact if the wrapping message is ever reworded, and survives
// the *net.OpError the net package wraps a Control hook's error in.
var ErrSSRFRefused = errors.New("ssrf guard: refused non-public address")

// SSRFSafeControl is a net.Dialer.Control hook that rejects connections to
// non-public addresses, preventing untrusted referrals from probing internal
// networks.
func SSRFSafeControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf guard: malformed address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf guard: non-IP address %q", host)
	}
	// Only this branch wraps ErrSSRFRefused. The two above are parse failures,
	// not evidence of an SSRF attempt — a hostile referral never fails to parse,
	// it names a disallowed IP — and reporting them as refusals would tell
	// operators an attack was attempted when none was.
	//
	// The sentinel leads so its text supplies the whole prefix and the refused
	// address is appended, rather than re-prefixing an already-prefixed message.
	if IsDisallowedIP(ip) {
		return fmt.Errorf("%w %s", ErrSSRFRefused, ip)
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
