package domains

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSSRFSafeControl proves the dial guard rejects every non-public referral
// target — metadata address, RFC1918, loopback, CGNAT, link-local, plus the
// IANA special-use ranges the method checks miss (benchmarking, reserved/Class E,
// broadcast, protocol assignments, TEST-NET-1/2/3, 6to4 anycast, and the IPv6
// documentation / discard-only prefixes) — while allowing a public IP. This is
// the check that keeps an attacker-controlled WHOIS referral from turning the
// runner into an internal prober (ENG-5123 review, Gemini + Codex).
func TestSSRFSafeControl(t *testing.T) {
	blocked := []string{
		"169.254.169.254:43", // cloud metadata (link-local)
		"127.0.0.1:43",       // loopback
		"10.0.0.1:43",        // RFC1918
		"192.168.1.1:43",     // RFC1918
		"172.16.0.1:43",      // RFC1918
		"100.64.0.1:43",      // CGNAT 100.64/10
		"0.0.0.1:43",         // "this network" 0.0.0.0/8 (nonzero — IsUnspecified misses it)
		"198.18.0.1:43",      // benchmarking 198.18.0.0/15
		"198.19.255.1:43",    // benchmarking 198.18.0.0/15 (upper half)
		"240.0.0.1:43",       // reserved/Class E 240.0.0.0/4
		"255.255.255.255:43", // limited broadcast
		"192.0.0.1:43",       // IETF protocol assignments 192.0.0.0/24
		"192.0.2.1:43",       // TEST-NET-1
		"198.51.100.1:43",    // TEST-NET-2
		"203.0.113.1:43",     // TEST-NET-3
		"192.88.99.1:43",     // 6to4 relay anycast
		"[::1]:43",           // IPv6 loopback
		"[fd00::1]:43",       // IPv6 ULA
		"[fec0::1]:43",       // deprecated IPv6 site-local (RFC 3879), non-public
		"[fec0::abcd:1]:43",  // deprecated IPv6 site-local (RFC 3879), second point in fec0::/10
		"[2001:db8::1]:43",   // IPv6 documentation 2001:db8::/32
		"[100::1]:43",        // IPv6 discard-only 100::/64
		// IPv6 transition prefixes that embed an internal IPv4 target — the v6
		// literal must be rejected so it can't smuggle an internal v4 past the
		// v4 guard (ENG-5123 review, CodeRabbit).
		"[2002:a9fe:a9fe::]:43", // 6to4 wrapping 169.254.169.254 (metadata)
		"[2002:0a00:0001::]:43", // 6to4 wrapping 10.0.0.1 (RFC1918)
		"[2001:0:0a00:1::]:43",  // Teredo 2001::/32
		"[64:ff9b::a00:1]:43",   // well-known NAT64 64:ff9b::/96 wrapping 10.0.0.1
		"[64:ff9b:1::a00:1]:43", // local-use NAT64 64:ff9b:1::/48 (RFC 8215) wrapping 10.0.0.1
		"[::127.0.0.1]:43",      // IPv4-compatible IPv6 (::/96), embeds loopback 127.0.0.1 — must be refused (Codex P1)
		"[::1.2.3.4]:43",        // second point in ::/96, proves range rejection not just the loopback case
		"0.0.0.0:43",            // unspecified
	}
	for _, addr := range blocked {
		assert.Error(t, ssrfSafeControl("tcp", addr, nil), "must reject %s", addr)
	}

	allowed := []string{
		"8.8.8.8:43",                // public v4
		"[2001:4860:4860::8888]:43", // public v6
	}
	for _, addr := range allowed {
		assert.NoError(t, ssrfSafeControl("tcp", addr, nil), "must allow %s", addr)
	}

	// A hostname that never resolved to an IP (Control sees the literal) is rejected.
	assert.Error(t, ssrfSafeControl("tcp", "whois.example.com:43", nil))
}

// TestSSRFGuard_IANARegistryExhaustive encodes the full offline audit of
// isDisallowedDialIP against the IANA IPv4 and IPv6 Special-Purpose Address
// Registries plus the IPv6 Address Space registry (snapshot 2026-07-28, the
// same snapshot disallowedDialPrefixes mirrors) as a permanent hermetic test.
// The two-layer guard was rebuilt after bot reviewers found gaps one range at
// a time (ENG-5123 rounds 4-5: fec0::/10, ::/96); this table pins EVERY
// registry row — first address, an interior point (first host bit set), and
// the last address of each blocked range — plus every Reserved-by-IETF IPv6
// top-level block, the deliberately-allowed Globally-Reachable=True rows, and
// public allow anchors, so no future one-off review round is possible: any
// regression in either layer (the structural 2000::/3 gate or the enumerated
// prefix list) fails a named case here. Hermetic: isDisallowedDialIP is pure,
// no socket is ever opened.
func TestSSRFGuard_IANARegistryExhaustive(t *testing.T) {
	type probe struct {
		ip      string
		blocked bool
		reason  string // registry row / RFC this case pins
	}

	cases := []probe{
		// ─── GROUP 1: IANA IPv4 Special-Purpose Address Registry — every
		// non-Globally-Reachable row must be BLOCKED (first / interior / last). ───
		{"0.0.0.0", true, `"this network" 0.0.0.0/8 (RFC 791/1122) — first (unspecified)`},
		{"0.128.0.0", true, `"this network" 0.0.0.0/8 — interior (IsUnspecified misses nonzero hosts; the /8 entry is load-bearing)`},
		{"0.255.255.255", true, `"this network" 0.0.0.0/8 — last`},
		{"10.0.0.0", true, "RFC1918 private 10.0.0.0/8 — first"},
		{"10.128.0.0", true, "RFC1918 private 10.0.0.0/8 — interior"},
		{"10.255.255.255", true, "RFC1918 private 10.0.0.0/8 — last"},
		{"100.64.0.0", true, "CGNAT shared space 100.64.0.0/10 (RFC 6598) — first"},
		{"100.96.0.0", true, "CGNAT shared space 100.64.0.0/10 — interior"},
		{"100.127.255.255", true, "CGNAT shared space 100.64.0.0/10 — last"},
		{"127.0.0.0", true, "loopback 127.0.0.0/8 (RFC 1122) — first"},
		{"127.128.0.0", true, "loopback 127.0.0.0/8 — interior"},
		{"127.255.255.255", true, "loopback 127.0.0.0/8 — last"},
		{"169.254.0.0", true, "link-local 169.254.0.0/16 (RFC 3927) — first"},
		{"169.254.128.0", true, "link-local 169.254.0.0/16 — interior (cloud metadata 169.254.169.254 lives here)"},
		{"169.254.255.255", true, "link-local 169.254.0.0/16 — last"},
		{"172.16.0.0", true, "RFC1918 private 172.16.0.0/12 — first"},
		{"172.24.0.0", true, "RFC1918 private 172.16.0.0/12 — interior"},
		{"172.31.255.255", true, "RFC1918 private 172.16.0.0/12 — last"},
		{"192.0.0.0", true, "IETF Protocol Assignments 192.0.0.0/24 (RFC 6890) — first"},
		{"192.0.0.128", true, "IETF Protocol Assignments 192.0.0.0/24 — interior"},
		{"192.0.0.255", true, "IETF Protocol Assignments 192.0.0.0/24 — last"},
		{"192.0.2.0", true, "TEST-NET-1 documentation 192.0.2.0/24 (RFC 5737) — first"},
		{"192.0.2.128", true, "TEST-NET-1 documentation 192.0.2.0/24 — interior"},
		{"192.0.2.255", true, "TEST-NET-1 documentation 192.0.2.0/24 — last"},
		{"192.88.99.0", true, "deprecated 6to4 relay anycast 192.88.99.0/24 (RFC 7526) — first"},
		{"192.88.99.128", true, "deprecated 6to4 relay anycast 192.88.99.0/24 — interior"},
		{"192.88.99.255", true, "deprecated 6to4 relay anycast 192.88.99.0/24 — last"},
		{"192.168.0.0", true, "RFC1918 private 192.168.0.0/16 — first"},
		{"192.168.128.0", true, "RFC1918 private 192.168.0.0/16 — interior"},
		{"192.168.255.255", true, "RFC1918 private 192.168.0.0/16 — last"},
		{"198.18.0.0", true, "benchmarking 198.18.0.0/15 (RFC 2544) — first"},
		{"198.19.0.0", true, "benchmarking 198.18.0.0/15 — interior"},
		{"198.19.255.255", true, "benchmarking 198.18.0.0/15 — last"},
		{"198.51.100.0", true, "TEST-NET-2 documentation 198.51.100.0/24 (RFC 5737) — first"},
		{"198.51.100.128", true, "TEST-NET-2 documentation 198.51.100.0/24 — interior"},
		{"198.51.100.255", true, "TEST-NET-2 documentation 198.51.100.0/24 — last"},
		{"203.0.113.0", true, "TEST-NET-3 documentation 203.0.113.0/24 (RFC 5737) — first"},
		{"203.0.113.128", true, "TEST-NET-3 documentation 203.0.113.0/24 — interior"},
		{"203.0.113.255", true, "TEST-NET-3 documentation 203.0.113.0/24 — last"},
		{"224.0.0.0", true, "multicast 224.0.0.0/4 (RFC 5771) — first"},
		{"232.0.0.0", true, "multicast 224.0.0.0/4 — interior"},
		{"239.255.255.255", true, "multicast 224.0.0.0/4 — last"},
		{"240.0.0.0", true, "reserved/Class E 240.0.0.0/4 (RFC 1112 §4) — first"},
		{"248.0.0.0", true, "reserved/Class E 240.0.0.0/4 — interior"},
		{"255.255.255.255", true, "limited broadcast 255.255.255.255/32 (RFC 8190) — also the last address of Class E 240.0.0.0/4"},

		// ─── GROUP 2: IPv4 Globally-Reachable=True rows. Standalone GR=True
		// rows are routable anycast services, deliberately NOT blocked; GR=True
		// sub-rows INSIDE blocked parents stay blocked (deliberate conservative
		// overblock — no WHOIS servers live there). ───
		{"192.31.196.1", false, "AS112-v4 192.31.196.0/24 (RFC 7535, GR=True) — routable anycast service, deliberately not blocked"},
		{"192.52.193.1", false, "AMT 192.52.193.0/24 (RFC 7450, GR=True) — routable anycast service, deliberately not blocked"},
		{"192.175.48.1", false, "AS112 Direct Delegation 192.175.48.0/24 (RFC 7534, GR=True) — routable anycast service, deliberately not blocked"},
		{"192.0.0.9", true, "PCP anycast 192.0.0.9/32 (RFC 7723, GR=True) inside blocked parent 192.0.0.0/24 — deliberate conservative overblock"},
		{"192.0.0.10", true, "Traversal-Using-Relays anycast 192.0.0.10/32 (RFC 8155, GR=True) inside blocked parent 192.0.0.0/24 — deliberate conservative overblock"},

		// ─── GROUP 3: IANA IPv6 Special-Purpose Address Registry (plus the
		// deprecated registry-removed ranges) — must be BLOCKED
		// (first / interior / last per prefix). ───
		{"::1", true, "loopback ::1/128 (RFC 4291)"},
		{"::", true, "unspecified ::/128 (RFC 4291)"},
		// ::/96 IPv4-compatible (RFC 4291 §2.5.5.1, deprecated & removed from
		// the registry) — embeds an internal v4 target; Unmap does NOT
		// normalize it (ENG-5123 r5, Codex P1). ::/96's literal first address
		// is :: itself (pinned above as ::/128), so probe three distinct points.
		{"::1.2.3.4", true, "IPv4-compatible ::/96 (deprecated, RFC 4291) — interior, proves range rejection"},
		{"::127.0.0.1", true, "IPv4-compatible ::/96 wrapping loopback 127.0.0.1 — the ENG-5123 r5 Codex P1 finding, stays pinned"},
		{"::255.255.255.255", true, "IPv4-compatible ::/96 — last address (0:0:0:0:0:0:ffff:ffff; NOT IPv4-mapped, group 6 is zero)"},
		{"64:ff9b::", true, "well-known NAT64 64:ff9b::/96 (RFC 6052, GR=True but embeds an IPv4 target — deliberately blocked) — first"},
		{"64:ff9b::8000:0", true, "well-known NAT64 64:ff9b::/96 — interior"},
		{"64:ff9b::ffff:ffff", true, "well-known NAT64 64:ff9b::/96 — last"},
		{"64:ff9b:1::", true, "local-use NAT64 64:ff9b:1::/48 (RFC 8215, embeds IPv4) — first"},
		{"64:ff9b:1:8000::", true, "local-use NAT64 64:ff9b:1::/48 — interior"},
		{"64:ff9b:1:ffff:ffff:ffff:ffff:ffff", true, "local-use NAT64 64:ff9b:1::/48 — last"},
		{"100::", true, "discard-only 100::/64 (RFC 6666) — first"},
		{"100::8000:0:0:0", true, "discard-only 100::/64 — interior"},
		{"100::ffff:ffff:ffff:ffff", true, "discard-only 100::/64 — last"},
		{"100:0:0:1::", true, "dummy prefix 100:0:0:1::/64 (RFC 9780, registry row added 2025-04, the row the old enumeration missed) — first"},
		{"100:0:0:1:8000::", true, "dummy prefix 100:0:0:1::/64 (RFC 9780) — interior"},
		{"100:0:0:1:ffff:ffff:ffff:ffff", true, "dummy prefix 100:0:0:1::/64 (RFC 9780) — last"},
		{"2001::", true, "IETF Protocol Assignments 2001::/23 (RFC 2928) — first (also the Teredo 2001::/32 base)"},
		{"2001:100::", true, "IETF Protocol Assignments 2001::/23 — interior (first host bit)"},
		{"2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", true, "IETF Protocol Assignments 2001::/23 — last"},
		{"2001::1", true, "Teredo 2001::/32 (RFC 4380) — GR sub-row inside blocked parent 2001::/23, deliberate conservative overblock"},
		{"2001:2::1", true, "benchmarking 2001:2::/48 (RFC 5180) inside blocked parent 2001::/23"},
		{"2001:20::1", true, "ORCHIDv2 2001:20::/28 (RFC 7343) inside blocked parent 2001::/23"},
		{"2001:db8::", true, "documentation 2001:db8::/32 (RFC 3849) — first"},
		{"2001:db8:8000::", true, "documentation 2001:db8::/32 — interior"},
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true, "documentation 2001:db8::/32 — last"},
		{"2002::", true, "6to4 2002::/16 (RFC 3056, embeds IPv4) — first"},
		{"2002:8000::", true, "6to4 2002::/16 — interior"},
		{"2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "6to4 2002::/16 — last"},
		// 3fff::/20 sits INSIDE 2000::/3, so the structural gate cannot catch
		// it — this enumerated entry is load-bearing (mutation-proven).
		{"3fff::", true, "documentation 3fff::/20 (RFC 9637, registry row added 2024) — first"},
		{"3fff:800::", true, "documentation 3fff::/20 (RFC 9637) — interior (first host bit)"},
		{"3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", true, "documentation 3fff::/20 (RFC 9637) — last"},
		{"5f00::", true, "SRv6 SIDs 5f00::/16 (RFC 9602) — first"},
		{"5f00:8000::", true, "SRv6 SIDs 5f00::/16 — interior"},
		{"5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "SRv6 SIDs 5f00::/16 — last"},
		{"fc00::", true, "unique local fc00::/7 (RFC 4193) — first"},
		{"fd00::", true, "unique local fc00::/7 — interior (fd00::/8 half)"},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "unique local fc00::/7 — last"},
		{"fe80::", true, "link-local unicast fe80::/10 (RFC 4291) — first"},
		{"fea0::", true, "link-local unicast fe80::/10 — interior"},
		{"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "link-local unicast fe80::/10 — last"},
		{"fec0::", true, "deprecated site-local fec0::/10 (RFC 3879, removed from the registry) — first"},
		{"fec0::1", true, "deprecated site-local fec0::/10 — the ENG-5123 r4 finding, stays pinned"},
		{"fee0::", true, "deprecated site-local fec0::/10 — interior"},
		{"feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "deprecated site-local fec0::/10 — last"},
		{"ff00::", true, "multicast ff00::/8 (RFC 4291) — first"},
		{"ff80::", true, "multicast ff00::/8 — interior"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "multicast ff00::/8 — last"},

		// ─── GROUP 4: Reserved-by-IETF IPv6 space (IANA IPv6 Address Space
		// registry) — every top-level block outside 2000::/3 must be BLOCKED
		// by the STRUCTURAL gate alone; none of these appear in the enumerated
		// list (except where noted), so these cases pin the gate itself. ───
		{"100:0:0:2::1", true, "reserved 0100::/8 space between/outside the two enumerated /64s (100::/64, 100:0:0:1::/64) — only the structural gate catches it (mutation-proven)"},
		{"100::ffff", true, "inside discard-only 100::/64 (0100:0:0:0::ffff) — blocked by BOTH the gate and the enumeration"},
		{"200::1", true, "deprecated OSI NSAP-mapped 200::/7 (RFC 4048) — reserved by IETF, gate-blocked"},
		{"400::1", true, "reserved 400::/6 (IPv6 Address Space registry) — gate-blocked"},
		{"800::1", true, "reserved 800::/5 — gate-blocked"},
		{"1000::1", true, "reserved 1000::/4 — gate-blocked"},
		{"1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "last address below 2000:: — lower boundary of the structural gate"},
		{"4000::1", true, "reserved 4000::/3 — first block above 3fff:ffff…, upper boundary of the gate"},
		{"5f01::1", true, "returned 6bone 5f00::/8 (RFC 1897, returned) but OUTSIDE SRv6 5f00::/16 — gate-blocked, not enumeration-blocked"},
		{"6000::1", true, "reserved 6000::/3 — gate-blocked"},
		{"8000::1", true, "reserved 8000::/3 — gate-blocked"},
		{"a000::1", true, "reserved a000::/3 — gate-blocked"},
		{"c000::1", true, "reserved c000::/3 — gate-blocked"},
		{"e000::1", true, "reserved e000::/4 — gate-blocked"},
		{"f000::1", true, "reserved f000::/5 — gate-blocked"},
		{"f800::1", true, "reserved f800::/6 — gate-blocked"},
		{"fe00::1", true, "reserved fe00::/9 (NOT link-local fe80::/10) — gate-blocked; the range nobody would have enumerated"},

		// ─── GROUP 5: public allow anchors + boundaries — must be ALLOWED
		// (0 public regressions), plus mapped-internal must be BLOCKED. ───
		{"8.8.8.8", false, "Google Public DNS — public v4 anchor"},
		{"1.1.1.1", false, "Cloudflare DNS — public v4 anchor"},
		{"::ffff:8.8.8.8", false, "IPv4-mapped public (::ffff:0:0/96) — Unmap normalizes to 8.8.8.8, judged by the embedded v4, allowed"},
		{"2001:4860:4860::8888", false, "Google Public DNS — public v6 anchor (ARIN space)"},
		{"2606:4700:4700::1111", false, "Cloudflare DNS — public v6 anchor (ARIN space)"},
		{"2a00:1450:4001:800::200e", false, "RIPE-region public v6 anchor (google.com)"},
		{"2400:cb00::1", false, "APNIC-region public v6 anchor (Cloudflare)"},
		{"2c0f:fb50::1", false, "AFRINIC-region public v6 anchor (Google ZA)"},
		{"2800:3f0::1", false, "LACNIC-region public v6 anchor (Google AR)"},
		{"2000::1", false, "first address of global unicast 2000::/3 — lower boundary of the structural gate, allowed"},
		{"3ffe::1", false, "returned 6bone 3ffe::/16 — unallocated-but-allocatable global unicast inside 2000::/3; bogon filtering deliberately out of scope, allowed"},
		{"2620:4f:8000::1", false, "AS112 Direct Delegation 2620:4f:8000::/48 (RFC 7534, GR=True standalone row) — routable anycast service, deliberately allowed"},
		{"::ffff:10.0.0.1", true, "IPv4-mapped RFC1918 — Unmap yields 10.0.0.1, mapped-internal must be blocked"},
		{"::ffff:169.254.169.254", true, "IPv4-mapped cloud metadata — Unmap yields 169.254.169.254, mapped-internal must be blocked"},
	}

	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			require.NotNilf(t, ip, "net.ParseIP(%q) must parse — bad literal in the table", tc.ip)
			got := isDisallowedDialIP(ip)
			assert.Equalf(t, tc.blocked, got,
				"isDisallowedDialIP(%s): want blocked=%v — %s", tc.ip, tc.blocked, tc.reason)
		})
	}
}

// TestWhoisRaw_SSRFGuardBlocksInternalReferral proves the guard fires end-to-end
// on the dial path: a referral pointing at an internal address is refused before
// any connection is attempted (ENG-5123 review, Gemini). Hermetic: no socket is
// ever opened because Control rejects pre-connect.
func TestWhoisRaw_SSRFGuardBlocksInternalReferral(t *testing.T) {
	_, err := whoisRaw(context.Background(), "example.com", "127.0.0.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssrf guard")
}

func TestExtractReferral_IanaRefer(t *testing.T) {
	raw := "refer:        whois.verisign-grs.com\n\ndomain:       COM\n"
	assert.Equal(t, "whois.verisign-grs.com", extractReferral(raw))
}

func TestExtractReferral_RegistrarWhoisServer(t *testing.T) {
	raw := "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: whois.registrar.com\n"
	assert.Equal(t, "whois.registrar.com", extractReferral(raw))
}

func TestExtractReferral_WhoisField(t *testing.T) {
	raw := "whois:        whois.nic.uk\n"
	assert.Equal(t, "whois.nic.uk", extractReferral(raw))
}

func TestExtractReferral_NoReferral(t *testing.T) {
	raw := "Domain Name: EXAMPLE.COM\nRegistrant: Acme Corp\n"
	assert.Equal(t, "", extractReferral(raw))
}

func TestExtractReferral_StripsProtocol(t *testing.T) {
	raw := "Registrar WHOIS Server: https://whois.example.com/\n"
	assert.Equal(t, "whois.example.com", extractReferral(raw))
}

// TestWhoisDialAddr proves whoisDialAddr always normalizes a (possibly
// untrusted) referral server to the standard WHOIS port tcp/43: it appends :43
// to a bare host, strips scheme/trailing slash, and DROPS any explicit port a
// referral carries. WHOIS is tcp/43 by protocol, so honoring a non-43 port
// would let a hostile WHOIS record steer the plugin into probing arbitrary
// public host:port pairs (the SSRF guard blocks non-public IPs, not a public
// host on an arbitrary port). Strip-then-append also keeps a :43 referral from
// being double-appended into a malformed "host:43:43" (ENG-5123 review, Gemini
// + Codex).
func TestWhoisDialAddr(t *testing.T) {
	assert.Equal(t, "whois.nic.uk:43", whoisDialAddr("whois.nic.uk"))
	assert.Equal(t, "whois.example.com:43", whoisDialAddr("https://whois.example.com/"))
	assert.Equal(t, "whois.example.com:43", whoisDialAddr("whois.example.com:43")) // :43 stripped then re-appended, never doubled into host:43:43
	// Security: a hostile referral carrying a non-standard port must be
	// normalized back to tcp/43, closing the arbitrary-port-probing vector — the
	// SSRF guard only blocks non-public IPs, not a public host on any port
	// (ENG-5123 review, Codex).
	assert.Equal(t, "evil.example.com:43", whoisDialAddr("evil.example.com:22"))
	assert.Equal(t, "whois.registry.net:43", whoisDialAddr("whois.registry.net:4343")) // non-standard port dropped, not preserved
	// A bracketed IPv6 referral with a port round-trips: the port is dropped and
	// the address is re-bracketed with :43.
	assert.Equal(t, "[2001:db8::1]:43", whoisDialAddr("[2001:db8::1]:8080"))
	// A bracketed IPv6 literal WITHOUT a port makes SplitHostPort fail; the
	// else-branch must strip the brackets so JoinHostPort re-wraps the address
	// exactly once as "[2001:db8::1]:43" rather than double-bracketing into the
	// malformed "[[2001:db8::1]]:43" that never dials (ENG-5123 review, Gemini).
	assert.Equal(t, "[2001:db8::1]:43", whoisDialAddr("[2001:db8::1]"))
}

func TestBoundedDeadline_UsesCtxDeadlineWhenSooner(t *testing.T) {
	soon := time.Now().Add(50 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), soon)
	defer cancel()
	// ctx deadline (50ms) is well inside the fixed queryTimeout, so it wins.
	got := boundedDeadline(ctx)
	assert.WithinDuration(t, soon, got, time.Millisecond)
}

func TestBoundedDeadline_FallsBackToQueryTimeout(t *testing.T) {
	// A ctx with no deadline falls back to the fixed per-query timeout.
	got := boundedDeadline(context.Background())
	assert.WithinDuration(t, time.Now().Add(queryTimeout), got, time.Second)
}

// TestReadAllWithContext_HonorsCancellation proves that a read parked on a
// server that never replies unwinds as soon as ctx is cancelled — not after the
// full fixed deadline — so the WHOIS fallback respects the pass-wide budget's
// cancellation (ENG-5123 review). Hermetic: net.Pipe, no network.
func TestReadAllWithContext_HonorsCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }() // server never writes → read would block forever

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: watcher must close the conn and unblock the read

	start := time.Now()
	_, err := readAllWithContext(ctx, client, "example.com", "whois.example.com")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, elapsed, 2*time.Second, "cancellation must unblock the read promptly")
}

// TestReadAllWithContext_HonorsDeadline proves an already-past ctx deadline ends
// the read immediately and is surfaced as context.DeadlineExceeded rather than a
// raw i/o-timeout error.
func TestReadAllWithContext_HonorsDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	start := time.Now()
	_, err := readAllWithContext(ctx, client, "example.com", "whois.example.com")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 2*time.Second, "past deadline must end the read promptly")
}

// TestReadAllWithContext_CapsResponseSize proves a server that streams more than
// maxWhoisResponseBytes is truncated at the cap rather than read unbounded — the
// memory-amplification guard the reverse-whois verifier relies on when driving
// this read for many candidates concurrently (ENG-5123 review). Hermetic:
// net.Pipe, no network.
func TestReadAllWithContext_CapsResponseSize(t *testing.T) {
	client, server := net.Pipe()
	// net.Pipe is unbuffered, so the oversized Write below blocks once the reader
	// stops at the cap; closing the client at test end unblocks and reaps it.
	defer func() { _ = client.Close() }()
	go func() {
		big := make([]byte, maxWhoisResponseBytes+4096)
		_, _ = server.Write(big)
		_ = server.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	resp, err := readAllWithContext(ctx, client, "example.com", "whois.example.com")
	require.NoError(t, err)
	assert.Len(t, resp, maxWhoisResponseBytes, "response must be capped at maxWhoisResponseBytes")
}

// TestReadAllWithContext_ReadsFullResponse proves the happy path still returns
// the complete payload and leaves no error when the peer sends data then closes.
func TestReadAllWithContext_ReadsFullResponse(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		_, _ = server.Write([]byte("Registrant: Acme Corp\n"))
		_ = server.Close() // EOF ends io.ReadAll
	}()

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	resp, err := readAllWithContext(ctx, client, "example.com", "whois.example.com")
	require.NoError(t, err)
	assert.Equal(t, "Registrant: Acme Corp\n", string(resp))
}

// stubWhoisRawFn reassigns the whoisRawFn production seam to fn for the duration
// of the test and restores the original via t.Cleanup. This lets whoisQuery's
// referral/salvage state machine be driven hermetically — no socket, no DNS —
// by returning canned raw records keyed by the server being queried.
func stubWhoisRawFn(t *testing.T, fn func(ctx context.Context, domain, server string) (string, error)) {
	t.Helper()
	prev := whoisRawFn
	whoisRawFn = fn
	t.Cleanup(func() { whoisRawFn = prev })
}

// TestWhoisQuery_SeedOnlyChainReturnsError pins Fix A's core invariant: when only
// the bootstrap seed (whois.iana.org) answers and it carries NO referral, the
// chain never advances past the seed, so whoisQuery returns the seed-guard error
// (never the seed record) and the caller scores the candidate unverified 0.50.
// The seed's response is the TLD registry record, not the registrant's, so
// salvaging it would hand the caller a wrong-entity record it cannot distinguish
// from a real one.
func TestWhoisQuery_SeedOnlyChainReturnsError(t *testing.T) {
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		require.Equal(t, defaultServer, server, "only the bootstrap seed should be queried")
		// A seed record with NO referral line: extractReferral returns "" so the
		// loop breaks at the seed and lastRaw is never set.
		return "domain: COM\norganisation: VeriSign Global Registry Services\n", nil
	})

	got, incomplete, err := whoisQuery(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no record beyond bootstrap seed")
	assert.Empty(t, got, "no salvageable record should be returned for a seed-only chain")
	assert.Equal(t, whoisComplete, incomplete, "an error path reports no partial record")
}

// TestWhoisQuery_PostReferralSalvageReturnsPostReferralRecord pins the
// de-rank-never-drop salvage: the seed refers to a TLD server that returns a real
// registrant record whose own referral points to a registrar server that ERRORS.
// whoisQuery must salvage the TLD server's post-referral record (nil error), NOT
// the seed record — a later hop failing does not discard an already-advanced
// post-referral record.
func TestWhoisQuery_PostReferralSalvageReturnsPostReferralRecord(t *testing.T) {
	const (
		tldServer       = "whois.tld.example"
		registrarServer = "whois.registrar.example"
		seedRecord      = "refer: whois.tld.example\ndomain: EXAMPLE\n"
		tldRecord       = "Domain Name: EXAMPLE.COM\nRegistrant Organization: Acme Corp\nRegistrar WHOIS Server: whois.registrar.example\n"
	)
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		switch server {
		case defaultServer:
			return seedRecord, nil // seed refers onward to the TLD server
		case tldServer:
			return tldRecord, nil // real registrant record, refers to the registrar
		case registrarServer:
			return "", fmt.Errorf("dial tcp: connection refused") // registrar hop fails
		default:
			t.Fatalf("unexpected server queried: %q", server)
			return "", nil
		}
	})

	got, incomplete, err := whoisQuery(context.Background(), "example.com")

	require.NoError(t, err, "a failed registrar hop must not discard the salvaged TLD record")
	assert.Equal(t, tldRecord, got, "must return the post-referral TLD record")
	assert.NotEqual(t, seedRecord, got, "must NOT salvage the bootstrap seed record")
	// ENG-5405: the salvage still returns the payload with a nil error (recall is
	// unchanged and this line pins it), but the caller now also learns WHY the
	// record is partial, so a truncated chain is no longer indistinguishable from
	// a chain that completed and found no registrant.
	assert.Equal(t, whoisIncompleteReferral, incomplete,
		"a failed registrar hop must report itself as an incomplete referral chain")
}

// TestWhoisQuery_CtxCancelAfterSeedReturnsError pins the ctx-error path when
// cancellation is observed with nothing salvageable: the seed answers (with a
// referral so the chain would otherwise continue) but ctx is cancelled before the
// next hop runs. Because only the seed answered, lastRaw is empty and whoisQuery
// returns the ctx error, not a record.
func TestWhoisQuery_CtxCancelAfterSeedReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		require.Equal(t, defaultServer, server, "only the seed should be reached before cancellation")
		cancel() // cancel so the NEXT loop iteration observes it with lastRaw still empty
		return "refer: whois.tld.example\n", nil
	})

	got, incomplete, err := whoisQuery(ctx, "example.com")

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, got, "nothing salvageable → no record on the cancelled path")
	assert.Equal(t, whoisComplete, incomplete, "an error path reports no partial record")
}

// TestWhoisQuery_CtxCancelAfterReferralSalvages pins the other ctx-error branch:
// once a referral has advanced past the seed and set lastRaw, an observed
// cancellation salvages that post-referral record with a nil error rather than
// discarding it — the budget-honoring path stays recall-safe.
func TestWhoisQuery_CtxCancelAfterReferralSalvages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	const (
		tldServer = "whois.tld.example"
		tldRecord = "Registrant Organization: Acme Corp\nRegistrar WHOIS Server: whois.registrar.example\n"
	)
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		switch server {
		case defaultServer:
			return "refer: whois.tld.example\n", nil // advance past the seed
		case tldServer:
			cancel() // now lastRaw holds the TLD record; cancel so the next iteration bails
			return tldRecord, nil
		default:
			t.Fatalf("unexpected server queried after cancel: %q", server)
			return "", nil
		}
	})

	got, incomplete, err := whoisQuery(ctx, "example.com")

	require.NoError(t, err, "a cancellation after a referral advanced must salvage the post-referral record")
	assert.Equal(t, tldRecord, got, "must return the salvaged post-referral TLD record")
	// ENG-5405: recall is unchanged (the require.NoError above pins it), but the
	// caller now also learns WHY the record is partial — a deadline or
	// cancellation observed mid-chain — instead of a bit-identical "chain
	// completed, no registrant".
	assert.Equal(t, whoisIncompleteDeadline, incomplete,
		"a cancellation observed mid-chain must report itself as a deadline-expired record")
}

// TestWhoisQuery_ReferralHopFailureOnRegistrantLessRecordIsDistinguishable is
// the AC2 unit-level case for ENG-5405. It differs from
// TestWhoisQuery_PostReferralSalvageReturnsPostReferralRecord in the payload:
// there the salvaged TLD record HAS a registrant org, so the outcome was never
// ambiguous. Here it has none, which is exactly the state that used to be
// indistinguishable from "this domain has no registrant on record".
func TestWhoisQuery_ReferralHopFailureOnRegistrantLessRecordIsDistinguishable(t *testing.T) {
	const (
		seedRecord = "refer: whois.tld.example\ndomain: EXAMPLE\n"
		// No Registrant Organization and no Registrant Name — but a referral
		// onward, so the chain is NOT finished.
		tldRecordNoRegistrant = "Domain Name: EXAMPLE.COM\n" +
			"Registrar: Example Registrar, Inc.\n" +
			"Registrar WHOIS Server: whois.registrar.example\n"
	)
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		switch server {
		case defaultServer:
			return seedRecord, nil
		case "whois.tld.example":
			return tldRecordNoRegistrant, nil
		case "whois.registrar.example":
			return "", errors.New("connection refused") // the referral hop FAILS
		default:
			t.Fatalf("unexpected whois server %q", server)
			return "", nil
		}
	})

	got, incomplete, err := whoisQuery(context.Background(), "example.com")

	require.NoError(t, err, "the salvage must not discard the recall-safe payload")
	assert.Equal(t, tldRecordNoRegistrant, got, "the salvaged post-referral record is returned")
	assert.Equal(t, whoisIncompleteReferral, incomplete, "and it is reported as partial")
}

// TestWhoisQuery_RegistrantLessCompleteChainStaysComplete is the AC3
// unit-level case for ENG-5405 and the mirror of the AC2 case above: the chain
// runs to its natural end (the post-referral TLD record carries NO onward
// referral, so the loop breaks) and that record genuinely has no registrant
// organization on record. This must stay the ORDINARY not-found outcome. Without
// this case the fix could satisfy AC2 by calling everything incomplete, which
// collapses the distinction in the other direction.
func TestWhoisQuery_RegistrantLessCompleteChainStaysComplete(t *testing.T) {
	const (
		seedRecord = "refer: whois.tld.example\ndomain: EXAMPLE\n"
		// No Registrant Organization, no Registrant Name, and NO onward referral:
		// the chain ends here on its own.
		tldRecordNoRegistrant = "Domain Name: EXAMPLE.COM\n" +
			"Registrar: Example Registrar, Inc.\n"
	)
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		switch server {
		case defaultServer:
			return seedRecord, nil
		case "whois.tld.example":
			return tldRecordNoRegistrant, nil
		default:
			t.Fatalf("unexpected whois server %q", server)
			return "", nil
		}
	})

	got, incomplete, err := whoisQuery(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, tldRecordNoRegistrant, got, "the chain's endpoint record is returned")
	assert.Equal(t, whoisComplete, incomplete,
		"a chain that ran to its natural end is complete, even with no registrant")
}

// TestWhoisQuery_HopBudgetExhaustionWithPendingReferralIsIncomplete covers the
// third indistinguishable arm ENG-5405 closes: every hop yields a FURTHER
// referral, so the loop exits on its own maxWhoisReferrals bound with a referral
// still unfollowed. lastRaw is then a mid-chain record, not the chain's
// endpoint — previously returned as (record, nil) with no way to tell it apart
// from a chain that completed and found no registrant.
func TestWhoisQuery_HopBudgetExhaustionWithPendingReferralIsIncomplete(t *testing.T) {
	// The seed plus four hops is exactly maxWhoisReferrals queries, and hop 4
	// still refers onward, so whois.hop5.example is left unfollowed.
	const hop4Record = "Domain Name: EXAMPLE.COM\nrefer: whois.hop5.example\n"

	var calls int
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		calls++
		switch server {
		case defaultServer:
			return "refer: whois.hop1.example\n", nil
		case "whois.hop1.example":
			return "Domain Name: EXAMPLE.COM\nrefer: whois.hop2.example\n", nil
		case "whois.hop2.example":
			return "Domain Name: EXAMPLE.COM\nrefer: whois.hop3.example\n", nil
		case "whois.hop3.example":
			return "Domain Name: EXAMPLE.COM\nrefer: whois.hop4.example\n", nil
		case "whois.hop4.example":
			return hop4Record, nil
		default:
			t.Fatalf("unexpected whois server %q: the hop budget must stop the chain at hop 4", server)
			return "", nil
		}
	})

	got, incomplete, err := whoisQuery(context.Background(), "example.com")

	require.NoError(t, err, "hop-budget exhaustion stays recall-safe: the mid-chain record is still returned")
	assert.Equal(t, hop4Record, got, "the last record the budget allowed is salvaged")
	assert.Equal(t, whoisIncompleteHops, incomplete,
		"a budget-exhausted chain with a pending referral must report itself as partial")
	assert.Equal(t, maxWhoisReferrals, calls, "the chain must stop after exactly maxWhoisReferrals hops")
}

// TestWhoisPlugin_Run_CancelledContextDoesNotEmit pins Fix A: whoisQuery is shared
// with the reverse-whois verifier, where a caller cancellation deliberately
// SALVAGES the last post-referral record (recall-safe, nil error). WhoisPlugin has
// no such recall contract — a cancelled run must ABORT, not emit preseeds parsed
// from that salvaged partial record. The stub drives whoisQuery into its
// salvage-on-cancel branch (a post-referral hop sets lastRaw, then the context is
// cancelled so the next loop-top ctx.Err() check returns (lastRaw, nil)), and Run
// must re-check the context and return the ctx error with NO findings rather than
// parsing the salvaged record (ENG-5123 review, Codex).
func TestWhoisPlugin_Run_CancelledContextDoesNotEmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var calls int
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		calls++
		switch server {
		case defaultServer:
			// Bootstrap seed hop: refer onward to the registrar server. The seed
			// record is NOT salvageable (server == defaultServer), so lastRaw stays
			// empty here and only the referral matters.
			return "refer: whois.registrar.test\n", nil
		case "whois.registrar.test":
			// Post-referral hop: a real registrant record that whoisparser.Parse
			// accepts (the "Domain Name:" line satisfies its validity check) AND
			// that yields preseeds (registrant org/name/email) AND that ALSO refers
			// onward to a THIRD server via "Registrar WHOIS Server:" (so lastRaw is
			// set AND the loop would continue). Cancel the context right before
			// returning so the next loop-top ctx.Err() check fires and whoisQuery
			// returns (lastRaw, nil) — the salvage-on-cancel path. Without Fix A's
			// guard, Run would parse THIS record into 3 preseeds and return them with
			// a nil error; the guard makes it abort with the ctx error instead.
			cancel()
			return "Domain Name: EXAMPLE.COM\n" +
				"Registry Domain ID: 2336799_DOMAIN_COM-VRSN\n" +
				"Registrar WHOIS Server: whois.second.test\n" +
				"Registrar: Example Registrar, LLC\n" +
				"Creation Date: 1995-08-14T04:00:00Z\n" +
				"Registrant Organization: Acme Corp\n" +
				"Registrant Name: John Doe\n" +
				"Registrant Email: admin@acme.com\n", nil
		default:
			// The third-server hop must never run: the ctx.Err() check at the loop
			// top returns the salvaged record first.
			t.Fatalf("unexpected server queried after cancel: %q", server)
			return "", nil
		}
	})

	findings, err := (&WhoisPlugin{}).Run(ctx, plugins.Input{Domain: "example.com"})

	// assert (not require) so that when Fix A's guard is removed a single run
	// exhibits every caught assertion at once: without the guard Run parses the
	// salvaged record into 3 preseeds and returns them with a nil error, so the
	// error-present, error-is-Canceled, AND findings-empty checks all fail
	// together — each assertion is independently mutation-proven.
	assert.Error(t, err, "a cancelled Run must abort, not emit salvaged preseeds")
	assert.True(t, errors.Is(err, context.Canceled), "error must wrap context.Canceled, got %v", err)
	assert.Empty(t, findings, "no preseeds may be emitted from a salvaged partial record on a cancelled run")
	assert.Equal(t, 2, calls, "the third-server hop must not run: ctx.Err() salvages lastRaw at the loop top")
}

// TestWhoisPlugin_Run_RecoversParserPanic proves the deferred recover in
// WhoisPlugin.Run catches a panic raised while parsing an untrusted WHOIS
// record and de-grades it to a logged error + no preseeds, instead of letting
// the panic unwind through the errgroup goroutine and crash the whole pius run
// (ENG-5123 review, Gemini). whoisparser.Parse (v1.24.21) is defensive enough
// that no adversarial raw input reliably panics it — which is exactly why the
// package-level whoisParseFn seam exists: injecting a panicking parse is the
// only way to exercise the guard. Hermetic: both the network seam (whoisRawFn,
// via stubWhoisRawFn) and the parse seam (whoisParseFn) are stubbed, so no
// socket, DNS, or real WHOIS/RDAP call happens.
func TestWhoisPlugin_Run_RecoversParserPanic(t *testing.T) {
	// Drive whoisQuery to a successful, network-free result. The bootstrap seed
	// (defaultServer) must refer once past itself, because whoisQuery never
	// salvages the seed record alone (seed-guard invariant); the referred-to
	// server then returns a benign record with NO further referral, so the loop
	// breaks with lastRaw set and whoisQuery returns that non-empty record. The
	// raw content is irrelevant — the injected parse below ignores it entirely.
	// stubWhoisRawFn restores whoisRawFn automatically via t.Cleanup.
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		if server == defaultServer {
			return "refer: whois.registrar.test\n", nil // advance past the bootstrap seed
		}
		return "Domain Name: example.com\n", nil // benign post-referral record, no refer line
	})

	// Inject a parse that panics, standing in for a malformed third-party record
	// that trips the parser. Save/restore the seam via defer.
	orig := whoisParseFn
	defer func() { whoisParseFn = orig }()
	whoisParseFn = func(string) (whoisparser.WhoisInfo, error) {
		panic("synthetic parse panic")
	}

	// If Run re-panicked (i.e. the guard were removed) the panic would unwind
	// past this call and crash the test binary — so merely REACHING the
	// assertions below is itself proof that the deferred recover fired.
	findings, err := (&WhoisPlugin{}).Run(context.Background(), plugins.Input{Domain: "example.com"})

	assert.Error(t, err, "a recovered parser panic must surface as an error")
	assert.Contains(t, err.Error(), "recovered panic", "error must name the recovered panic")
	assert.Contains(t, err.Error(), "example.com", "error must name the domain whose record panicked")
	assert.Empty(t, findings, "no preseeds may be emitted when parsing panicked")
}
