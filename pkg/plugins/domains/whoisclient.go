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

	// whoisHopAttempts bounds the per-hop retry. Registry and registrar WHOIS
	// servers throttle and drop connections routinely, and without a retry a
	// single dropped hop truncates the whole chain.
	whoisHopAttempts = 3

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

// whoisIncompleteness names WHY a WHOIS record is known to be partial.
//
// The zero value, whoisComplete, means "the referral chain ran to a natural end"
// — so a whoisIncompleteness that is never assigned reads as complete, and every
// pre-existing registrantResult literal keeps its old meaning. This polarity is
// load-bearing: a `Complete bool` field would default to false and make every
// existing zero-valued struct claim incompleteness (ENG-5405).
//
// It is a string, not an int enum, so the value logs directly as a slog
// attribute with no String() method to maintain. The set is closed and
// compile-time constant, which is why it is safe to log where the raw WHOIS
// payload and the unbounded, attacker-chosen referral server string are not.
type whoisIncompleteness string

const (
	whoisComplete           whoisIncompleteness = ""
	whoisIncompleteDeadline whoisIncompleteness = "deadline_expired" // ctx deadline/cancel observed mid-chain
	whoisIncompleteReferral whoisIncompleteness = "referral_failed"  // a referral hop's transport failed
	whoisIncompleteHops     whoisIncompleteness = "referral_budget"  // hop budget exhausted with a referral pending
)

// maxWhoisReferrals bounds the referral chain to prevent loops. Eight matches
// the bound the consumer's own referral walker used before this became the only
// TCP/43 path in production; a few registries chain seed -> registry ->
// registrar -> a reseller's server, and five hops truncated those.
const maxWhoisReferrals = 8

// disallowedDialPrefixes is the enumerated layer of the two-layer "public
// unicast only" guard on untrusted WHOIS referrals (see isDisallowedDialIP):
//
//   - Layer 1 (structural): a genuine IPv6 address outside 2000::/3 is denied
//     wholesale (see v6GlobalUnicast) — covering ALL Reserved-by-IETF and
//     deprecated IPv6 space, present and future, without enumerating it.
//   - Layer 2 (enumerated, this list): mirrors the IANA IPv4 and IPv6
//     Special-Purpose Address Registries (snapshot 2026-07-28) for every row
//     that is not Globally Reachable=True, plus multicast/Class E, plus the
//     deprecated registry-removed ranges (site-local fec0::/10,
//     IPv4-compatible ::/96).
//
// Earlier rounds spot-added ranges to a byte-switch one reviewer finding at a
// time (CGNAT, benchmarking, Class E, TEST-NETs, the IPv6 transition prefixes,
// then local-use NAT64, then 0.0.0.0/8, then fec0::/10 and ::/96); the two
// layers together are the durable shape and stop the whack-a-mole (ENG-5123
// review — Codex, Gemini, CodeRabbit).
//
// Deliberate boundaries of the enumeration:
//
//   - Standalone Globally-Reachable=True registry rows (AS112 192.31.196.0/24
//     and 192.175.48.0/24, AMT 192.52.193.0/24, Direct Delegation AS112
//     2620:4f:8000::/48) are ALLOWED — truly routable anycast services, not
//     internal pivots.
//   - 64:ff9b::/96 (NAT64) is blocked despite Globally Reachable=True because
//     it embeds an IPv4 target.
//   - Globally-reachable sub-rows inside blocked parents (192.0.0.9/.10
//     anycast inside 192.0.0.0/24; the PCP/AMT/AS112/ORCHIDv2/DETs sub-blocks
//     inside 2001::/23) stay blocked — conservative; no WHOIS servers live
//     there.
//   - Unallocated-but-allocatable global unicast inside 2000::/3 (e.g. the
//     returned 6bone 3ffe::/16) is ALLOWED — bogon filtering is a moving
//     target and out of scope.
//   - IPv4-mapped ::ffff:0:0/96 is judged by its embedded v4 address after
//     Unmap: mapped-public is allowed, mapped-internal is blocked.
//
// The IPv6 v4-embedding prefixes — IPv4-compatible ::/96 (deprecated), 6to4
// 2002::/16, Teredo 2001::/32, and NAT64 64:ff9b::/96 + the RFC 8215 local-use
// 64:ff9b:1::/48 — each EMBED an IPv4 address, so denying them stops an internal
// v4 target (e.g. 169.254.169.254 or an RFC1918 host) from being smuggled past
// the v4 guard as a v6 literal.
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
		"::/96",          // IPv4-compatible IPv6 (RFC 4291 §2.5.5.1, deprecated & removed from the IANA registry) — embeds an internal v4 target (e.g. ::127.0.0.1); Unmap does NOT normalize it, so the fail-closed gate misses it (ENG-5123 review, Codex P1)
		"64:ff9b::/96",   // well-known NAT64 (embeds IPv4)
		"64:ff9b:1::/48", // local-use NAT64, RFC 8215 (embeds IPv4)
		"100::/64",       // discard-only
		"100:0:0:1::/64", // dummy prefix (RFC 9780) — non-routable; NOT inside 100::/64, a registry row added 2025-04 that the old enumeration missed
		"2001::/23",      // IETF protocol assignments (incl. Teredo 2001::/32)
		"2001:db8::/32",  // documentation
		"2002::/16",      // 6to4 (embeds IPv4)
		"3fff::/20",      // documentation (RFC 9637, added 2024) — inside 2000::/3, so the structural gate cannot catch it; this entry is load-bearing
		"5f00::/16",      // SRv6 SIDs (RFC 9602) — outside 2000::/3 (redundant with the structural gate; listed to keep the enumeration mirroring the registry)
		"fc00::/7",       // unique local (IPv6 ULA)
		"fe80::/10",      // link-local unicast
		"fec0::/10",      // deprecated site-local (RFC 3879) — non-public, absent from the current IANA registry
		"ff00::/8",       // multicast
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(c))
	}
	return prefixes
}()

// v6GlobalUnicast is the only block IANA has ever allocated for IPv6 global
// unicast ("IANA unicast address assignments are currently limited to the
// IPv6 unicast address range of 2000::/3" — IANA IPv6 Address Space registry).
// Every genuine v6 address outside it is reserved, deprecated (::/96
// IPv4-compatible, fec0::/10 site-local, 200::/7 NSAP, returned 6bone
// 5f00::/8), or special-purpose (ULA, link-local, multicast, the v4-embedding
// translation prefixes) — never a legitimate public WHOIS server. Denying
// !2000::/3 structurally closes the whole class instead of enumerating its
// members one bot-review round at a time (ENG-5123 rounds 4-5: fec0::/10,
// ::/96). If IANA ever allocates unicast outside 2000::/3 the guard fails
// closed: the dial is refused and logged, and the candidate scores unverified
// (0.50) under de-rank-never-drop — recall-safe.
var v6GlobalUnicast = netip.MustParsePrefix("2000::/3")

// isDisallowedDialIP reports whether ip is in a range we must never dial when
// following an untrusted WHOIS referral. It fails closed by default: only
// genuine global-unicast, non-private addresses pass, the structural IPv6 gate
// then denies any genuine v6 address outside 2000::/3 (see v6GlobalUnicast),
// and the enumerated disallowedDialPrefixes finally reject the remaining
// global-unicast-but-non-public ranges.
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
	// Fail closed: only genuine global-unicast, non-private addresses may pass.
	// The enumerated denylist below then rejects the ranges that are
	// global-unicast per the stdlib predicates but still non-public (CGNAT,
	// documentation, benchmarking, Class E, the v4-embedding transition
	// prefixes, and deprecated site-local fec0::/10). This inverts the guard
	// from "allow unless listed" to "deny unless proven public", so a
	// non-public range nobody enumerated no longer slips through (ENG-5123
	// review, Codex).
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return true
	}
	// Structural IPv6 gate: see v6GlobalUnicast. addr is already Unmap()ed, so
	// Is6() here means a genuine v6 address, not an IPv4-mapped one.
	if addr.Is6() && !v6GlobalUnicast.Contains(addr) {
		return true
	}
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
// Invariant: the returned record always comes from a server reached by
// following at least one referral, NEVER from the whois.iana.org bootstrap
// seed alone. The seed's response is the TLD *registry* record — its org is
// the registry operator's, not the registrant's — so salvaging it would hand
// the caller a wrong-entity record it cannot distinguish from a real one
// (false corroboration or false de-rank). If the chain breaks before
// advancing past the seed, an error is returned instead; the caller scores
// that as unverified (mid-band 0.50), so honesty costs no recall. A record
// from a post-referral hop (e.g. the TLD server when the registrar hop fails)
// is still salvaged under de-rank-never-drop.
//
// Every hop is bounded by ctx: the referral loop bails as soon as ctx is
// cancelled or its deadline passes, and whoisRaw honors ctx on the socket read.
// This keeps the fallback path inside the overall verification budget instead of
// letting maxWhoisReferrals referrals x queryTimeout stack past it
// (ENG-5123 review).
//
// The second return value reports WHY the returned record is known to be
// partial. Recall is unchanged: both salvage arms below still return the payload
// with a nil error. What is new is that a caller which previously saw only
// (record, nil) could not tell a truncated chain from a chain that ran to
// completion and found no registrant — so an incomplete lookup surfaced as
// found=false, err=nil. Every non-salvaged path reports whoisComplete, including
// all three error paths (the no-salvage deadline arm, the no-salvage hop-error
// arm, and the "no record beyond bootstrap seed" arm): with no payload there is
// nothing to describe as partial and the error is already the signal (ENG-5405).
func whoisQuery(ctx context.Context, domain string) (string, whoisIncompleteness, error) {
	return whoisQueryWithRaw(ctx, domain, whoisRawFn)
}

func whoisQueryWithRaw(ctx context.Context, domain string, rawFn func(context.Context, string, string) (string, error)) (string, whoisIncompleteness, error) {
	server := defaultServer
	var lastRaw string
	var pendingRefer string

	for i := 0; i < maxWhoisReferrals; i++ {
		if err := ctx.Err(); err != nil {
			if lastRaw != "" {
				// Recall-safe salvage, UNCHANGED: return the last post-referral
				// record rather than dropping the candidate. What is new is the
				// second return: the caller can now tell this apart from a chain
				// that ran to completion and found no registrant (ENG-5405).
				return lastRaw, whoisIncompleteDeadline, nil
			}
			return "", whoisComplete, err
		}
		raw, err := whoisHopWithRaw(ctx, domain, server, rawFn)
		if err != nil {
			if lastRaw != "" {
				// Classify on ctx.Err(), NOT on the call site. An earlier revision of
				// this branch returned whoisIncompleteReferral unconditionally, so a
				// deadline that landed MID-hop was bucketed as a transport failure and
				// whoisIncompleteDeadline was reachable only in the window between hops
				// (the loop-top ctx.Err() check). That is the defect this fixes.
				//
				// ctx.Err() is the COMPLETE test for ctx-caused partiality, not a
				// partial one: it is monotone (once non-nil it never clears), it is read
				// here immediately after the failing call, and cancelCtx.cancel sets a
				// parent's err BEFORE it descends to the children. So an ancestor
				// deadline or cancel — the per-lookup wctx, the pass-wide budget bctx,
				// or the caller's own ctx — that fires mid-hop is already visible here,
				// whatever the hop error itself looks like.
				//
				// Never classify on the hop error's IDENTITY — not
				// context.DeadlineExceeded, not os.ErrDeadlineExceeded, not
				// net.Error.Timeout(). A clean-ctx stall bounded by the dialer's own
				// Timeout (queryTimeout, see whoisRaw) is a NONDETERMINISTIC MIXTURE of
				// the first two identities, so no identity match can separate "we ran
				// out of budget" from "the server never answered". Measured on
				// go1.26.2, reading ctx.Err() immediately after the failing call:
				//
				//   regime                                  Is(ctxDeadline)  Is(osDeadline)  ctx.Err()
				//   A dialer.Timeout fires, ctx clean       EITHER (race)    EITHER (race)   nil
				//   B ctx's own deadline fires              100%             0%              non-nil
				//   C ctx cancelled                         0% (Canceled)    0%              non-nil
				//   D conn.SetDeadline read stall, clean    0%               100%            nil
				//
				// Regime A's split is a scheduling race in net/fd_unix.go (~110-126):
				// the dialer's sub-context deadline is armed BOTH as an fd poll
				// write-deadline and as a context.AfterFunc, so when WaitWrite returns
				// poll.ErrDeadlineExceeded the select on ctx.Done() decides which
				// identity escapes — mapErr(ctx.Err()) => net.errTimeout, whose Is
				// reports context.DeadlineExceeded, when the context timer won the
				// race; the bare os.ErrDeadlineExceeded when it did not. Same server,
				// same timeout, either label, decided by goroutine scheduling.
				//
				// The RATIO is deliberately not recorded, because it is not a stable
				// property: two independent probes on this same toolchain, over the
				// same dialer timeouts of 60ms/250ms/1s, measured INVERTED majorities
				// (~16-30% vs ~99% context.DeadlineExceeded). Do not rely on either
				// identity being the common case, and do not write a test that asserts
				// one — it will be flaky. What both probes agreed on unanimously is all
				// the code needs: both identities occur, and ctx.Err() was nil in 100%
				// of regime-A samples.
				//
				// So the errors.Is(err, context.DeadlineExceeded) disjunct this
				// predicate used to carry was ACTIVELY WRONG, not merely redundant. No
				// rate is needed to condemn it: it fires AT ALL on a clean ctx, and
				// each time it does it labels an unresponsive referral server
				// deadline_expired and sends the operator to resize a budget on a path
				// (WhoisPlugin.Run) that has none. Matching os.ErrDeadlineExceeded or
				// net.Error.Timeout() would be worse still: that identity occurs in
				// regime A and ALWAYS in regime D, both with a clean ctx — so it would
				// mislabel every read stall, deterministically. Only ctx.Err() answers
				// the question actually being asked.
				//
				// The split has to hold because it drives OPPOSITE remedies: a
				// genuinely failed referral hop means pius is being throttled (pace
				// it), while an expired ctx means it is out of budget (resize it) —
				// and pacing an already-exhausted budget is actively harmful
				// (architecture-plan.md §D6, ENG-5405).
				//
				// Both arms stay `return`s on purpose: a `continue`/`break` or a
				// set-a-flag-and-fall-through would escape the maxWhoisReferrals bound
				// and the loop-top deadline bail.
				if ctx.Err() != nil {
					return lastRaw, whoisIncompleteDeadline, nil // last post-referral result
				}
				return lastRaw, whoisIncompleteReferral, nil // last post-referral result
			}
			return "", whoisComplete, fmt.Errorf("whois query to %s: %w", server, err)
		}
		// Only a post-referral record is salvageable: the bootstrap seed's
		// response describes the TLD registry, not the domain's registrant.
		if !strings.EqualFold(server, defaultServer) {
			lastRaw = raw
		}

		// Look for referral to a more specific server
		refer := extractReferral(raw)
		if refer == "" || strings.EqualFold(refer, server) {
			pendingRefer = "" // the chain ended naturally
			break
		}
		pendingRefer = refer
		server = refer
	}

	if lastRaw == "" {
		return "", whoisComplete, fmt.Errorf("whois query for %s: no record beyond bootstrap seed %s", domain, defaultServer)
	}
	if pendingRefer != "" {
		// The loop exited on maxWhoisReferrals with a referral still unfollowed,
		// so lastRaw is a mid-chain record, not the chain's endpoint (ENG-5405).
		return lastRaw, whoisIncompleteHops, nil
	}
	return lastRaw, whoisComplete, nil
}

// whoisHopBackoff is the base delay between hop attempts, a var so tests can
// shrink it — the same seam idiom as reverseWhoisTotalBudget.
var whoisHopBackoff = 250 * time.Millisecond

// whoisHopWithRaw queries one WHOIS server, retrying a failed attempt with
// exponential backoff. The retry stays inside the caller's deadline: ctx bounds
// the attempt and the backoff sleep alike, and an ended ctx returns its error
// immediately rather than funding another attempt. That matters because
// whoisQuery's caller may be inside the pass-wide reverse-whois budget, and a
// retry that outlived it would spend recall it cannot use.
func whoisHopWithRaw(ctx context.Context, domain, server string, rawFn func(context.Context, string, string) (string, error)) (string, error) {
	var err error
	for attempt := range whoisHopAttempts {
		if attempt > 0 {
			if serr := sleepBounded(ctx, whoisHopBackoff<<(attempt-1)); serr != nil {
				return "", serr
			}
		}
		var raw string
		raw, err = rawFn(ctx, domain, server)
		if err == nil {
			return raw, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return "", cerr
		}
	}
	return "", err
}

// sleepBounded waits d, returning the context error if ctx ends first.
func sleepBounded(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// whoisDialAddr normalizes a (possibly untrusted) referral server string into a
// host:port dial target: it strips any URL scheme / trailing slash, DROPS any
// explicit port the referral carries, and always dials the standard WHOIS port.
// WHOIS is tcp/43 by protocol, so a non-43 port in a referral is never
// legitimate — honoring it would let a hostile WHOIS record steer the plugin
// into probing arbitrary public host:port pairs (the SSRF guard blocks
// non-public IPs, not public-host:any-port). Strip-then-append also keeps a
// port-qualified referral like "whois.example.com:43" from being
// double-appended into a malformed "host:43:43" address (ENG-5123 review,
// Gemini + Codex).
func whoisDialAddr(server string) string {
	server = strings.TrimPrefix(server, "http://")
	server = strings.TrimPrefix(server, "https://")
	server = strings.TrimSuffix(server, "/")
	if host, _, err := net.SplitHostPort(server); err == nil {
		server = host // drop the untrusted explicit port — WHOIS is tcp/43 only
	} else {
		// A bracketed IPv6 literal WITHOUT a port (e.g. "[2001:db8::1]")
		// makes SplitHostPort fail; strip the brackets so JoinHostPort
		// re-wraps it once instead of producing a malformed
		// "[[2001:db8::1]]:43" that never dials (ENG-5123 review, Gemini).
		// A hostname or a bare (unbracketed) IPv6 carries no brackets, so
		// this is a no-op for them.
		server = strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
	}
	return net.JoinHostPort(server, whoisPort)
}

// whoisRawFn is indirected through a var so tests can drive whoisQuery's
// referral/salvage state machine without real network I/O. Production code
// leaves it as whoisRaw; only tests reassign it (restoring via defer).
var whoisRawFn = whoisRaw

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

	resp, err := readAllWithContext(ctx, conn, domain, server)
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
func readAllWithContext(ctx context.Context, conn net.Conn, domain, server string) ([]byte, error) {
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
			"server", server, "domain", domain,
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
