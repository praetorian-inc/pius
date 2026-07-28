package domains

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

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

	got, err := whoisQuery(context.Background(), "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no record beyond bootstrap seed")
	assert.Empty(t, got, "no salvageable record should be returned for a seed-only chain")
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

	got, err := whoisQuery(context.Background(), "example.com")

	require.NoError(t, err, "a failed registrar hop must not discard the salvaged TLD record")
	assert.Equal(t, tldRecord, got, "must return the post-referral TLD record")
	assert.NotEqual(t, seedRecord, got, "must NOT salvage the bootstrap seed record")
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

	got, err := whoisQuery(ctx, "example.com")

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, got, "nothing salvageable → no record on the cancelled path")
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

	got, err := whoisQuery(ctx, "example.com")

	require.NoError(t, err, "a cancellation after a referral advanced must salvage the post-referral record")
	assert.Equal(t, tldRecord, got, "must return the salvaged post-referral TLD record")
}
