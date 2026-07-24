package domains

import (
	"context"
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
		"0.0.0.0:43",         // unspecified
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
	_, err := readAllWithContext(ctx, client)
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
	_, err := readAllWithContext(ctx, client)
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

	resp, err := readAllWithContext(ctx, client)
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

	resp, err := readAllWithContext(ctx, client)
	require.NoError(t, err)
	assert.Equal(t, "Registrant: Acme Corp\n", string(resp))
}
