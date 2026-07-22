package domains

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	defer server.Close() // server never writes → read would block forever

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
	defer server.Close()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	start := time.Now()
	_, err := readAllWithContext(ctx, client)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 2*time.Second, "past deadline must end the read promptly")
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
