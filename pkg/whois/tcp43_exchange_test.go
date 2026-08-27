package whois

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// tcp43Exchange tests -- exercise the exchange logic with real TCP connections
// to a mock server, verifying context deadline, cancellation, and happy-path
// behavior without needing the tcp43RawFn stub or the SSRF guard.
// ---------------------------------------------------------------------------

// TestTCP43Exchange_StallMidBody_ReturnsOnDeadline verifies that a context
// deadline unblocks a stalled TCP read well before the 10s dialTimeout.
func TestTCP43Exchange_StallMidBody_ReturnsOnDeadline(t *testing.T) {
	serverDone := make(chan struct{})
	defer close(serverDone)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("Registrant Organization: Example Inc"))
		<-serverDone // stall until test cleanup
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, exchangeErr := tcp43Exchange(ctx, conn, "example.com")
	elapsed := time.Since(start)

	require.Error(t, exchangeErr)
	assert.ErrorIs(t, exchangeErr, context.DeadlineExceeded)
	assert.Less(t, elapsed, 1*time.Second, "should return well before the 10s dialTimeout")
}

// TestTCP43Exchange_CancelDuringRead verifies that canceling a context
// (without a deadline) unblocks a stalled TCP read immediately via the
// background goroutine.
func TestTCP43Exchange_CancelDuringRead(t *testing.T) {
	serverDone := make(chan struct{})
	defer close(serverDone)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("Registrant Organization: Example Inc"))
		<-serverDone // stall until test cleanup
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, exchangeErr := tcp43Exchange(ctx, conn, "example.com")
	elapsed := time.Since(start)

	require.Error(t, exchangeErr)
	assert.ErrorIs(t, exchangeErr, context.Canceled)
	assert.Less(t, elapsed, 1*time.Second, "should return well before the 10s dialTimeout")
}

// TestTCP43Exchange_BoundedRead verifies that a well-behaved server response
// (under maxResponseBytes) is returned successfully.
func TestTCP43Exchange_BoundedRead(t *testing.T) {
	const whoisResponse = "Registrant Organization: Example Inc\r\nRegistrar: Test Registrar\r\n"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(whoisResponse))
		// Close after writing -- the client's ReadAll returns when the
		// connection is closed by the server.
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	result, exchangeErr := tcp43Exchange(context.Background(), conn, "example.com")

	require.NoError(t, exchangeErr)
	assert.Equal(t, whoisResponse, result)
}
