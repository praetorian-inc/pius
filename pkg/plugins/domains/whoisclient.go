package domains

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	whoisPort     = "43"
	defaultServer = "whois.iana.org"
	queryTimeout  = 10 * time.Second
)

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

	dialer := net.Dialer{Timeout: queryTimeout}
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
// per-read timer). A separate byte cap on the response is tracked as ENG-5167.
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

	resp, err := io.ReadAll(conn)
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
