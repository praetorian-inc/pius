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
func whoisQuery(ctx context.Context, domain string) (string, error) {
	server := defaultServer
	var lastRaw string

	for i := 0; i < 5; i++ { // max 5 referrals to prevent loops
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
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(queryTimeout))

	_, err = fmt.Fprintf(conn, "%s\r\n", domain)
	if err != nil {
		return "", err
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}

	return string(resp), nil
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
