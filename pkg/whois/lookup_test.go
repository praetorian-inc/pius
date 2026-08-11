package whois

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENG-5456: slog value-position escaping is the only thing standing between a
// control-character-bearing domain (RootDomain is a shape normalizer, not a
// sanitizer — see normalize.go) and a forged operator log line. JSON escapes
// control characters structurally, so a newline can never break out of a JSON
// string value; the interesting format is the text handler, where a raw
// newline in an attribute value could in principle inject a bogus
// "level=ERROR msg=forged" record into the log stream. This file exercises
// both handlers so the JSON case documents the (structurally safe) baseline
// and the text case is the one that actually tests the claim.

// captureSlog swaps the global slog default for a handler writing into a
// buffer and returns that buffer. It restores the original default via
// t.Cleanup.
//
// NOT safe for use with t.Parallel(): it mutates the process-global slog
// default, so parallel tests using this helper would race on it. This is a
// known property of the helper, not an oversight.
//
// The Debug level is explicitly enabled via HandlerOptions — slog's default
// level is Info, so without this option every slog.Debug call in lookup.go
// would be silently discarded and every assertion below would pass
// vacuously against an empty buffer.
func captureSlog(t *testing.T, format string) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(&buf, opts)
	case "text":
		handler = slog.NewTextHandler(&buf, opts)
	default:
		t.Fatalf("captureSlog: unknown format %q", format)
	}

	orig := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(orig) })

	return &buf
}

// alwaysFailRoundTripper is an http.RoundTripper that always fails without
// making any real network call. Used to drive Lookup's RDAP path to its
// error-logging branch hermetically. The error is a plain sentinel wrapped in
// a generic error — not an *rdap.ClientError and not
// whoisparser.ErrNotFoundDomain — so it does not satisfy isDomainNotFound,
// and Lookup falls through to the slog.Debug call at line 51 instead of
// early-returning as an "unregistered domain" result.
type alwaysFailRoundTripper struct{}

func (alwaysFailRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("simulated transport failure: connection refused")
}

// stubTCP43AlwaysFails overrides the tcp43RawFn test seam so tcp43Lookup
// fails hermetically (no real network I/O), driving Lookup's TCP-43 path to
// its error-logging branch at line 59. Restored via t.Cleanup.
func stubTCP43AlwaysFails(t *testing.T) {
	t.Helper()

	orig := tcp43RawFn
	tcp43RawFn = func(_ context.Context, _ string, _ string) (string, error) {
		return "", errors.New("simulated tcp43 dial failure")
	}
	t.Cleanup(func() { tcp43RawFn = orig })
}

// logInjectionPayload places a newline inside the second-to-last label so it
// survives RootDomain's eTLD+1 reduction. A payload placed ahead of the last
// two labels would be silently stripped by RootDomain, and the test would
// prove nothing about escaping.
const logInjectionPayload = "a.exa\nlevel=ERROR msg=forged\nmple.com"

// stripQuotedSpans removes the content of double-quoted spans from a log
// line (honoring backslash escapes), leaving only the bare, unquoted
// structure of the line. Both the JSON and text handlers double-quote string
// values and backslash-escape control characters and embedded quotes within
// them, so anything legitimately escaped into a value — including our
// forged-looking payload text — disappears here. What's left is exactly the
// handler's own record framing (keys, "=" / ":" separators, "level=DEBUG",
// etc.). Checking for injected tokens against this remainder, rather than
// the raw line, distinguishes "the payload text happens to contain the
// string msg=forged" (expected, safe) from "the handler emitted msg=forged
// as a bare, unquoted attribute" (the actual defect this test would need to
// catch).
func stripQuotedSpans(s string) string {
	var b strings.Builder
	inQuotes, escaped := false, false
	for _, r := range s {
		if inQuotes {
			switch {
			case escaped:
				escaped = false
			case r == '\\':
				escaped = true
			case r == '"':
				inQuotes = false
			}
			continue
		}
		if r == '"' {
			inQuotes = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func TestLookup_LogInjectionEscaping(t *testing.T) {
	// MANDATORY PRECONDITION: verify RootDomain actually retains the
	// newline for this payload before making any claim about escaping. If
	// RootDomain stripped or rewrote the payload, every assertion below
	// would pass vacuously — this must fail loudly instead.
	rootDomain := RootDomain(logInjectionPayload)
	require.Contains(t, rootDomain, "\n",
		"precondition failed: RootDomain(%q) = %q does not retain the injected newline; "+
			"escaping assertions below would be vacuous", logInjectionPayload, rootDomain)

	tests := []struct {
		name   string
		format string
	}{
		{"json handler", "json"},
		{"text handler", "text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Not t.Parallel(): captureSlog swaps the global slog default.
			buf := captureSlog(t, tt.format)
			stubTCP43AlwaysFails(t)

			httpClient := &http.Client{Transport: alwaysFailRoundTripper{}}

			// Both RDAP and TCP-43 fail, so Lookup returns an error from
			// line 63. That is expected and fine — we're asserting on the
			// captured log output, not the return value.
			_, err := Lookup(context.Background(), logInjectionPayload, WithHTTPClient(httpClient))
			require.Error(t, err)

			output := buf.String()
			require.NotEmpty(t, output,
				"no log output captured: check that the handler's Level option enables Debug")

			// Proves the log fired at all (both RDAP-failure and
			// TCP43-failure records carry a "domain" attribute) AND that
			// the normalized domain value itself arrived intact with its
			// embedded newline escaped to the two-character sequence
			// `\n`, rather than being dropped, truncated, or replaced.
			// This subsumes the old key-only "domain" substring check:
			// if this assertion holds, the weaker one necessarily does
			// too.
			escapedDomain := strings.ReplaceAll(rootDomain, "\n", `\n`)
			assert.Contains(t, output, escapedDomain,
				"handler did not emit the normalized domain with escaped newlines")

			// The payload's newline must be ESCAPED, not literal: the raw
			// captured bytes must not contain a real newline that starts a
			// parseable forged record. Split on the actual newline byte,
			// strip anything the handler legitimately quoted/escaped into a
			// value, and verify no resulting line's bare (unquoted)
			// structure looks like an injected log record.
			for _, line := range strings.Split(output, "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				bare := stripQuotedSpans(trimmed)
				assert.False(t, strings.HasPrefix(trimmed, "level=ERROR"),
					"line parses as a forged text-handler record: %q", trimmed)
				assert.NotContains(t, bare, "level=ERROR",
					"line has an ERROR-level record outside any escaped value: %q", trimmed)
				assert.NotContains(t, bare, "msg=forged",
					"line has a forged msg attribute outside any escaped value: %q", trimmed)
			}
		})
	}
}
