package domains

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReverseWhoisPlugin_Accepts(t *testing.T) {
	// Setup: Set API key environment variable
	originalKey := os.Getenv("VIEWDNS_API_KEY")
	defer func() {
		if originalKey == "" {
			_ = os.Unsetenv("VIEWDNS_API_KEY")
		} else {
			_ = os.Setenv("VIEWDNS_API_KEY", originalKey)
		}
	}()

	p, ok := plugins.Get("reverse-whois")
	require.True(t, ok, "reverse-whois plugin should be registered")

	tests := []struct {
		name     string
		apiKey   string
		input    plugins.Input
		expected bool
	}{
		{
			name:   "accepts with API key and org name",
			apiKey: "test-key",
			input: plugins.Input{
				OrgName: "Acme Corp",
			},
			expected: true,
		},
		{
			name:   "rejects without API key",
			apiKey: "",
			input: plugins.Input{
				OrgName: "Acme Corp",
			},
			expected: false,
		},
		{
			name:     "rejects without org name",
			apiKey:   "test-key",
			input:    plugins.Input{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.apiKey == "" {
				_ = os.Unsetenv("VIEWDNS_API_KEY")
			} else {
				_ = os.Setenv("VIEWDNS_API_KEY", tt.apiKey)
			}

			result := p.Accepts(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReverseWhois_Run_OrgMode(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	// Mock returns the REAL ViewDNS API shape: response.matches[].domain
	// (not the broken query.domains[].domain_name shape the parser currently reads)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.RawQuery, "q=")
		_, _ = w.Write([]byte(`{"query":{"tool":"reversewhois","query":"Acme Corp"},"response":{"match_count":1,"matches":[{"domain":"acme.com","created_date":"2010-01-01","registrar":"Example Registrar, Inc."}]}}`))
	}))
	defer srv.Close()
	// Inject a stub resolver so verification stays hermetic (no live RDAP/WHOIS).
	// acme.com's own registrant corroborates "Acme Corp".
	stub := &stubResolver{byDomain: map[string]registrantResult{"acme.com": org("Acme Corp")}}
	p := &ReverseWhoisPlugin{client: client.New(), baseURL: srv.URL, resolver: stub}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "acme.com", findings[0].Value)
	assert.Equal(t, "Acme Corp", findings[0].Data["org"])
}

// TestReverseWhois_Run_UnverifiedMatchNeedsReview asserts the ENG-5123 bands
// against the walmart.com-from-a-Leica-query false positive. With
// verify-after-retrieve:
//   - acme.com's own registrant is unresolvable → unverified 0.50, needs_review
//     (kept: a lookup failure is never a drop).
//   - walmart.com's own registrant is "Walmart Inc.", unmasked and a clear
//     mismatch against the Leica query → DE-RANKED to 0.40 (bottom of the
//     needs_review band), NOT dropped: a textual mismatch is not proof of
//     non-ownership, so nothing is removed from the graph (ENG-5123 #1).
//
// Both findings stay strictly below ConfidenceHigh (never clean) and at/above
// ConfidenceLow (never dropped).
func TestReverseWhois_Run_UnverifiedMatchNeedsReview(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"match_count":2,"matches":[{"domain":"acme.com"},{"domain":"walmart.com"}]}}`))
	}))
	defer srv.Close()

	stub := &stubResolver{
		byDomain: map[string]registrantResult{
			"acme.com":    {},                  // unresolvable → unverified, kept
			"walmart.com": org("Walmart Inc."), // clear mismatch → de-ranked, kept
		},
	}
	p := &ReverseWhoisPlugin{client: client.New(), baseURL: srv.URL, resolver: stub}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Leica Biosystems Richmond, Inc."})
	require.NoError(t, err)

	require.Len(t, findings, 2, "clear-mismatch candidate must be de-ranked, never dropped")
	byDomain := map[string]plugins.Finding{}
	for _, f := range findings {
		conf, ok := f.Data["confidence"].(float64)
		require.True(t, ok, "confidence must be set for %q", f.Value)
		assert.GreaterOrEqual(t, conf, plugins.ConfidenceLow,
			"confidence for %q must be at or above the noise floor", f.Value)
		assert.Less(t, conf, plugins.ConfidenceHigh,
			"confidence for %q must be below ConfidenceHigh so it is not clean", f.Value)
		assert.True(t, plugins.NeedsReview(f),
			"match %q must be flagged needs_review", f.Value)
		byDomain[f.Value] = f
	}
	require.Contains(t, byDomain, "acme.com")
	require.Contains(t, byDomain, "walmart.com")
	assert.InDelta(t, 0.50, byDomain["acme.com"].Data["confidence"].(float64), 0.001,
		"unresolvable match must be scored at the 0.50 mid-band value")
	assert.InDelta(t, confReverseWhoisMismatch, byDomain["walmart.com"].Data["confidence"].(float64), 0.001,
		"clear mismatch must be de-ranked to the bottom of the band")
}

// TestReverseWhois_Run_CorroboratedRanksHigherStillNeedsReview asserts a
// candidate whose own registrant corroborates the query org is scored at the
// top of the needs_review band (0.60) — ranked above unverified matches but
// still NOT clean.
func TestReverseWhois_Run_CorroboratedRanksHigherStillNeedsReview(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"matches":[{"domain":"acme.com"}]}}`))
	}))
	defer srv.Close()

	stub := &stubResolver{byDomain: map[string]registrantResult{"acme.com": org("Acme Corp")}}
	p := &ReverseWhoisPlugin{client: client.New(), baseURL: srv.URL, resolver: stub}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	f := findings[0]
	assert.InDelta(t, 0.60, plugins.Confidence(f), 0.001,
		"corroborated match must rank at the 0.60 top-of-band value")
	assert.Less(t, plugins.Confidence(f), plugins.ConfidenceHigh,
		"corroborated match must still be below ConfidenceHigh (never auto-clean)")
	assert.True(t, plugins.NeedsReview(f), "corroborated match must still be needs_review")
}

func TestReverseWhois_Accepts_WithKeyAndEmail(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	p := &ReverseWhoisPlugin{client: client.New()}
	assert.True(t, p.Accepts(plugins.Input{Email: "admin@acme.com"}))
	assert.False(t, p.Accepts(plugins.Input{})) // neither org nor email
}

func TestReverseWhois_Run_EmailMode(t *testing.T) {
	t.Setenv("VIEWDNS_API_KEY", "test-key")
	// Mock returns the REAL ViewDNS API shape: response.matches[].domain
	// (not the broken query.domains[].domain_name shape the parser currently reads)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.RawQuery, "q=admin%40acme.com") // email url-escaped into q=
		_, _ = w.Write([]byte(`{"query":{"tool":"reversewhois","query":"admin@acme.com"},"response":{"match_count":1,"matches":[{"domain":"acme.com","created_date":"2010-01-01","registrar":"Example Registrar, Inc."}]}}`))
	}))
	defer srv.Close()
	p := &ReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{Email: "admin@acme.com"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "acme.com", findings[0].Value)
	assert.Equal(t, "admin@acme.com", findings[0].Data["org"]) // provenance: Data["org"] holds active seed
}

// TestReverseWhois_Run_EmailMode_ErrorOmitsRawEmail is the TDD RED test proving that
// ViewDNS Run() currently leaks the registrant email in error strings (PII leak).
//
// The parse-error branch (line 74 of reverse_whois.go) formats:
//
//	fmt.Errorf("reverse-whois: parse response for %q: %w", query, err)
//
// When query == input.Email, the raw email appears in the error. The runner logs
// Phase-0 plugin errors, so this email reaches the logs.
//
// RED: this test FAILS against current production code because the email IS present.
// GREEN: fix reverse_whois.go to omit the raw email from error strings.
func TestReverseWhois_Run_EmailMode_ErrorOmitsRawEmail(t *testing.T) {
	const sensitiveEmail = "admin@secret-corp.com"

	t.Setenv("VIEWDNS_API_KEY", "test-key")

	// Server returns HTTP 200 with an invalid JSON body so json.Unmarshal fails,
	// triggering the parse-error branch at line 74 of reverse_whois.go.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := &ReverseWhoisPlugin{client: client.New(), baseURL: srv.URL}

	_, err := p.Run(context.Background(), plugins.Input{Email: sensitiveEmail})

	// The parse must have failed.
	require.Error(t, err, "Run must return an error when the response body is not valid JSON")

	// PII assertion: the raw email must NOT appear in the error string.
	// This assertion FAILS today because line 74 embeds %q query (== sensitiveEmail).
	assert.False(t,
		strings.Contains(err.Error(), sensitiveEmail),
		"error string must not contain the raw registrant email (PII leak): got %q",
		err.Error(),
	)
}
