package domains

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingResolver blocks each lookup until its context is cancelled, then
// surfaces the context error. It models a slow/unresponsive registrant source so
// tests can prove the overall verification budget (not just the per-lookup
// timeout) caps the pass.
type blockingResolver struct{}

func (blockingResolver) resolveRegistrant(ctx context.Context, _ string) (registrantResult, error) {
	<-ctx.Done()
	return registrantResult{}, ctx.Err()
}

// stubResolver is a hermetic registrantResolver: it returns canned results per
// domain with no network access, and records which domains were queried so
// tests can assert (e.g.) that filtered candidates never trigger a lookup.
type stubResolver struct {
	byDomain map[string]registrantResult
	errBy    map[string]error

	mu    sync.Mutex
	calls []string
}

func (s *stubResolver) resolveRegistrant(_ context.Context, domain string) (registrantResult, error) {
	s.mu.Lock()
	s.calls = append(s.calls, domain)
	s.mu.Unlock()
	if err, ok := s.errBy[domain]; ok {
		return registrantResult{}, err
	}
	if r, ok := s.byDomain[domain]; ok {
		return r, nil
	}
	// Unknown domain: no registrant resolved → unverified (never dropped).
	return registrantResult{}, nil
}

func (s *stubResolver) queried(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.calls {
		if d == domain {
			return true
		}
	}
	return false
}

func org(v string) registrantResult { return newRegistrantResult(v) }

func TestNormalizeOrg(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"strips inc suffix + punctuation", "Walmart Inc.", "walmart"},
		{"strips llc", "Acme, LLC", "acme"},
		{"strips corp", "Acme Corp", "acme"},
		{"strips gmbh", "Siemens GmbH", "siemens"},
		{"preserves group disambiguator", "Danaher Group", "danaher group"},
		{"preserves holdings disambiguator", "Leica Holdings Ltd", "leica holdings"},
		{"preserves international", "Acme International Inc", "acme international"},
		{"preserves systems", "Acme Systems", "acme systems"},
		{"lowercases and collapses", "  LEICA   Biosystems ", "leica biosystems"},
		{"all-suffix org normalizes to empty", "Co., Ltd.", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeOrg(tt.in))
		})
	}
}

func TestDecideConfidence(t *testing.T) {
	lookupErr := errors.New("boom")
	tests := []struct {
		name      string
		queryOrg  string
		res       registrantResult
		lookupErr error
		wantScore float64
	}{
		{
			name:      "corroborated exact",
			queryOrg:  "Leica Biosystems",
			res:       org("Leica Biosystems Inc."),
			wantScore: confReverseWhoisCorroborated,
		},
		{
			name:      "corroborated partial (shorter fully contained)",
			queryOrg:  "Acme",
			res:       org("Acme Corp"),
			wantScore: confReverseWhoisCorroborated,
		},
		{
			// De-ranked to the bottom of the band, NOT dropped: a textual
			// registrant mismatch is not proof of non-ownership (ENG-5123 #1).
			name:      "clear mismatch de-ranks (walmart from Leica)",
			queryOrg:  "Leica Biosystems Richmond, Inc.",
			res:       org("Walmart Inc."),
			wantScore: confReverseWhoisMismatch,
		},
		{
			name:      "masked registrant stays unverified",
			queryOrg:  "Leica Biosystems",
			res:       org("Domains By Proxy, LLC"),
			wantScore: confReverseWhoisUnverified,
		},
		{
			name:      "empty registrant stays unverified",
			queryOrg:  "Leica Biosystems",
			res:       registrantResult{},
			wantScore: confReverseWhoisUnverified,
		},
		{
			name:      "lookup error stays unverified (not mismatch)",
			queryOrg:  "Leica Biosystems",
			res:       registrantResult{},
			lookupErr: lookupErr,
			wantScore: confReverseWhoisUnverified,
		},
		{
			name:      "ambiguous partial overlap stays unverified",
			queryOrg:  "Acme Global Services",
			res:       org("Acme Widgets Manufacturing Holdings"),
			wantScore: confReverseWhoisUnverified,
		},
		{
			// 3 of 5 shared tokens = 0.60 == simCorroborate. Non-degenerate
			// (both sides >1 token, partial overlap) so it exercises the real
			// ratio, not a fully-contained shorter string.
			name:      "sim exactly at corroborate threshold corroborates",
			queryOrg:  "Acme Global Data Cloud Services",
			res:       org("Acme Global Data Widgets Holdings"),
			wantScore: confReverseWhoisCorroborated,
		},
		{
			// 3 of 10 shared tokens = 0.30 == simMismatch. The mismatch test is
			// strictly-less-than, so the boundary stays unverified (not de-ranked).
			name:      "sim exactly at mismatch threshold stays unverified (boundary)",
			queryOrg:  "alpha bravo charlie delta echo foxtrot golf hotel india juliet",
			res:       org("alpha bravo charlie kilo lima mike november oscar papa quebec"),
			wantScore: confReverseWhoisUnverified,
		},
		{
			// 2 of 10 shared tokens = 0.20 < simMismatch → clear mismatch de-ranks.
			name:      "sim just below mismatch threshold de-ranks",
			queryOrg:  "alpha bravo charlie delta echo foxtrot golf hotel india juliet",
			res:       org("alpha bravo kilo lima mike november oscar papa quebec romeo"),
			wantScore: confReverseWhoisMismatch,
		},
		{
			// queryOrg normalizes to "" (all legal-suffix tokens) → similarity is
			// undefined → unverifiable, never a mismatch (ENG-5123 S1).
			name:      "query normalizes empty stays unverified",
			queryOrg:  "Co., Ltd.",
			res:       org("Walmart Inc."),
			wantScore: confReverseWhoisUnverified,
		},
		{
			// candidate registrant normalizes to "" → same guard, from the other
			// side (ENG-5123 S1).
			name:      "candidate registrant normalizes empty stays unverified",
			queryOrg:  "Walmart",
			res:       org("Co., Ltd."),
			wantScore: confReverseWhoisUnverified,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := decideConfidence(tt.queryOrg, tt.res, tt.lookupErr)
			assert.InDelta(t, tt.wantScore, score, 0.001, "score")
			// Design invariant: every score stays in needs_review — below clean
			// (never auto-clean) and at/above the noise floor (never dropped).
			assert.Less(t, score, plugins.ConfidenceHigh,
				"reverse-whois must never auto-clean")
			assert.GreaterOrEqual(t, score, plugins.ConfidenceLow,
				"reverse-whois must never drop below needs_review")
		})
	}
}

func TestIsMaskedOrg(t *testing.T) {
	assert.True(t, isMaskedOrg("Domains By Proxy, LLC"))
	assert.True(t, isMaskedOrg("REDACTED FOR PRIVACY"))
	assert.True(t, isMaskedOrg("whois agent")) // present in whoisPrivacyNames
	// Proxy orgs append a per-customer suffix that defeats an exact lookup; the
	// substring pass must still catch it (ENG-5123 #2).
	assert.True(t, isMaskedOrg("Domains By Proxy, LLC (customer 12345)"))
	assert.True(t, isMaskedOrg("Registration Private, Domains By Proxy"))
	assert.False(t, isMaskedOrg("Leica Biosystems"))
	assert.False(t, isMaskedOrg(""))
}

// TestVerifyCandidates_EmailModeShortCircuits proves an empty queryOrg emits
// every candidate at the unverified mid-band with NO resolver calls.
func TestVerifyCandidates_EmailModeShortCircuits(t *testing.T) {
	stub := &stubResolver{}
	cands := []candidate{
		{domain: "a.com", finding: plugins.Finding{Type: plugins.FindingDomain, Value: "a.com"}},
		{domain: "b.com", finding: plugins.Finding{Type: plugins.FindingDomain, Value: "b.com"}},
	}
	findings, err := verifyCandidates(context.Background(), stub, "", cands)
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Empty(t, stub.calls, "email-mode must not call the resolver")
	for _, f := range findings {
		assert.InDelta(t, confReverseWhoisUnverified, plugins.Confidence(f), 0.001)
		assert.True(t, plugins.NeedsReview(f))
	}
}

// TestVerifyCandidates_OrderPreservedAllEmitted proves output order matches
// input order and that a clear mismatch is DE-RANKED (bottom of band), never
// dropped — nothing is ever removed from the graph (ENG-5123 #1).
func TestVerifyCandidates_OrderPreservedAllEmitted(t *testing.T) {
	stub := &stubResolver{
		byDomain: map[string]registrantResult{
			"first.com":  org("Acme Corp"),    // corroborated
			"second.com": org("Walmart Inc."), // clear mismatch → de-rank, keep
			"third.com":  {},                  // unverified
		},
	}
	cands := []candidate{
		{domain: "first.com", finding: plugins.Finding{Value: "first.com"}},
		{domain: "second.com", finding: plugins.Finding{Value: "second.com"}},
		{domain: "third.com", finding: plugins.Finding{Value: "third.com"}},
	}
	findings, err := verifyCandidates(context.Background(), stub, "Acme", cands)
	require.NoError(t, err)
	require.Len(t, findings, 3)
	assert.Equal(t, "first.com", findings[0].Value)
	assert.Equal(t, "second.com", findings[1].Value)
	assert.Equal(t, "third.com", findings[2].Value)
	assert.InDelta(t, confReverseWhoisCorroborated, plugins.Confidence(findings[0]), 0.001)
	assert.InDelta(t, confReverseWhoisMismatch, plugins.Confidence(findings[1]), 0.001)
	assert.InDelta(t, confReverseWhoisUnverified, plugins.Confidence(findings[2]), 0.001)
	// De-ranked mismatch is still in the needs_review band, not discarded.
	assert.True(t, plugins.NeedsReview(findings[1]))
}

// TestVerifyCandidates_DropsImplausibleDomains proves malformed candidates
// (interior whitespace/control chars, over-length, URL/authority punctuation, or
// dot-less single labels) are filtered out before any resolver call or emission
// (ENG-5123 F2 + Codex-suggestion hardening). Because reverse-whois never drops,
// this filter is the only thing keeping such values out of the graph.
func TestVerifyCandidates_DropsImplausibleDomains(t *testing.T) {
	overLen := strings.Repeat("a", 250) + ".com" // 254 chars > 253 max
	stub := &stubResolver{byDomain: map[string]registrantResult{"good.com": org("Acme Corp")}}
	cands := []candidate{
		{domain: "good.com", finding: plugins.Finding{Value: "good.com"}},
		{domain: "bad domain.com", finding: plugins.Finding{Value: "bad domain.com"}},
		{domain: "inject\r\n.com", finding: plugins.Finding{Value: "inject\r\n.com"}},
		{domain: overLen, finding: plugins.Finding{Value: overLen}},
		{domain: "example.com:443", finding: plugins.Finding{Value: "example.com:443"}},
		{domain: "http://example.com/path", finding: plugins.Finding{Value: "http://example.com/path"}},
		{domain: "admin@example.com", finding: plugins.Finding{Value: "admin@example.com"}},
		{domain: "localhost", finding: plugins.Finding{Value: "localhost"}},
	}
	findings, err := verifyCandidates(context.Background(), stub, "Acme", cands)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "good.com", findings[0].Value)
	assert.False(t, stub.queried("bad domain.com"), "malformed candidate must not be looked up")
	assert.False(t, stub.queried("inject\r\n.com"), "control-char candidate must not be looked up")
	assert.False(t, stub.queried(overLen), "over-length candidate must not be looked up")
	assert.False(t, stub.queried("example.com:443"), "port-bearing candidate must not be looked up")
	assert.False(t, stub.queried("http://example.com/path"), "URL candidate must not be looked up")
	assert.False(t, stub.queried("admin@example.com"), "userinfo-bearing candidate must not be looked up")
	assert.False(t, stub.queried("localhost"), "dot-less single label must not be looked up")
}

// TestVerifyCandidates_TotalBudgetCapsRuntime proves the overall verification
// budget bounds the pass even when every lookup hangs. With a slow/serialized
// registrant source, per-lookup 10s budgets would otherwise stack; the total
// budget caps runtime and scores every unresolved candidate unverified —
// emitted, needs_review, never dropped (ENG-5123 review, Codex critical).
func TestVerifyCandidates_TotalBudgetCapsRuntime(t *testing.T) {
	orig := reverseWhoisTotalBudget
	reverseWhoisTotalBudget = 100 * time.Millisecond
	defer func() { reverseWhoisTotalBudget = orig }()

	cands := make([]candidate, 0, 20)
	for _, d := range []string{
		"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com",
		"h.com", "i.com", "j.com", "k.com", "l.com", "m.com", "n.com",
	} {
		cands = append(cands, candidate{domain: d, finding: plugins.Finding{Value: d}})
	}

	start := time.Now()
	findings, err := verifyCandidates(context.Background(), blockingResolver{}, "Acme Corp", cands)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Len(t, findings, len(cands), "every candidate must still be emitted (never dropped)")
	// The pass must be bounded by the total budget, NOT by a single per-lookup
	// timeout — proving the stacking-budget failure mode is capped.
	assert.Less(t, elapsed, reverseWhoisLookupTimeout,
		"total budget must cap the pass well under one per-lookup timeout")
	for _, f := range findings {
		assert.InDelta(t, confReverseWhoisUnverified, plugins.Confidence(f), 0.001,
			"budget-expired lookup must score unverified")
		assert.True(t, plugins.NeedsReview(f))
	}
}

// TestReverseWhois_NeverAutoCleans is the design-guard invariant: across a mix
// of corroborated / unverified / masked / mismatch results, NO reverse-whois
// finding is ever emitted at or above plugins.ConfidenceHigh. A future
// regression to an auto-clean path fails here.
func TestReverseWhois_NeverAutoCleans(t *testing.T) {
	stub := &stubResolver{
		byDomain: map[string]registrantResult{
			"corroborated.com": org("Acme Corp"),             // strongest signal
			"unverified.com":   {},                           // empty
			"masked.com":       org("Domains By Proxy, LLC"), // masked
		},
		errBy: map[string]error{
			"timeout.com": errors.New("deadline exceeded"),
		},
	}

	viewdns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"matches":[{"domain":"corroborated.com"},{"domain":"unverified.com"},{"domain":"masked.com"},{"domain":"timeout.com"}]}}`))
	}))
	defer viewdns.Close()

	t.Setenv("VIEWDNS_API_KEY", "test-key")
	p := &ReverseWhoisPlugin{client: client.New(), baseURL: viewdns.URL, resolver: stub}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Less(t, plugins.Confidence(f), plugins.ConfidenceHigh,
			"reverse-whois finding %q must never be emitted as clean", f.Value)
		assert.True(t, plugins.NeedsReview(f),
			"reverse-whois finding %q must be flagged needs_review", f.Value)
	}
}
