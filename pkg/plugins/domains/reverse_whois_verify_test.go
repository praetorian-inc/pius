package domains

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		wantDrop  bool
	}{
		{
			name:      "corroborated exact",
			queryOrg:  "Leica Biosystems",
			res:       org("Leica Biosystems Inc."),
			wantScore: confReverseWhoisCorroborated,
			wantDrop:  false,
		},
		{
			name:      "corroborated partial (shorter fully contained)",
			queryOrg:  "Acme",
			res:       org("Acme Corp"),
			wantScore: confReverseWhoisCorroborated,
			wantDrop:  false,
		},
		{
			name:      "clear mismatch drops (walmart from Leica)",
			queryOrg:  "Leica Biosystems Richmond, Inc.",
			res:       org("Walmart Inc."),
			wantScore: 0,
			wantDrop:  true,
		},
		{
			name:      "masked registrant stays unverified",
			queryOrg:  "Leica Biosystems",
			res:       org("Domains By Proxy, LLC"),
			wantScore: confReverseWhoisUnverified,
			wantDrop:  false,
		},
		{
			name:      "empty registrant stays unverified",
			queryOrg:  "Leica Biosystems",
			res:       registrantResult{},
			wantScore: confReverseWhoisUnverified,
			wantDrop:  false,
		},
		{
			name:      "lookup error stays unverified (not mismatch)",
			queryOrg:  "Leica Biosystems",
			res:       registrantResult{},
			lookupErr: lookupErr,
			wantScore: confReverseWhoisUnverified,
			wantDrop:  false,
		},
		{
			name:      "ambiguous partial overlap stays unverified",
			queryOrg:  "Acme Global Services",
			res:       org("Acme Widgets Manufacturing Holdings"),
			wantScore: confReverseWhoisUnverified,
			wantDrop:  false,
		},
		{
			// 3 of 5 shared tokens = 0.60 == simCorroborate. Non-degenerate
			// (both sides >1 token, partial overlap) so it exercises the real
			// ratio, not a fully-contained shorter string.
			name:      "sim exactly at corroborate threshold corroborates",
			queryOrg:  "Acme Global Data Cloud Services",
			res:       org("Acme Global Data Widgets Holdings"),
			wantScore: confReverseWhoisCorroborated,
			wantDrop:  false,
		},
		{
			// 3 of 10 shared tokens = 0.30 == simMismatch. The drop test is
			// strictly-less-than, so the recall boundary must NOT drop here.
			name:      "sim exactly at mismatch threshold stays unverified (recall boundary)",
			queryOrg:  "alpha bravo charlie delta echo foxtrot golf hotel india juliet",
			res:       org("alpha bravo charlie kilo lima mike november oscar papa quebec"),
			wantScore: confReverseWhoisUnverified,
			wantDrop:  false,
		},
		{
			// 2 of 10 shared tokens = 0.20 < simMismatch → clear mismatch drops.
			name:      "sim just below mismatch threshold drops",
			queryOrg:  "alpha bravo charlie delta echo foxtrot golf hotel india juliet",
			res:       org("alpha bravo kilo lima mike november oscar papa quebec romeo"),
			wantScore: 0,
			wantDrop:  true,
		},
		{
			// queryOrg normalizes to "" (all legal-suffix tokens) → similarity is
			// undefined → unverifiable, never a mismatch-drop (ENG-5123 S1).
			name:      "query normalizes empty stays unverified (not drop)",
			queryOrg:  "Co., Ltd.",
			res:       org("Walmart Inc."),
			wantScore: confReverseWhoisUnverified,
			wantDrop:  false,
		},
		{
			// candidate registrant normalizes to "" → same guard, from the other
			// side (ENG-5123 S1).
			name:      "candidate registrant normalizes empty stays unverified (not drop)",
			queryOrg:  "Walmart",
			res:       org("Co., Ltd."),
			wantScore: confReverseWhoisUnverified,
			wantDrop:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, drop := decideConfidence(tt.queryOrg, tt.res, tt.lookupErr)
			assert.Equal(t, tt.wantDrop, drop, "drop")
			assert.InDelta(t, tt.wantScore, score, 0.001, "score")
			// Design invariant: no emitted (non-dropped) score ever reaches clean.
			if !drop {
				assert.Less(t, score, plugins.ConfidenceHigh,
					"reverse-whois must never auto-clean")
			}
		})
	}
}

func TestIsMaskedOrg(t *testing.T) {
	assert.True(t, isMaskedOrg("Domains By Proxy, LLC"))
	assert.True(t, isMaskedOrg("REDACTED FOR PRIVACY"))
	assert.True(t, isMaskedOrg("whois agent")) // present in whoisPrivacyNames
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

// TestVerifyCandidates_OrderPreservedAndDropped proves output order matches
// input order and dropped candidates are omitted.
func TestVerifyCandidates_OrderPreservedAndDropped(t *testing.T) {
	stub := &stubResolver{
		byDomain: map[string]registrantResult{
			"first.com":  org("Acme Corp"),    // corroborated
			"second.com": org("Walmart Inc."), // clear mismatch → drop
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
	require.Len(t, findings, 2)
	assert.Equal(t, "first.com", findings[0].Value)
	assert.Equal(t, "third.com", findings[1].Value)
	assert.InDelta(t, confReverseWhoisCorroborated, plugins.Confidence(findings[0]), 0.001)
	assert.InDelta(t, confReverseWhoisUnverified, plugins.Confidence(findings[1]), 0.001)
}

// TestVerifyCandidates_DropsImplausibleDomains proves malformed candidates
// (interior whitespace/control chars, over-length) are filtered out before any
// resolver call or emission (ENG-5123 F2).
func TestVerifyCandidates_DropsImplausibleDomains(t *testing.T) {
	stub := &stubResolver{byDomain: map[string]registrantResult{"good.com": org("Acme Corp")}}
	cands := []candidate{
		{domain: "good.com", finding: plugins.Finding{Value: "good.com"}},
		{domain: "bad domain.com", finding: plugins.Finding{Value: "bad domain.com"}},
		{domain: "inject\r\n.com", finding: plugins.Finding{Value: "inject\r\n.com"}},
	}
	findings, err := verifyCandidates(context.Background(), stub, "Acme", cands)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "good.com", findings[0].Value)
	assert.False(t, stub.queried("bad domain.com"), "malformed candidate must not be looked up")
	assert.False(t, stub.queried("inject\r\n.com"), "control-char candidate must not be looked up")
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
