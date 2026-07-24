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

	"github.com/openrdap/rdap"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vcardProp builds a single-string jCard property for test fixtures.
func vcardProp(name, value string) *rdap.VCardProperty {
	return &rdap.VCardProperty{Name: name, Type: "text", Value: value}
}

// registrantEntity builds an Entity with the "registrant" role and a vCard
// carrying the given org/fn (empty string = property omitted).
func registrantEntity(org, fn string) rdap.Entity {
	var props []*rdap.VCardProperty
	props = append(props, vcardProp("version", "4.0"))
	if org != "" {
		props = append(props, vcardProp("org", org))
	}
	if fn != "" {
		props = append(props, vcardProp("fn", fn))
	}
	return rdap.Entity{Roles: []string{"registrant"}, VCard: &rdap.VCard{Properties: props}}
}

// TestRegistrantOrgFromDomain covers the jCard extraction the RDAP primary path
// relies on: org preferred over fn, fn fallback, no-registrant, masked-registrar,
// and the nil-vCard / role-mismatch guards (ENG-5123 review, Claude — the
// jCard parser had no direct unit coverage).
func TestRegistrantOrgFromDomain(t *testing.T) {
	tests := []struct {
		name string
		dom  *rdap.Domain
		want string
	}{
		{
			name: "org preferred over fn",
			dom:  &rdap.Domain{Entities: []rdap.Entity{registrantEntity("Acme Corporation", "John Doe")}},
			want: "Acme Corporation",
		},
		{
			name: "fn fallback when org absent",
			dom:  &rdap.Domain{Entities: []rdap.Entity{registrantEntity("", "John Doe")}},
			want: "John Doe",
		},
		{
			name: "masked registrar org is returned verbatim (classified downstream)",
			dom:  &rdap.Domain{Entities: []rdap.Entity{registrantEntity("REDACTED FOR PRIVACY", "")}},
			want: "REDACTED FOR PRIVACY",
		},
		{
			name: "no registrant entity",
			dom: &rdap.Domain{Entities: []rdap.Entity{
				{Roles: []string{"administrative"}, VCard: &rdap.VCard{Properties: []*rdap.VCardProperty{vcardProp("org", "Admin LLC")}}},
			}},
			want: "",
		},
		{
			name: "registrant with nil vCard",
			dom:  &rdap.Domain{Entities: []rdap.Entity{{Roles: []string{"registrant"}, VCard: nil}}},
			want: "",
		},
		{
			name: "no entities at all",
			dom:  &rdap.Domain{},
			want: "",
		},
		{
			name: "org value whitespace-trimmed",
			dom:  &rdap.Domain{Entities: []rdap.Entity{registrantEntity("  Globex GmbH  ", "")}},
			want: "Globex GmbH",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, registrantOrgFromDomain(tt.dom))
		})
	}
}

// blockingResolver blocks each lookup until its context is cancelled, then
// surfaces the context error. It models a slow/unresponsive registrant source so
// tests can prove the overall verification budget (not just the per-lookup
// timeout) caps the pass.
type blockingResolver struct{}

func (blockingResolver) resolveRegistrant(ctx context.Context, _ string) (registrantResult, error) {
	<-ctx.Done()
	return registrantResult{}, ctx.Err()
}

// panickingResolver panics on a designated domain and resolves the rest cleanly.
// It models the real hazard the worker-level recover() guards: whoisparser.Parse
// panicking on a malformed third-party WHOIS record. It lets a test prove that a
// single poisoned candidate keeps its pre-filled unverified score instead of
// crashing the whole pass (ENG-5123 review, Gemini).
type panickingResolver struct {
	panicOn map[string]bool
	byOK    map[string]registrantResult
}

func (p *panickingResolver) resolveRegistrant(_ context.Context, domain string) (registrantResult, error) {
	if p.panicOn[domain] {
		panic("simulated whoisparser panic on malformed record for " + domain)
	}
	if r, ok := p.byOK[domain]; ok {
		return r, nil
	}
	return registrantResult{}, nil
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

// TestVerifyCandidates_ResolverPanicScoresUnverified proves a resolver panic on
// one candidate (e.g. whoisparser.Parse blowing up on a malformed WHOIS record)
// is recovered at the worker level: the pass does NOT crash, every candidate is
// still emitted, and the poisoned candidate keeps the pre-filled unverified
// mid-band score instead of falling to the 0.0 discard floor — de-rank, never
// drop, even under panic (ENG-5123 review, Gemini).
func TestVerifyCandidates_ResolverPanicScoresUnverified(t *testing.T) {
	res := &panickingResolver{
		panicOn: map[string]bool{"boom.com": true},
		byOK:    map[string]registrantResult{"first.com": org("Acme Corp")},
	}
	cands := []candidate{
		{domain: "first.com", finding: plugins.Finding{Value: "first.com"}},
		{domain: "boom.com", finding: plugins.Finding{Value: "boom.com"}},
		{domain: "third.com", finding: plugins.Finding{Value: "third.com"}},
	}
	findings, err := verifyCandidates(context.Background(), res, "Acme", cands)
	require.NoError(t, err)
	require.Len(t, findings, 3, "a panic on one candidate must not drop any finding")
	assert.Equal(t, "boom.com", findings[1].Value)
	// The panicked candidate keeps the pre-filled unverified score, staying inside
	// the needs_review band rather than the 0.0 discard floor.
	assert.InDelta(t, confReverseWhoisUnverified, plugins.Confidence(findings[1]), 0.001)
	assert.True(t, plugins.NeedsReview(findings[1]))
	// A clean sibling still scores corroborated — the recover() is scoped per
	// worker and does not poison the rest of the pass.
	assert.InDelta(t, confReverseWhoisCorroborated, plugins.Confidence(findings[0]), 0.001)
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

// TestVerifyCandidates_PropagatesCallerCancellation proves the two context
// regimes are distinguished: an INTERNAL budget expiry is recall-safe (every
// candidate still emitted, see TestVerifyCandidates_TotalBudgetCapsRuntime),
// but a cancelled CALLER context — user interrupt / runner deadline — aborts
// the pass with ctx.Err() instead of returning a full set of half-verified
// findings as though the run completed (ENG-5123 review, Codex critical).
func TestVerifyCandidates_PropagatesCallerCancellation(t *testing.T) {
	// Keep the internal budget long so it cannot be what fires — the ONLY thing
	// that ends this pass is the parent cancellation below.
	orig := reverseWhoisTotalBudget
	reverseWhoisTotalBudget = 30 * time.Second
	defer func() { reverseWhoisTotalBudget = orig }()

	cands := make([]candidate, 0, 8)
	for _, d := range []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com", "h.com"} {
		cands = append(cands, candidate{domain: d, finding: plugins.Finding{Value: d}})
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel() // caller aborts mid-pass
	}()

	start := time.Now()
	findings, err := verifyCandidates(ctx, blockingResolver{}, "Acme Corp", cands)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, findings, "an aborted pass must not emit a partial finding set")
	assert.Less(t, elapsed, reverseWhoisTotalBudget,
		"caller cancellation must abort well before the internal budget")
}

// TestVerifyCandidates_EmailModeHonorsPreCancellation proves the entry-level
// ctx check aborts even paths that do no lookups of their own. Email-mode
// (empty queryOrg) short-circuits to the unverified band before the parallel
// resolver runs, so it never reaches the post-g.Wait cancellation check; a
// caller that already cancelled (e.g. right after the upstream API fetch) must
// still get ctx.Err() and no findings, not a full "completed" slice (ENG-5123
// review, Codex P2).
func TestVerifyCandidates_EmailModeHonorsPreCancellation(t *testing.T) {
	cands := make([]candidate, 0, 4)
	for _, d := range []string{"a.com", "b.com", "c.com", "d.com"} {
		cands = append(cands, candidate{domain: d, finding: plugins.Finding{Value: d}})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // caller already aborted before the pass starts

	// Empty queryOrg selects the email-mode fast path (no resolver calls).
	findings, err := verifyCandidates(ctx, blockingResolver{}, "", cands)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, findings, "a pre-cancelled email-mode pass must not emit findings")
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

// TestResolveWithFallback pins the RDAP-primary / WHOIS-fallback policy that the
// review round found broken: RDAP is authoritative ONLY when it actually
// resolved a registrant. A redacted-but-successful RDAP response (Found==false,
// nil error — the GDPR norm for gTLDs), an RDAP transport error, and a busy
// serialization slot must ALL fall through to WHOIS; only a genuine RDAP hit
// short-circuits it (Codex+Claude+Gemini review, ENG-5123).
func TestResolveWithFallback(t *testing.T) {
	const domain = "example.com"
	rdapHit := registrantResult{Org: "RDAP Org", Found: true}
	whoisHit := registrantResult{Org: "WHOIS Org", Found: true}

	// fn builds a fake resolver step that records whether it ran.
	fn := func(res registrantResult, err error, ran *bool) func(context.Context, string) (registrantResult, error) {
		return func(context.Context, string) (registrantResult, error) {
			*ran = true
			return res, err
		}
	}

	tests := []struct {
		name      string
		rdapRes   registrantResult
		rdapErr   error
		wantOrg   string
		wantFound bool
		wantWHOIS bool // WHOIS fallback must have run
	}{
		{
			name:      "rdap hit short-circuits whois",
			rdapRes:   rdapHit,
			wantOrg:   "RDAP Org",
			wantFound: true,
			wantWHOIS: false,
		},
		{
			name:      "rdap redacted (found=false) falls through to whois",
			rdapRes:   registrantResult{}, // successful RDAP, but registrant absent/redacted
			wantOrg:   "WHOIS Org",
			wantFound: true,
			wantWHOIS: true,
		},
		{
			name:      "rdap masked registrant falls through to whois",
			rdapRes:   registrantResult{Org: "REDACTED FOR PRIVACY", Found: true, Masked: true},
			wantOrg:   "WHOIS Org",
			wantFound: true,
			wantWHOIS: true,
		},
		{
			name:      "rdap transport error falls through to whois",
			rdapErr:   errors.New("rdap: dial tcp: timeout"),
			wantOrg:   "WHOIS Org",
			wantFound: true,
			wantWHOIS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rdapRan, whoisRan bool
			rdapFn := fn(tt.rdapRes, tt.rdapErr, &rdapRan)
			whoisFn := fn(whoisHit, nil, &whoisRan)

			res, err := resolveWithFallback(context.Background(), domain, rdapFn, whoisFn)
			require.NoError(t, err)
			assert.True(t, rdapRan, "RDAP must always be attempted first")
			assert.Equal(t, tt.wantWHOIS, whoisRan, "WHOIS fallback ran?")
			assert.Equal(t, tt.wantOrg, res.Org)
			assert.Equal(t, tt.wantFound, res.Found)
		})
	}
}

// fakeRDAPDoer drives extractRDAPRegistrantOrg without real network I/O:
// panicVal (non-nil) makes Do panic; otherwise it returns resp/err verbatim.
type fakeRDAPDoer struct {
	resp     *rdap.Response
	err      error
	panicVal any
}

func (f fakeRDAPDoer) Do(*rdap.Request) (*rdap.Response, error) {
	if f.panicVal != nil {
		panic(f.panicVal)
	}
	return f.resp, f.err
}

// TestExtractRDAPRegistrantOrg covers the safety-critical RDAP primary branch
// directly (ENG-5123 review, Claude): a panic anywhere in the lookup/extraction
// is recovered into an error AND flags the client for discard (never pooled),
// and the nil-response / wrong-object guards fall through as errors rather than
// crashing. Hermetic: the doer is a fake, no network. The happy path proves a
// well-formed *rdap.Domain yields the registrant org and keeps the client
// poolable.
func TestExtractRDAPRegistrantOrg(t *testing.T) {
	t.Run("panic is recovered and flags client for discard", func(t *testing.T) {
		org, panicked, err := extractRDAPRegistrantOrg(context.Background(),
			fakeRDAPDoer{panicVal: "boom in openrdap"}, "example.com")
		require.Error(t, err)
		assert.True(t, panicked, "a panicked client must be discarded, not pooled")
		assert.Empty(t, org)
		assert.Contains(t, err.Error(), "recovered panic")
	})

	t.Run("transport error passes through, client stays poolable", func(t *testing.T) {
		wantErr := errors.New("dial tcp: connection refused")
		org, panicked, err := extractRDAPRegistrantOrg(context.Background(),
			fakeRDAPDoer{err: wantErr}, "example.com")
		require.Error(t, err)
		assert.False(t, panicked, "a transport error leaves the client's maps intact")
		assert.Empty(t, org)
		assert.ErrorIs(t, err, wantErr)
	})

	t.Run("nil response is guarded, not dereferenced", func(t *testing.T) {
		org, panicked, err := extractRDAPRegistrantOrg(context.Background(),
			fakeRDAPDoer{resp: nil, err: nil}, "example.com")
		require.Error(t, err)
		assert.False(t, panicked)
		assert.Empty(t, org)
		assert.Contains(t, err.Error(), "nil response")
	})

	t.Run("wrong response object type is guarded", func(t *testing.T) {
		org, panicked, err := extractRDAPRegistrantOrg(context.Background(),
			fakeRDAPDoer{resp: &rdap.Response{Object: "not a *rdap.Domain"}}, "example.com")
		require.Error(t, err)
		assert.False(t, panicked)
		assert.Empty(t, org)
		assert.Contains(t, err.Error(), "unexpected response object")
	})

	t.Run("well-formed domain yields registrant org", func(t *testing.T) {
		resp := &rdap.Response{Object: &rdap.Domain{
			Entities: []rdap.Entity{registrantEntity("Acme Corp", "")},
		}}
		org, panicked, err := extractRDAPRegistrantOrg(context.Background(),
			fakeRDAPDoer{resp: resp}, "acme.com")
		require.NoError(t, err)
		assert.False(t, panicked)
		assert.Equal(t, "Acme Corp", org)
	})
}
