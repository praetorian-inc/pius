package domains

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
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

// TestDecideConfidence_RedactedRegistrantScoresUnverified proves the ENG-5404
// mis-ranking consequence: a redaction placeholder compared against the query
// org yields zero token overlap and falls into the clear-mismatch branch, so a
// domain whose registrant is merely hidden is de-ranked as though its registrant
// contradicted the query. Masked registrants are UNVERIFIABLE, not mismatches.
// The result is built through newRegistrantResult (as viaRDAP/viaWHOIS do) so
// the predicate is genuinely exercised rather than stubbed past.
func TestDecideConfidence_RedactedRegistrantScoresUnverified(t *testing.T) {
	const queryOrg = "Cloudflare, Inc."

	for _, org := range []string{"DATA REDACTED", "REDACTED FOR GDPR", "GDPR Masked"} {
		t.Run(org, func(t *testing.T) {
			got := decideConfidence(queryOrg, newRegistrantResult(org), nil)
			assert.Equal(t, confReverseWhoisUnverified, got,
				"a redaction placeholder is unverifiable, not a clear mismatch")
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

// TestIsMaskedOrg_PrivacyMarkers covers ENG-5404. The exact-phrase tables are
// structurally fail-open against registrar wording variation: detection fires
// only on an exact wording or a superstring of one, so any wording built from
// the same vocabulary in a different order escapes. Detection must therefore key
// on redaction MARKERS carried by the org's tokens, not on enumerated phrases.
func TestIsMaskedOrg_PrivacyMarkers(t *testing.T) {
	masked := []string{
		"DATA REDACTED",       // the live cloudflare.com wording (ENG-5404)
		"   data redacted   ", // case- and whitespace-insensitive, per AC1
		// Statute-named wordings stay masked WITHOUT a bare "gdpr" marker: the
		// action word beside the statute is what fires (ENG-5404, Codex review).
		"REDACTED FOR GDPR",      // via "redacted"
		"GDPR Masked",            // via "masked"
		"Data Protected by GDPR", // via tier 2's "data protected" guard phrase
		"Redacted | EU registrant",
		"Registrant Withheld",
		"Data Protected by Registrar",
	}
	for _, org := range masked {
		assert.Truef(t, isMaskedOrg(org),
			"%q is a redaction placeholder, not a real registrant", org)
	}

	// No real-name regression (ENG-5404 AC4). Each of these CONTAINS marker
	// vocabulary as a substring but not as a whole token — which is exactly why
	// marker matching is token-bounded rather than substring-based.
	genuine := []string{
		"Redactron Systems",     // contains "redact"
		"Maskell Group",         // contains "mask"
		"Privacy International", // a real NGO — bare "privacy" is NOT a marker
		"Leica Biosystems",
		"GDPR Register B.V.", // a statute-named org — "gdpr" is NOT a marker
		"The GDPR Institute",
	}
	for _, org := range genuine {
		assert.Falsef(t, isMaskedOrg(org), "%q is a real organization name", org)
	}
}

// TestIsMaskedOrg_MarkerPhrasesMatchTokenRuns covers the marker-PHRASE mechanism
// of tier 3 (whoisPrivacyMarkerPhrases via containsTokenRun), which the tests
// above never reach: every phrase-shaped string they use is answered by an
// EARLIER tier. "Data Protected by Registrar" contains the guard phrase "data
// protected" verbatim, so tier 2's substring pass returns first; "Not Disclosed"
// is an exact whoisPrivacyNames entry, so tier 1 returns first. Deleting
// containsTokenRun's match or emptying whoisPrivacyMarkerPhrases would leave
// those assertions green — the phrases would be asserted only in principle.
//
// Every masked input below is therefore chosen to fall THROUGH tiers 1 and 2 so
// that run matching is what actually decides, and requireTierThree asserts that
// fall-through rather than assuming it: if a future table edit makes an earlier
// tier answer one of these strings, the test fails loudly instead of silently
// re-covering the same ground.
func TestIsMaskedOrg_MarkerPhrasesMatchTokenRuns(t *testing.T) {
	// requireTierThree fails unless org escapes tier 1 (exact lookup in either
	// table) and tier 2 (substring pass over eligible guard phrases), leaving
	// tier 3 as the only tier that can answer.
	requireTierThree := func(t *testing.T, org string) {
		t.Helper()
		key := strings.ToLower(strings.TrimSpace(org))
		require.Falsef(t, whoisPrivacyGuards[key],
			"vacuity guard: %q is an exact whoisPrivacyGuards entry, so tier 1 answers and tier 3 is never reached", key)
		require.Falsef(t, whoisPrivacyNames[key],
			"vacuity guard: %q is an exact whoisPrivacyNames entry, so tier 1 answers and tier 3 is never reached", key)
		for phrase := range whoisPrivacyGuards {
			if len(phrase) >= maskedSubstringMinLen {
				require.NotContainsf(t, key, phrase,
					"vacuity guard: %q contains guard phrase %q, so tier 2's substring pass answers and tier 3 is never reached", key, phrase)
			}
		}
	}

	// {"data","protected"} reached at tier 3. The hyphen means the literal
	// substring "data protected" is absent (tier 2 misses), but tokenize splits
	// on non-alphanumerics into ["data","protected","holdings"], where the pair is
	// a consecutive run.
	t.Run("data protected run", func(t *testing.T) {
		const org = "Data-Protected Holdings"
		requireTierThree(t, org)
		assert.Truef(t, isMaskedOrg(org),
			"%q carries the {data protected} marker run across a token boundary; only tier 3 can see it", org)
	})

	// {"not","disclosed"} reached at tier 3. "not disclosed" is an exact
	// whoisPrivacyNames entry but is NOT a whoisPrivacyGuards phrase, so tier 2
	// never scans for it; prefixing a field label defeats tier 1's exact lookup.
	t.Run("not disclosed run", func(t *testing.T) {
		const org = "Registrant: Not Disclosed"
		requireTierThree(t, org)
		assert.Truef(t, isMaskedOrg(org),
			"%q carries the {not disclosed} marker run; tier 1's exact lookup misses the labelled form", org)
	})

	// Non-adjacency negative: both tokens of {"data","protected"} are present but
	// not consecutive, so containsTokenRun's window comparison must reject them.
	// This is what makes run matching a RUN check rather than an any-two-tokens
	// check — without it, a set-membership implementation would pass too.
	t.Run("tokens present but not adjacent", func(t *testing.T) {
		const org = "Data Systems Protected Ltd"
		requireTierThree(t, org)
		assert.Falsef(t, isMaskedOrg(org),
			"%q separates \"data\" and \"protected\", so no marker RUN is present and it is a real org", org)
	})

	// Run longer than the token list: containsTokenRun's len(run) > len(tokens)
	// early return. A single-token org cannot contain any two-token run, and the
	// guard keeps the window loop from being entered with a negative bound.
	t.Run("single token org shorter than every run", func(t *testing.T) {
		const org = "Cloudflare"
		requireTierThree(t, org)
		assert.Falsef(t, isMaskedOrg(org),
			"%q is one token, shorter than every marker run, and is a real organization", org)
	})
}

// TestMaskedSubstringMinLenGuardsTheSubstringPass asserts the length gate that
// keeps isMaskedOrg's substring pass from firing on an incidental fragment of a
// real org name (ENG-5404 AC4). The gate is SILENT by construction: a phrase
// shorter than the constant is skipped by the loop, so adding one would look
// like a widening while actually being dead weight. Assert every guard phrase
// clears it, and assert non-vacuously that at least one phrase is eligible.
func TestMaskedSubstringMinLenGuardsTheSubstringPass(t *testing.T) {
	eligible := 0
	for phrase := range whoisPrivacyGuards {
		assert.GreaterOrEqualf(t, len(phrase), maskedSubstringMinLen,
			"guard phrase %q is shorter than maskedSubstringMinLen (%d): isMaskedOrg's substring pass skips it silently",
			phrase, maskedSubstringMinLen)
		if len(phrase) >= maskedSubstringMinLen {
			eligible++
		}
	}
	require.NotZero(t, eligible,
		"vacuity guard: no guard phrase is eligible for the substring pass")

	// Behavioral counterpart: a sub-threshold fragment of a guard phrase must not
	// mask a real org. "gandi" (5 chars) is a fragment of the guard phrase
	// "gandi sas"; an org carrying only the fragment stays unmasked.
	assert.False(t, isMaskedOrg("Gandi Solutions"))
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

// TestResolveWithFallback_RedactedRDAPRegistrantConsultsWHOIS proves the second
// ENG-5404 consequence — the fallback, not just the predicate. The "rdap masked
// registrant" case in TestResolveWithFallback hand-sets Masked:true in a struct
// literal, so it passes no matter what isMaskedOrg decides and cannot detect a
// false negative in the predicate. Here the RDAP step builds its result the way
// production does (newRegistrantResult, as viaRDAP does), so a redaction
// placeholder the predicate fails to flag reads as an authoritative registrant
// and short-circuits the early return in resolveWithFallback — the WHOIS leg
// that may carry the real registrant never runs. Hermetic: fake steps, no network.
func TestResolveWithFallback_RedactedRDAPRegistrantConsultsWHOIS(t *testing.T) {
	const realOrg = "Cloudflare, Inc."

	for _, org := range []string{"DATA REDACTED", "REDACTED FOR GDPR", "GDPR Masked"} {
		t.Run(org, func(t *testing.T) {
			var whoisRan bool
			rdapFn := func(context.Context, string) (registrantResult, error) {
				return newRegistrantResult(org), nil
			}
			whoisFn := func(context.Context, string) (registrantResult, error) {
				whoisRan = true
				return registrantResult{Org: realOrg, Found: true}, nil
			}

			res, err := resolveWithFallback(context.Background(), "cloudflare.com", rdapFn, whoisFn)
			require.NoError(t, err)
			assert.True(t, whoisRan,
				"a redacted RDAP registrant must not short-circuit the WHOIS fallback")
			assert.Equal(t, realOrg, res.Org)
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

// TestVerifyCandidates_DeRankOrderingAndLiteralAnchors pins the de-rank ORDERING
// that is the whole point of verify-after-retrieve: as EMITTED scores,
// corroborated > unverified > mismatch. It also anchors the mismatch band to the
// LITERAL 0.40 (mirroring the literal 0.60 corroborated anchor in
// reverse_whois_test.go). The existing mismatch assertions compare against the
// confReverseWhoisMismatch CONSTANT, so raising that constant above the
// unverified 0.50 (e.g. 0.40 → 0.62) moves prod and test together and stays
// green while silently inverting the ranking. The literal anchor and the
// ordering assertions below both fail under that mutation (ENG-5123 #1).
func TestVerifyCandidates_DeRankOrderingAndLiteralAnchors(t *testing.T) {
	stub := &stubResolver{
		byDomain: map[string]registrantResult{
			"corroborated.com": org("Acme Corp"),    // sim high → corroborated
			"unverified.com":   {},                  // no registrant → unverified
			"mismatch.com":     org("Walmart Inc."), // present, unmasked, disjoint → mismatch
		},
	}
	cands := []candidate{
		{domain: "corroborated.com", finding: plugins.Finding{Value: "corroborated.com"}},
		{domain: "unverified.com", finding: plugins.Finding{Value: "unverified.com"}},
		{domain: "mismatch.com", finding: plugins.Finding{Value: "mismatch.com"}},
	}
	findings, err := verifyCandidates(context.Background(), stub, "Acme", cands)
	require.NoError(t, err)
	require.Len(t, findings, 3)

	corr := plugins.Confidence(findings[0])
	unver := plugins.Confidence(findings[1])
	mism := plugins.Confidence(findings[2])

	// Literal band anchors — NOT the package constants, so a constant edit cannot
	// move the expectation together with the emission.
	assert.InDelta(t, 0.60, corr, 0.001, "corroborated must emit at the literal 0.60 top-of-band")
	assert.InDelta(t, 0.50, unver, 0.001, "unverified must emit at the literal 0.50 mid-band")
	assert.InDelta(t, 0.40, mism, 0.001, "mismatch must emit at the literal 0.40 bottom-of-band")

	// Explicit ORDERING of emitted scores: corroborated > unverified > mismatch.
	assert.Greater(t, corr, unver, "corroborated must outrank unverified")
	assert.Greater(t, unver, mism, "unverified must outrank mismatch (the feature's whole deliverable)")
}

// TestVerifyCandidates_CapLimitsCallsNotRecall pins that maxReverseWhoisCandidates
// caps resolver CALLS, never output (ENG-5123 #3). With one more candidate than
// the cap, the resolver is invoked at most cap times, yet every candidate —
// including the overflow — is still emitted (de-rank-never-drop). A
// `cands = cands[:resolveCount]` truncation drops the overflow finding and fails
// require.Len; dropping the cap entirely makes the call count exceed the cap.
func TestVerifyCandidates_CapLimitsCallsNotRecall(t *testing.T) {
	total := maxReverseWhoisCandidates + 1 // crosses the resolver-call cap by exactly one
	stub := &stubResolver{byDomain: map[string]registrantResult{}}
	cands := make([]candidate, 0, total)
	for i := 0; i < total; i++ {
		d := fmt.Sprintf("cand-%d.example.com", i)
		stub.byDomain[d] = org("Acme Corp") // every candidate WOULD corroborate if resolved
		cands = append(cands, candidate{domain: d, finding: plugins.Finding{Value: d}})
	}

	findings, err := verifyCandidates(context.Background(), stub, "Acme", cands)
	require.NoError(t, err)

	// Recall: every candidate is still emitted — the cap limits resolver CALLS,
	// never output. Truncation would drop the overflow finding here.
	require.Len(t, findings, total, "candidates beyond the cap must still be emitted, never truncated")

	// Calls: the resolver is invoked at most maxReverseWhoisCandidates times.
	assert.Len(t, stub.calls, maxReverseWhoisCandidates, "resolver must be called at most cap times")

	// The overflow candidate (index == cap) was NOT resolved, so it keeps the
	// unverified mid-band score — de-ranked, never dropped — and output order is
	// preserved through the cap boundary.
	overflow := findings[maxReverseWhoisCandidates]
	assert.Equal(t, cands[maxReverseWhoisCandidates].domain, overflow.Value, "output order preserved through the cap")
	assert.InDelta(t, confReverseWhoisUnverified, plugins.Confidence(overflow), 0.001,
		"a candidate beyond the cap is emitted unverified WITHOUT a lookup")
	assert.False(t, stub.queried(overflow.Value), "the overflow candidate must not be resolved")

	// A resolved candidate below the cap corroborates (0.60), proving resolution
	// did happen up to the boundary — the cap is where calls stop, not recall.
	assert.InDelta(t, confReverseWhoisCorroborated, plugins.Confidence(findings[0]), 0.001)
}

// TestResolveWithFallback_PerStepTimeoutsAreIndependent proves each resolver step
// (RDAP, then the WHOIS fallback) gets its OWN timeout derived fresh from the
// incoming budget, not one shared deadline. The RDAP step burns a measurable
// slice of wall-clock before falling through; because the WHOIS step's context
// is created AFTER that, its deadline lands strictly later than the RDAP step's.
// Collapsing the two context.WithTimeout calls into a single shared context
// would give both steps the SAME deadline (gap 0), so this pins the per-step
// independence the review added (ENG-5123 review, Codex P2).
func TestResolveWithFallback_PerStepTimeoutsAreIndependent(t *testing.T) {
	const rdapCost = 30 * time.Millisecond

	var rdapDeadline, whoisDeadline time.Time
	var rdapHasDL, whoisHasDL bool

	rdapFn := func(ctx context.Context, _ string) (registrantResult, error) {
		rdapDeadline, rdapHasDL = ctx.Deadline()
		time.Sleep(rdapCost)           // burn a measurable slice of the step budget
		return registrantResult{}, nil // not Found → force fall-through to WHOIS
	}
	whoisFn := func(ctx context.Context, _ string) (registrantResult, error) {
		whoisDeadline, whoisHasDL = ctx.Deadline()
		return registrantResult{Org: "WHOIS Org", Found: true}, nil
	}

	res, err := resolveWithFallback(context.Background(), "example.com", rdapFn, whoisFn)
	require.NoError(t, err)
	require.Equal(t, "WHOIS Org", res.Org, "WHOIS fallback must have run")
	require.True(t, rdapHasDL, "RDAP step must carry its own per-step deadline")
	require.True(t, whoisHasDL, "WHOIS step must carry its own per-step deadline")

	// Independent steps: the WHOIS deadline is created after the RDAP step ran,
	// so it is later by ~rdapCost. A single shared context yields gap == 0.
	gap := whoisDeadline.Sub(rdapDeadline)
	assert.GreaterOrEqual(t, gap, 10*time.Millisecond,
		"each step must get an independent per-step timeout, not one shared budget (gap==0 means collapsed)")
}

// drainClientPool empties the resolver's pool via non-blocking receives and
// returns every client it held, in order. Callers own re-filling the pool if
// the test continues to use it. Purely channel mechanics — no network.
func drainClientPool(r *rdapWhoisResolver) []*rdap.Client {
	var out []*rdap.Client
	for {
		select {
		case c := <-r.clientPool:
			out = append(out, c)
		default:
			return out
		}
	}
}

// TestRDAPClientPool_PrewarmedFixedSize proves the pool is pre-warmed with
// exactly reverseWhoisWorkers distinct, non-nil clients at fixed capacity, and
// that a bare zero-value literal is usable — both prod call sites construct
// the resolver as &rdapWhoisResolver{} and rely on lazy sync.Once init
// (ENG-5376).
func TestRDAPClientPool_PrewarmedFixedSize(t *testing.T) {
	r := &rdapWhoisResolver{} // zero value, exactly as the prod call sites build it
	r.initClientPool()
	require.NotNil(t, r.clientPool, "zero-value resolver must self-initialize its pool")
	assert.Equal(t, reverseWhoisWorkers, cap(r.clientPool),
		"pool capacity must be fixed at the worker bound")

	drained := drainClientPool(r)
	require.Len(t, drained, reverseWhoisWorkers,
		"pool must be pre-warmed FULL up front, not filled lazily on demand")
	seen := make(map[*rdap.Client]struct{}, len(drained))
	for _, c := range drained {
		require.NotNil(t, c, "a pre-warmed slot must never hold a nil client")
		seen[c] = struct{}{}
	}
	assert.Len(t, seen, reverseWhoisWorkers,
		"every pre-warmed client must be a distinct instance — shared clients race in rdap.Client.Do")

	// Init is once-only: a second init call must not swap in a fresh pool or
	// refill the (deliberately drained) existing one.
	r.initClientPool()
	assert.Zero(t, len(r.clientPool), "initClientPool must be idempotent, not re-fill or replace the pool")
	assert.Equal(t, reverseWhoisWorkers, cap(r.clientPool))
}

// TestRDAPClientPool_SurvivesGC is the regression test for ENG-5376 AC1: the
// pooled clients must survive garbage collection. The old sync.Pool did NOT —
// the runtime's poolCleanup GC pre-hook demotes pool contents to a victim
// cache on one collection and drops them on the next, so a mid-pass GC
// silently replaced every warm client (and its 24h in-client bootstrap cache)
// with a cold fresh one. A buffered channel is ordinary heap-reachable memory
// the GC never evicts. The discriminating assertion is pointer IDENTITY: after
// GC cycles, the pool must still hand back exactly the original client set,
// never a silent replacement. Proven to fail against a sync.Pool-backed
// equivalent (mutation proof, Phase 14).
func TestRDAPClientPool_SurvivesGC(t *testing.T) {
	r := &rdapWhoisResolver{}
	r.initClientPool()

	// Record the identity set of the six pre-warmed clients, then put them all
	// back so the pool is the only place the resolver references them when GC
	// runs. The `original` map ALSO keeps the objects allocated — deliberately:
	// that pins their addresses so a cold replacement can never reuse an
	// original's address and alias it, which would make the identity comparison
	// vacuous. It does NOT mask the regression this test exists to catch:
	// sync.Pool eviction is the POOL dropping its reference (poolCleanup clears
	// the pool's slots unconditionally), not the object being freed, so the old
	// primitive fails this test even with `original` holding the pointers.
	held := drainClientPool(r)
	require.Len(t, held, reverseWhoisWorkers)
	original := make(map[*rdap.Client]struct{}, reverseWhoisWorkers)
	for _, c := range held {
		original[c] = struct{}{}
		r.releaseClient(c, false)
	}
	clear(held) // zero the six element pointers so the pool channel is the only reference when GC runs

	for cycle := 0; cycle < 3; cycle++ {
		// Two back-to-back collections per cycle, with the clients sitting ONLY
		// in the pool: sync.Pool needs exactly this pattern to evict (first GC
		// demotes to the victim cache, second drops the victim cache), so a
		// single GC per acquire/release round could let the victim cache hide
		// the regression. A channel pool survives any number of collections.
		runtime.GC()
		runtime.GC()

		batch := make([]*rdap.Client, 0, reverseWhoisWorkers)
		for i := 0; i < reverseWhoisWorkers; i++ {
			c := r.acquireClient()
			require.NotNil(t, c)
			_, ok := original[c]
			assert.True(t, ok,
				"cycle %d: pool handed back a client outside the original pre-warmed set — a warm client was silently replaced after GC (the sync.Pool failure mode, ENG-5376 AC1)", cycle)
			batch = append(batch, c)
		}
		for _, c := range batch {
			r.releaseClient(c, false)
		}
	}

	// After all collections, the pool holds exactly the original identity set —
	// same six pointers, nothing evicted, nothing swapped for a fresh client.
	final := drainClientPool(r)
	require.Len(t, final, reverseWhoisWorkers)
	got := make(map[*rdap.Client]struct{}, len(final))
	for _, c := range final {
		got[c] = struct{}{}
	}
	assert.Equal(t, original, got, "pool must survive GC with its original clients intact")
	// Keep the originals' addresses pinned until every identity comparison above
	// has run, so no assertion ever compared against a recycled address.
	runtime.KeepAlive(original)
}

// TestRDAPClientPool_PanicRefillKeepsPoolFull proves a poisoned client
// (panicked mid-Lookup, possibly holding a half-written registries map) is
// discarded on release AND its slot is refilled with a fresh client. This is a
// genuine channel-pool regression risk the old primitive never had: sync.Pool
// got replacements for free from New, but a channel slot lost to a discard is
// lost forever unless releaseClient explicitly refills it — one leak per panic
// until the pool sits permanently empty. Repeating well past the pool size
// proves there is no slow starvation.
func TestRDAPClientPool_PanicRefillKeepsPoolFull(t *testing.T) {
	r := &rdapWhoisResolver{}
	r.initClientPool()

	for i := 0; i < 20; i++ {
		c := r.acquireClient()
		require.NotNil(t, c, "iteration %d: acquire from a maintained pool", i)
		r.releaseClient(c, true) // poisoned: discard, refill the slot

		// (b)+(c): the pool is back to full strength — no slot leaked, even after
		// more panics than the pool has slots.
		remaining := drainClientPool(r)
		require.Len(t, remaining, reverseWhoisWorkers,
			"iteration %d: a panic discard must refill the slot, or the pool starves one slot per panic", i)
		for _, p := range remaining {
			require.NotNil(t, p)
			// (a): the poisoned pointer itself must never re-enter the pool.
			assert.NotSame(t, c, p,
				"iteration %d: the poisoned client must be discarded, not pooled", i)
			r.releaseClient(p, false)
		}
	}
}

// TestRDAPClientPool_AcquireDoesNotBlockWhenEmpty proves an empty pool
// degrades to a fresh cold client instead of parking the worker. Under the
// g.SetLimit(reverseWhoisWorkers) invariant the pool never runs dry, but if
// that invariant is ever violated the failure mode must be a slowdown, not a
// hang until the pass budget cancels. Non-blocking is asserted structurally:
// the call runs on the test goroutine with nothing that could ever unblock a
// blocking receive, so returning at all proves the non-blocking select.
func TestRDAPClientPool_AcquireDoesNotBlockWhenEmpty(t *testing.T) {
	r := &rdapWhoisResolver{}
	handedOut := make(map[*rdap.Client]struct{}, reverseWhoisWorkers)
	for i := 0; i < reverseWhoisWorkers; i++ {
		c := r.acquireClient() // first call also proves zero-value lazy init on the acquire path
		require.NotNil(t, c)
		handedOut[c] = struct{}{}
	}
	require.Len(t, handedOut, reverseWhoisWorkers)
	require.Zero(t, len(r.clientPool), "pool must be fully drained before the overflow acquire")

	extra := r.acquireClient()
	require.NotNil(t, extra, "an empty pool must still yield a usable client")
	_, recycled := handedOut[extra]
	assert.False(t, recycled,
		"the overflow client must be FRESH — recycling one still in flight would race in rdap.Client.Do")
}

// TestRDAPClientPool_ReleaseDoesNotBlockWhenFull proves releasing into a full
// pool drops the extra client for GC instead of blocking or growing the pool,
// keeping total live clients bounded. This covers both callers of that path:
// a release-without-acquire, and an acquire-fallback cold client coming home
// to a pool that refilled meanwhile. Non-blocking is asserted structurally:
// each call runs on the test goroutine with no receiver that could ever drain
// the full channel, so returning at all proves the non-blocking send.
func TestRDAPClientPool_ReleaseDoesNotBlockWhenFull(t *testing.T) {
	r := &rdapWhoisResolver{}
	r.initClientPool() // pool starts full

	for i := 0; i < reverseWhoisWorkers+3; i++ {
		r.releaseClient(newRDAPClient(), false)
		assert.Equal(t, reverseWhoisWorkers, len(r.clientPool),
			"iteration %d: an overflow release must be dropped, never grow the pool past its fixed size", i)
	}
	assert.Equal(t, reverseWhoisWorkers, cap(r.clientPool))
}

// TestRDAPClientPool_ExclusiveOwnershipUnderConcurrency proves ENG-5376 AC2:
// no client is ever held by two goroutines at once — the whole reason the pool
// exists, since openrdap's Client.Do writes an unsynchronized registries map.
// Many more goroutines than pool slots hammer acquire→work→release while a
// mutex-guarded in-use set flags any pointer handed out twice concurrently.
// Run under -race, which additionally checks the pool's own internals. No
// sleeps: contention comes from goroutine count, not wall-clock.
func TestRDAPClientPool_ExclusiveOwnershipUnderConcurrency(t *testing.T) {
	r := &rdapWhoisResolver{}

	const goroutines = 4 * reverseWhoisWorkers
	const iterations = 200

	var mu sync.Mutex
	inUse := make(map[*rdap.Client]struct{})

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				c := r.acquireClient()
				if c == nil {
					t.Error("acquireClient returned nil under concurrency")
					return
				}
				mu.Lock()
				if _, held := inUse[c]; held {
					mu.Unlock()
					t.Errorf("client %p handed to two goroutines at once — exclusive ownership violated (ENG-5376 AC2)", c)
					return
				}
				inUse[c] = struct{}{}
				mu.Unlock()

				runtime.Gosched() // brief hold: widen the window for a double hand-out to surface

				// Un-mark BEFORE releasing: once the client is back in the pool it
				// may legitimately be re-acquired immediately.
				mu.Lock()
				delete(inUse, c)
				mu.Unlock()
				r.releaseClient(c, false)
			}
		}()
	}
	wg.Wait()
}
