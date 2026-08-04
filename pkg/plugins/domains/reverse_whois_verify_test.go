package domains

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	whoisparser "github.com/likexian/whois-parser"
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
			got := decideConfidence(tt.queryOrg, tt.res, tt.lookupErr)
			assert.InDelta(t, tt.wantScore, got.Score, 0.001, "score")
			assert.NotEmpty(t, got.Justification, "every decision explains itself")
			// The justification must never leak the resolved registrant, which is
			// exactly the third-party WHOIS PII this plugin declines to log.
			if tt.res.Org != "" {
				assert.NotContains(t, got.Justification, tt.res.Org,
					"justifications must not reproduce the registrant organization")
			}
			// Design invariant: every score stays in needs_review — below clean
			// (never auto-clean) and at/above the noise floor (never dropped).
			assert.Less(t, got.Score, plugins.ConfidenceHigh,
				"reverse-whois must never auto-clean")
			assert.GreaterOrEqual(t, got.Score, plugins.ConfidenceLow,
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
			assert.Equal(t, confidenceDecision{Score: confReverseWhoisUnverified, Justification: justifyReverseWhoisUnverified}, got,
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
		assert.InDelta(t, confReverseWhoisUnverified, plugins.TotalConfidence(f), 0.001)
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
	assert.InDelta(t, confReverseWhoisCorroborated, plugins.TotalConfidence(findings[0]), 0.001)
	assert.InDelta(t, confReverseWhoisMismatch, plugins.TotalConfidence(findings[1]), 0.001)
	assert.InDelta(t, confReverseWhoisUnverified, plugins.TotalConfidence(findings[2]), 0.001)
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
	assert.InDelta(t, confReverseWhoisUnverified, plugins.TotalConfidence(findings[1]), 0.001)
	assert.True(t, plugins.NeedsReview(findings[1]))
	// A clean sibling still scores corroborated — the recover() is scoped per
	// worker and does not poison the rest of the pass.
	assert.InDelta(t, confReverseWhoisCorroborated, plugins.TotalConfidence(findings[0]), 0.001)
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
		assert.InDelta(t, confReverseWhoisUnverified, plugins.TotalConfidence(f), 0.001,
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
		assert.Less(t, plugins.TotalConfidence(f), plugins.ConfidenceHigh,
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

	corr := plugins.TotalConfidence(findings[0])
	unver := plugins.TotalConfidence(findings[1])
	mism := plugins.TotalConfidence(findings[2])

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
// capCrossingCandidates builds exactly maxReverseWhoisCandidates+1 candidates —
// crossing the resolver-call cap by exactly one — alongside a resolver that WOULD
// corroborate every one of them if it were asked. Shared by the two tests that
// need that boundary crossed by one, so the construction cannot drift apart
// between them: one asserts what the cap does to calls and recall, the other what
// it does to the pass summary.
func capCrossingCandidates() (*stubResolver, []candidate) {
	total := maxReverseWhoisCandidates + 1
	stub := &stubResolver{byDomain: map[string]registrantResult{}}
	cands := make([]candidate, 0, total)
	for i := 0; i < total; i++ {
		d := fmt.Sprintf("cand-%d.example.com", i)
		stub.byDomain[d] = org("Acme Corp") // every candidate WOULD corroborate if resolved
		cands = append(cands, candidate{domain: d, finding: plugins.Finding{Value: d}})
	}
	return stub, cands
}

func TestVerifyCandidates_CapLimitsCallsNotRecall(t *testing.T) {
	stub, cands := capCrossingCandidates()
	total := len(cands)

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
	assert.InDelta(t, confReverseWhoisUnverified, plugins.TotalConfidence(overflow), 0.001,
		"a candidate beyond the cap is emitted unverified WITHOUT a lookup")
	assert.False(t, stub.queried(overflow.Value), "the overflow candidate must not be resolved")

	// A resolved candidate below the cap corroborates (0.60), proving resolution
	// did happen up to the boundary — the cap is where calls stop, not recall.
	assert.InDelta(t, confReverseWhoisCorroborated, plugins.TotalConfidence(findings[0]), 0.001)
}

// TestVerifyCandidates_CapTruncationDegradesThePass covers ENG-5405 fix A2 and
// discharges Phase 9 finding D4 in the same three assertions.
//
// A2: candidates past maxReverseWhoisCandidates are never looked up, so their
// zero-valued candidateOutcome entries read as whoisComplete. Summing the reason
// buckets ALONE therefore called a pass over 5000 candidates that attempted only
// 500 "complete" at slog.Info — exactly the silent-degradation class ENG-5405
// exists to remove, reappearing at the cap boundary. The cap is the FOURTH
// degradation arm, so `attempted < total` must degrade the pass. Note the shape:
// every one of the 500 attempted lookups here corroborates cleanly, so truncation
// is the ONLY thing degrading this pass — a bucket-sum-only predicate emits the
// clean Info line and this test fails.
//
// D4: summarizeVerifyPass(total, attempted int, ...) has two adjacent same-type int
// params. Every other call site passes EQUAL values (the end-to-end degraded test
// asserts both to 7, the direct-call subtests pass 7,7 and 3,3), so transposing
// the production arguments left the whole suite green. 501 vs 500 is the only
// shape that pins the argument order, which is why candidates and attempted are
// asserted here as two DIFFERENT values rather than one repeated one.
func TestVerifyCandidates_CapTruncationDegradesThePass(t *testing.T) {
	// The 501/500 literals below are spelled out rather than derived from the cap,
	// so a change to the constant cannot move expectation and emission together.
	// This guard makes such a change fail loudly here instead of drifting silently.
	require.Equal(t, 500, maxReverseWhoisCandidates, "the literals below assume the cap is 500")

	logs := captureSlog(t)
	stub, cands := capCrossingCandidates()

	findings, err := verifyCandidates(context.Background(), stub, "Acme", cands)
	require.NoError(t, err)
	require.Len(t, findings, 501, "de-rank never drop: the cap bounds calls, never output")

	recs := logs()
	// Resolve the summary record WITHOUT keying on its message. One record per pass
	// is the contract at either level, and this pass emits nothing else (no panic,
	// no lookup error). Deliberate: it keeps the two count assertions below
	// reachable even when the degraded/clean verdict itself regresses, so the D4
	// argument-order pin is proven independently of the A2 predicate pin instead of
	// being hidden behind a require that aborts first.
	require.Len(t, recs, 1, "exactly one pass-summary record, whatever its level; got %v", recs)
	rec := recs[0]

	// D4: two DIFFERENT values. A transposed call site swaps these and fails here.
	assert.EqualValues(t, 501, rec["candidates"],
		"candidates is the full input size, INCLUDING the overflow that was never looked up")
	assert.EqualValues(t, 500, rec["attempted"],
		"attempted is the lookups started, capped at maxReverseWhoisCandidates")
	assert.NotEqual(t, rec["candidates"], rec["attempted"],
		"the two counts must be distinguishable here, or the argument order is unpinned")

	// A2: and the verdict on those counts is the degraded one.
	assert.False(t, hasLogRecord(recs, verifyPassMsgClean),
		"A2: a pass that never looked at one of its 501 candidates must NOT report itself complete")
	assert.Equal(t, verifyPassMsgDegraded, rec["msg"], "truncation must emit the degraded line")
	assert.Equal(t, slog.LevelWarn.String(), rec["level"])

	// Truncation is the SOLE degradation: no per-candidate bucket fired. This is
	// what makes the degraded verdict above attributable to `attempted < total`
	// rather than to some incidental lookup failure.
	for _, k := range []string{
		"incomplete_deadline", "incomplete_referral", "incomplete_referral_budget",
		"lookup_failed", "panicked",
	} {
		assert.EqualValues(t, 0, rec[k], "%s must be zero: truncation alone degraded this pass", k)
	}
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

// ---------------------------------------------------------------------------
// ENG-5405 — incomplete-lookup observability at the resolver and pass level.
// ---------------------------------------------------------------------------

// tldRecordNoRegistrantOrg is a TLD-registry WHOIS record for a domain that
// EXISTS but publishes no registrant organization. The "Registrant Country" line
// is load-bearing: it is what makes whoisparser.Parse yield a non-nil
// parsed.Registrant whose Organization AND Name are both empty, so viaWHOIS
// reaches its org == "" branch through a FOUND domain rather than through a nil
// Registrant. That distinction is the whole point of AC3 — a chain that ran to
// its natural end and simply had no registrant on record must NOT be reported as
// incomplete (ENG-5405).
const tldRecordNoRegistrantOrg = "Domain Name: EXAMPLE.COM\n" +
	"Registry Domain ID: 123456_DOMAIN_COM-EXAMPLE\n" +
	"Registrar: Example Registrar, Inc.\n" +
	"Updated Date: 2024-01-01T00:00:00Z\n" +
	"Creation Date: 2020-01-01T00:00:00Z\n" +
	"Domain Status: clientTransferProhibited\n" +
	"Registrant Country: US\n"

// TestTLDRecordNoRegistrantOrgFixture_ParsesAsFoundDomainWithoutRegistrantOrg
// pins the precondition the two viaWHOIS tests below silently depend on. Without
// it, a whoisparser upgrade that started returning ErrNotFoundDomain for this
// record would make those tests pass for the WRONG reason: viaWHOIS would bail at
// the Parse error instead of exercising the empty-org branch, and the AC2/AC3
// distinction they exist to prove would never be evaluated.
func TestTLDRecordNoRegistrantOrgFixture_ParsesAsFoundDomainWithoutRegistrantOrg(t *testing.T) {
	parsed, err := whoisparser.Parse(tldRecordNoRegistrantOrg)
	require.NoError(t, err,
		"the fixture must parse as a FOUND domain — an error here (e.g. whoisparser.ErrNotFoundDomain) "+
			"would short-circuit viaWHOIS before the empty-org branch runs")
	require.NotNil(t, parsed.Registrant,
		"the Registrant Country line must yield a non-nil Registrant block")
	assert.Empty(t, parsed.Registrant.Organization, "no registrant organization is published")
	assert.Empty(t, parsed.Registrant.Name, "and no fallback registrant name either")
}

// TestViaWHOIS_ReferralHopFailureReportsIncomplete is AC2 at the resolver level:
// a referral chain whose final hop's transport dies still salvages the
// post-referral record with a nil error (recall is unchanged), but the caller can
// now TELL that the record is partial. Before ENG-5405 this returned exactly the
// same (found=false, err=nil) shape as a clean lookup of a domain with no
// registrant, which is the blindness the ticket exists to end.
func TestViaWHOIS_ReferralHopFailureReportsIncomplete(t *testing.T) {
	const tldRecordWithReferral = tldRecordNoRegistrantOrg +
		"Registrar WHOIS Server: whois.registrar.example\n"

	var hops []string
	stubWhoisRawFn(t, func(_ context.Context, domain, server string) (string, error) {
		hops = append(hops, server)
		switch server {
		case defaultServer:
			return "domain: EXAMPLE.COM\nrefer: whois.tld.example\n", nil
		case "whois.tld.example":
			return tldRecordWithReferral, nil
		case "whois.registrar.example":
			return "", errors.New("connection refused")
		default:
			require.FailNowf(t, "unexpected WHOIS server", "server=%q domain=%q", server, domain)
			return "", nil
		}
	})

	// viaWHOIS never touches its receiver, so a zero-value resolver is safe here
	// and keeps the test off the RDAP client pool entirely.
	res, err := (&rdapWhoisResolver{}).viaWHOIS(context.Background(), "example.com")

	require.NoError(t, err, "the recall-safe salvage still returns a nil error")
	assert.False(t, res.Found, "the truncated record yields no registrant")
	assert.Equal(t, whoisIncompleteReferral, res.Incomplete,
		"AC1/AC2: the caller can now tell a truncated lookup from a clean not-found")
	assert.Equal(t, []string{defaultServer, "whois.tld.example", "whois.registrar.example"}, hops,
		"the failure must be observed on the registrar hop, not earlier")
}

// TestViaWHOIS_NoRegistrantOnRecordIsOrdinaryNotFound is AC3: the two states must
// not collapse in THIS direction either. A chain that ran to its natural end and
// found no registrant organization is an ordinary not-found, so over-reporting it
// as incomplete would make the new signal useless — every privacy-protected or
// thin-registry domain would light up as degraded.
func TestViaWHOIS_NoRegistrantOnRecordIsOrdinaryNotFound(t *testing.T) {
	var hops []string
	stubWhoisRawFn(t, func(_ context.Context, domain, server string) (string, error) {
		hops = append(hops, server)
		switch server {
		case defaultServer:
			return "domain: EXAMPLE.COM\nrefer: whois.tld.example\n", nil
		case "whois.tld.example":
			return tldRecordNoRegistrantOrg, nil // no onward referral: the chain ends here
		default:
			require.FailNowf(t, "unexpected WHOIS server", "server=%q domain=%q", server, domain)
			return "", nil
		}
	})

	res, err := (&rdapWhoisResolver{}).viaWHOIS(context.Background(), "example.com")

	require.NoError(t, err)
	assert.False(t, res.Found, "no registrant organization on record")
	assert.Equal(t, whoisComplete, res.Incomplete,
		"AC3: a chain that ran to its natural end must NOT be flagged incomplete")
	assert.Equal(t, []string{defaultServer, "whois.tld.example"}, hops,
		"the chain must stop at the TLD server — no onward referral was published")
}

// TestViaWHOIS_WhoisQueryErrorCarriesNoIncompletenessReason pins the PREMISE that
// viaWHOIS's whoisQuery-error branch is built on. That branch discards the
// whoisIncompleteness it was handed and returns a bare registrantResult{}, and its
// comment justifies the discard with a claim about a DIFFERENT function: that
// whoisQuery reports whoisComplete on every path that returns a non-nil error. A
// claim about another function is exactly the kind a comment cannot enforce — if
// whoisQuery ever started reporting a real reason alongside an error, the discard
// would silently begin losing it and nothing here would fail.
//
// So both halves are asserted, per row:
//
//   - the PREMISE, read straight off whoisQuery: error non-nil, no payload, and
//     the reason is whoisComplete. This is what makes the discard lossless.
//   - the CONSEQUENCE, read off viaWHOIS: the error surfaces and the result is the
//     ZERO registrantResult — not merely whoisComplete, so no other field can be
//     fabricated on this path either.
//
// The rows are whoisQuery's three no-salvage error returns, which are all the ways
// it can produce a non-nil error: a first-hop transport failure, a chain that never
// advances past the bootstrap seed, and a ctx that was already done at the loop
// top. Enumerating all three is the point — the comment says "EVERY path", and a
// single row would only pin one of them.
func TestViaWHOIS_WhoisQueryErrorCarriesNoIncompletenessReason(t *testing.T) {
	// A seed record with NO referral: extractReferral finds nothing, so the loop
	// breaks at the seed and lastRaw is never set. The seed's own response is never
	// salvageable — it describes the TLD registry, not the registrant.
	const seedRecordNoReferral = "domain: COM\norganisation: VeriSign Global Registry Services\n"

	tests := []struct {
		name string
		// newCtx builds the ctx both calls run under. Only the pre-cancelled row
		// returns a non-clean one.
		newCtx func() (context.Context, context.CancelFunc)
		// respond answers a hop. nil means the stub must never be reached at all.
		respond func(t *testing.T, server string) (string, error)
		// wantHops is the exact server sequence ONE call must dial; nil = no dial.
		wantHops        []string
		wantErrContains string
		why             string
	}{
		{
			name:   "first-hop transport failure never reaches a salvageable record",
			newCtx: func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			respond: func(t *testing.T, server string) (string, error) {
				require.Equal(t, defaultServer, server, "the chain must die on the bootstrap seed hop")
				return "", errors.New("dial tcp: connection refused")
			},
			wantHops:        []string{defaultServer},
			wantErrContains: "whois query to",
			why: "the seed hop failed, so lastRaw was never set and there is no partial record to " +
				"describe — the error is the whole signal",
		},
		{
			name:   "chain that never advances past the bootstrap seed",
			newCtx: func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			respond: func(t *testing.T, server string) (string, error) {
				require.Equal(t, defaultServer, server, "with no referral the chain cannot advance")
				return seedRecordNoReferral, nil
			},
			wantHops:        []string{defaultServer},
			wantErrContains: "no record beyond bootstrap seed",
			why: "the seed answered, but a seed-only record is deliberately NOT salvaged, so there is " +
				"still no partial record — reporting a reason here would describe a payload the " +
				"caller never receives",
		},
		{
			name: "ctx already done before the first hop",
			newCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // done before whoisQuery's loop-top check runs
				return ctx, func() {}
			},
			respond:         nil, // must never be reached
			wantHops:        nil,
			wantErrContains: context.Canceled.Error(),
			why: "a ctx that was already done aborts at the loop top with nothing dialed, so this is " +
				"the one error path where whoisComplete is not merely correct but the only option",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.newCtx()
			defer cancel()

			// whoisQuery drives its hops sequentially on the calling goroutine, so a
			// plain slice needs no synchronisation. It is reset before each of the two
			// calls so wantHops describes ONE call's dials, not the sum of both.
			var hops []string
			stubWhoisRawFn(t, func(_ context.Context, domain, server string) (string, error) {
				hops = append(hops, server)
				if tc.respond == nil {
					require.FailNowf(t, "WHOIS must not be dialed",
						"a pre-cancelled ctx must abort before any hop; got server=%q domain=%q", server, domain)
					return "", nil
				}
				return tc.respond(t, server)
			})

			// Half 1 — the PREMISE, straight off whoisQuery. This is the assertion that
			// fails if whoisQuery ever starts reporting a reason on an error path, which
			// is the change that would make viaWHOIS's discard lossy.
			hops = nil
			raw, incomplete, queryErr := whoisQuery(ctx, "example.com")
			require.Error(t, queryErr, "row premise: this chain must make whoisQuery FAIL, not salvage")
			assert.Contains(t, queryErr.Error(), tc.wantErrContains,
				"row premise: the error must come from the intended no-salvage path")
			assert.Empty(t, raw, "an error path yields no payload, salvaged or otherwise")
			assert.Equal(t, whoisComplete, incomplete,
				"whoisQuery must report whoisComplete on EVERY non-nil-error return — this is the "+
					"premise viaWHOIS's discard depends on: %s", tc.why)
			assert.Equal(t, tc.wantHops, hops, "premise half must dial exactly the expected hops")

			// Half 2 — the CONSEQUENCE, off viaWHOIS: the error surfaces and the result
			// is the ZERO value. Asserting the whole struct (not just .Incomplete) means
			// no field can be invented on this path.
			hops = nil
			res, err := (&rdapWhoisResolver{}).viaWHOIS(ctx, "example.com")
			require.Error(t, err, "a failed WHOIS lookup must surface its error")
			assert.Contains(t, err.Error(), tc.wantErrContains,
				"and it must be whoisQuery's error, propagated unwrapped-over")
			assert.Equal(t, registrantResult{}, res,
				"with no record there is nothing to describe as partial, so viaWHOIS returns the ZERO "+
					"result — a fabricated reason here would send the operator after a truncation "+
					"that never happened")
			assert.Equal(t, whoisComplete, res.Incomplete,
				"stated explicitly as well as via the zero-value check, because whoisComplete is the "+
					"zero value and that coincidence is what makes the discard safe")
			assert.Equal(t, tc.wantHops, hops, "consequence half must dial exactly the same hops")
		})
	}
}

// salvagedStubWithReferral is a post-referral WHOIS response that whoisparser
// REJECTS while still publishing an onward referral — the shape a TLD server's
// redirect stub or throttle banner has. It is the payload for the damaged-partial
// case: whoisQuery salvages it as (lastRaw, <reason>, nil), and viaWHOIS then
// fails to parse it, so the reason has to survive an ERROR return or the
// deadline / referral / hop-budget attribution is lost for exactly this input.
//
// Two properties are load-bearing, and both are asserted (never assumed) by
// TestSalvagedStubWithReferralFixture_IsRejectedYetStillReferrable below:
//
//   - No `domain[ name]:`-shaped line — in fact no "domain" substring at all.
//     BOTH of whoisparser's domain regexes (searchDomainRx1/Rx2) require a literal
//     "domain", so its absence makes searchDomain return "" and Parse bail with
//     ErrDomainDataInvalid via getDomainErrorType before a single field is read.
//     Omitting the word is what makes the rejection structural rather than
//     incidental to some phrase whoisparser happens to special-case.
//   - A "Registrar WHOIS Server:" line, one of the three prefixes extractReferral
//     accepts, so the chain still advances to a further hop and whoisQuery can
//     reach its salvage arms at all.
//
// The wording deliberately avoids every phrase in whoisparser's not-found /
// blocked / premium / reserved / limit-exceeded key lists, so the rejection is
// ErrDomainDataInvalid specifically and the fixture assertion can pin it.
const salvagedStubWithReferral = "% This WHOIS service is temporarily unable to answer your request.\n" +
	"% Please try again later.\n" +
	"Registrar WHOIS Server: whois.registrar.example\n"

// TestSalvagedStubWithReferralFixture_IsRejectedYetStillReferrable is the
// NON-VACUITY guard for the two tests below. Both of them are worthless if the
// payload actually parses: viaWHOIS would return through its success path, the
// error branch the fix lives on would never execute, and both tests would pass
// while asserting nothing about the fix. So the precondition is asserted rather
// than commented — a whois-parser bump that starts accepting this text fails
// HERE, loudly, instead of silently hollowing out the regression guards.
func TestSalvagedStubWithReferralFixture_IsRejectedYetStillReferrable(t *testing.T) {
	_, err := whoisparser.Parse(salvagedStubWithReferral)
	require.Error(t, err,
		"the fixture MUST fail to parse — a nil error here means the tests below no longer "+
			"exercise viaWHOIS's parse-error path at all")
	assert.ErrorIs(t, err, whoisparser.ErrDomainDataInvalid,
		"no domain-name line → searchDomain finds nothing → getDomainErrorType's default arm")

	assert.NotContains(t, strings.ToLower(salvagedStubWithReferral), "domain",
		"the rejection must be structural: both whoisparser domain regexes require a literal "+
			"\"domain\", so the fixture must not contain the word anywhere")
	assert.Equal(t, "whois.registrar.example", extractReferral(salvagedStubWithReferral),
		"and the record must STILL refer onward, or whoisQuery never advances far enough to salvage it")
}

// TestViaWHOIS_UnparseableSalvagedRecordKeepsItsIncompletenessReason is the
// regression guard for the confirmed Codex finding on PR #108: viaWHOIS returned
// a bare registrantResult{} alongside the parse error, discarding the
// whoisIncompleteness that whoisQuery had just reported.
//
// The damaged-partial case is where that mattered. whoisQuery's salvage arms hand
// back (lastRaw, <reason>, nil), and lastRaw is ANY post-referral response —
// including a stub or banner whoisparser rejects. verifyCandidates reads
// res.Incomplete and err TOGETHER (`outcomes[i] = candidateOutcome{incomplete:
// res.Incomplete, failed: err != nil}`), so dropping the reason on the error path
// left the pass record showing only lookup_failed: the deadline / referral /
// hop-budget attribution that ENG-5405 exists to produce was lost for precisely
// the input that needed it most.
//
// The chain is three hops because lastRaw is only ever set from a NON-defaultServer
// response: bootstrap seed → refers to the TLD server; the TLD server answers with
// the unparseable stub AND a further referral; the registrar hop dies. Both salvage
// arms are covered — the rows differ only in the ctx state at the failing hop,
// which is the sole discriminator whoisQuery classifies on.
func TestViaWHOIS_UnparseableSalvagedRecordKeepsItsIncompletenessReason(t *testing.T) {
	const (
		tldServer       = "whois.tld.example"
		registrarServer = "whois.registrar.example"
		seedRecord      = "domain: EXAMPLE.COM\nrefer: whois.tld.example\n"
	)

	tests := []struct {
		name string
		// newCtx builds the ctx viaWHOIS runs under. Both rows build an
		// expiring/cancellable one, so neither gets its verdict from the ctx's type —
		// only from whether it actually fired.
		newCtx func() (context.Context, context.CancelFunc)
		// atFailingHop runs inside the whoisRawFn stub on the registrar hop, just
		// before it fails, so the ctx state and the hop failure are simultaneous.
		// nil leaves the ctx clean.
		atFailingHop func(ctx context.Context)
		want         whoisIncompleteness
		why          string
	}{
		{
			name:   "referral hop transport failure keeps referral_failed",
			newCtx: func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			want:   whoisIncompleteReferral,
			why: "the salvaged stub could not be parsed, but the chain's failure mode is still known: " +
				"a referral hop's transport died on a CLEAN ctx. Collapsing this to a bare " +
				"lookup_failed tells the operator to resize a budget that never bound the pass",
		},
		{
			name: "deadline landing inside the failing hop keeps deadline_expired",
			newCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			// Block until the REAL deadline fires, so the deadline arm is reached by an
			// expiry observed mid-hop rather than by a convenient explicit cancel.
			atFailingHop: func(ctx context.Context) { <-ctx.Done() },
			want:         whoisIncompleteDeadline,
			why: "the same unparseable payload under an EXPIRED ctx must keep the opposite reason — " +
				"the two drive opposite operator remedies (resize the budget vs. pace the leg), so a " +
				"parse failure must not erase the distinction",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// NON-VACUITY, asserted per row: if this payload ever parses, viaWHOIS
			// returns through its success path and this row proves nothing.
			_, parseErr := whoisparser.Parse(salvagedStubWithReferral)
			require.Error(t, parseErr,
				"row precondition: the salvaged payload must be REJECTED by whoisparser, or the "+
					"error path carrying the fix never runs")
			require.NotEqual(t, whoisComplete, tc.want,
				"row precondition: a whoisComplete expectation would be satisfiable by a chain that "+
					"never truncated at all")

			ctx, cancel := tc.newCtx()
			defer cancel()

			// whoisQuery drives the hops sequentially on this goroutine, so plain
			// appends here need no synchronisation.
			var hops []string
			stubWhoisRawFn(t, func(hopCtx context.Context, domain, server string) (string, error) {
				hops = append(hops, server)
				switch server {
				case defaultServer:
					return seedRecord, nil // seed refers onward; lastRaw stays unset here
				case tldServer:
					// Post-referral, so this becomes lastRaw — and it is the payload
					// whoisparser will reject. It still refers onward, so the chain
					// continues and can reach a salvage arm.
					return salvagedStubWithReferral, nil
				case registrarServer:
					if tc.atFailingHop != nil {
						tc.atFailingHop(hopCtx)
					}
					return "", errors.New("dial tcp: connection refused")
				default:
					require.FailNowf(t, "unexpected WHOIS server", "server=%q domain=%q", server, domain)
					return "", nil
				}
			})

			res, err := (&rdapWhoisResolver{}).viaWHOIS(ctx, "example.com")

			// The discriminator, asserted per row (ctx.Err() is monotone, so reading it
			// after the call reads the value the classifier saw).
			if tc.want == whoisIncompleteDeadline {
				require.Error(t, ctx.Err(), "this row's premise is an expired ctx at the failing hop")
			} else {
				require.NoError(t, ctx.Err(), "this row's premise is a CLEAN ctx at the failing hop")
			}

			// BOTH halves are the assertion. The error is what makes the case damaging
			// (it is the branch that used to discard the reason), and the reason is what
			// the fix preserves — either one alone is satisfiable without the fix.
			require.Error(t, err, "an unparseable salvaged record must still surface the parse error")
			assert.ErrorIs(t, err, whoisparser.ErrDomainDataInvalid,
				"and it is the parse error specifically, not the hop's transport error")
			assert.Equal(t, tc.want, res.Incomplete, tc.why)

			assert.False(t, res.Found, "nothing was parsed, so no registrant was resolved")
			assert.Empty(t, res.Org)
			assert.Equal(t, []string{defaultServer, tldServer, registrarServer}, hops,
				"lastRaw is only set from a post-referral response, so the salvage requires all three hops")
		})
	}
}

// whoisOnlyResolver is a registrantResolver that runs the REAL production policy
// (resolveWithFallback) with the RDAP leg forced to miss, so every candidate lands
// on the REAL viaWHOIS while the pass stays hermetic — the only seam is the
// stubbed whoisRawFn, so no socket and no DNS. This matters for the pass-level
// test below: a hand-canned stubResolver could only RESTATE viaWHOIS's return
// shape from memory, and a stub that returns a reason alongside an error would
// keep passing even after production stopped doing so. Driving the real function
// is what makes the assertion a regression guard rather than a tautology.
type whoisOnlyResolver struct{}

func (whoisOnlyResolver) resolveRegistrant(ctx context.Context, domain string) (registrantResult, error) {
	rdapMiss := func(context.Context, string) (registrantResult, error) {
		return registrantResult{}, errors.New("rdap step disabled for this hermetic test")
	}
	// viaWHOIS never touches its receiver, so a zero-value resolver keeps this off
	// the RDAP client pool entirely.
	return resolveWithFallback(ctx, domain, rdapMiss, (&rdapWhoisResolver{}).viaWHOIS)
}

// TestVerifyCandidates_UnparseableSalvagedRecordTalliesBothFailedAndItsReason is
// the observable end state of the fix, at the level an operator actually reads:
// the pass's single degraded record. One candidate's WHOIS leg salvages a partial
// record that then fails to parse, and that ONE candidate must appear in BOTH
// lookup_failed and incomplete_referral.
//
// The overlap is the behaviour under test, not an accident: "the lookup failed AND
// the chain was known to be partial" are both true, and reporting only the first
// is the blindness the ticket removes. (summarizeVerifyPass's comment says the
// counters are not a partition; this is the case that makes that true, and it is
// safe because the buckets are only ever summed in a test-for-zero predicate.)
//
// Before the fix incomplete_referral would read 0 here while lookup_failed read 1.
// The second, clean candidate is the control: it proves the reason is attributed to
// the truncated candidate specifically and not stamped on the whole pass.
func TestVerifyCandidates_UnparseableSalvagedRecordTalliesBothFailedAndItsReason(t *testing.T) {
	logs := captureSlog(t)

	const (
		tldServer       = "whois.tld.example"
		registrarServer = "whois.registrar.example"
		seedRecord      = "domain: EXAMPLE.COM\nrefer: whois.tld.example\n"
		// A chain that runs to its natural end and carries a corroborating
		// registrant: no onward referral, so whoisComplete.
		cleanTLDRecord = "Domain Name: CLEAN.EXAMPLE.COM\n" +
			"Registrar: Example Registrar, Inc.\n" +
			"Registrant Organization: Acme Corp\n"
	)
	const (
		cleanDomain     = "clean.example.com"
		truncatedDomain = "truncated.example.com"
	)

	// Stateless by construction: the stub only reads its arguments, so the two
	// workers may drive it concurrently without synchronisation. t.Errorf (not
	// Fatalf) on an unexpected hop, because this runs on worker goroutines.
	stubWhoisRawFn(t, func(_ context.Context, domain, server string) (string, error) {
		switch {
		case server == defaultServer:
			return seedRecord, nil
		case server == tldServer && domain == cleanDomain:
			return cleanTLDRecord, nil
		case server == tldServer && domain == truncatedDomain:
			return salvagedStubWithReferral, nil // salvageable, unparseable, refers onward
		case server == registrarServer && domain == truncatedDomain:
			return "", errors.New("dial tcp: connection refused")
		default:
			t.Errorf("unexpected WHOIS hop: server=%q domain=%q", server, domain)
			return "", errors.New("unexpected hop")
		}
	})

	order := []string{cleanDomain, truncatedDomain}
	cands := make([]candidate, 0, len(order))
	for _, d := range order {
		cands = append(cands, candidate{domain: d, finding: plugins.Finding{Value: d}})
	}

	findings, err := verifyCandidates(context.Background(), whoisOnlyResolver{}, "Acme Corp", cands)
	require.NoError(t, err)
	require.Len(t, findings, len(order), "de-rank, never drop: both candidates are still emitted")

	// Literals, not the package constants — same convention as the de-rank ordering
	// tests above, so a constant edit cannot move expectation and emission together.
	wantConfidence := map[string]float64{
		cleanDomain:     0.60, // complete chain, registrant corroborates the query org
		truncatedDomain: 0.50, // nothing parsed → unverified, exactly as a plain lookup error scores
	}
	for i, d := range order {
		assert.Equal(t, d, findings[i].Value, "input order must survive the summary")
		assert.InDelta(t, wantConfidence[d], plugins.TotalConfidence(findings[i]), 0.001,
			"%s must score on registrant corroboration ALONE — the incompleteness reason is "+
				"observational and must not enter ranking", d)
	}

	rec := findLogRecord(t, logs(), verifyPassMsgDegraded)
	assert.Equal(t, slog.LevelWarn.String(), rec["level"])
	assert.EqualValues(t, 2, rec["candidates"])
	assert.EqualValues(t, 2, rec["attempted"])
	assert.EqualValues(t, 1, rec["lookup_failed"],
		"the parse error IS a failed lookup and must still be counted as one")
	assert.EqualValues(t, 1, rec["incomplete_referral"],
		"AND the same candidate keeps its reason bucket — the two counters are deliberately "+
			"NON-DISJOINT here; before the fix this read 0 and the attribution was lost")
	assert.EqualValues(t, 0, rec["incomplete_deadline"], "the failing hop ran under a clean ctx")
	assert.EqualValues(t, 0, rec["incomplete_referral_budget"], "the chain died on a hop, not on the hop budget")
	assert.EqualValues(t, 0, rec["panicked"])
	assert.False(t, hasLogRecord(logs(), verifyPassMsgClean),
		"a pass carrying a truncated candidate must never also claim it completed cleanly")
}

// TestDecideConfidence_IncompleteAndNotFoundBothScoreUnverified is AC4, the core
// guarantee: registrantResult.Incomplete is PURELY OBSERVATIONAL. Every
// incompleteness reason and a genuine no-registrant must score IDENTICALLY, so
// adding the ENG-5405 signal cannot re-rank a single finding. The band is asserted
// end-to-end through an emitted finding as well, so the de-rank-never-drop
// contract is proven at the same time as the raw score.
func TestDecideConfidence_IncompleteAndNotFoundBothScoreUnverified(t *testing.T) {
	for name, res := range map[string]registrantResult{
		"incomplete lookup (deadline mid-chain)":  {Incomplete: whoisIncompleteDeadline},
		"incomplete lookup (referral hop failed)": {Incomplete: whoisIncompleteReferral},
		"incomplete lookup (referral budget)":     {Incomplete: whoisIncompleteHops},
		"genuine no-registrant":                   {},
	} {
		res := res
		t.Run(name, func(t *testing.T) {
			got := decideConfidence("Acme Corp", res, nil)
			assert.InDelta(t, confReverseWhoisUnverified, got.Score, 0.001,
				"AC4: the ENG-5405 observability signal must not change ranking")
			assert.Equal(t, justifyReverseWhoisUnverified, got.Justification,
				"AC4: nor may it change the explanation an operator reads")

			var f plugins.Finding
			plugins.AddConfidence(&f, got.Score, got.Justification)
			assert.InDelta(t, confReverseWhoisUnverified, plugins.TotalConfidence(f), 0.001)
			assert.True(t, plugins.NeedsReview(f), "the de-rank-never-drop band is unchanged")
		})
	}
}

// verifyPassMsgClean and verifyPassMsgDegraded duplicate summarizeVerifyPass's
// message strings on purpose: they are independent literal anchors, so silently
// renaming a production log message breaks a test instead of quietly breaking
// whatever alerting keys off it.
const (
	verifyPassMsgClean    = "reverse-whois: verification pass complete"
	verifyPassMsgDegraded = "reverse-whois: verification pass degraded; some candidates were not fully verified"
)

// captureSlog installs a JSON slog handler over a buffer for the duration of the
// test and returns a closure that decodes whatever was emitted. The PREVIOUS
// default is captured and restored (rather than assuming the zero default) so
// this cannot leak into the rest of the package; log's writer/flags are restored
// too, because slog.SetDefault also rewires the log package and restoring a
// defaultHandler-backed logger deliberately does not undo that.
//
// Reading the buffer is safe without extra synchronisation: slog's handler
// serialises concurrent writes internally, and every caller below reads only
// after verifyCandidates has returned, which is downstream of the errgroup's
// g.Wait() happens-before barrier.
func captureSlog(t *testing.T) func() []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	prevLogger := slog.Default()
	prevWriter, prevFlags := log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() {
		slog.SetDefault(prevLogger)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})
	return func() []map[string]any {
		t.Helper()
		var recs []map[string]any
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var rec map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &rec),
				"emitted slog record is not valid JSON: %q", line)
			recs = append(recs, rec)
		}
		return recs
	}
}

// findLogRecord returns the one record carrying the given message, failing when
// it is absent or duplicated — "one record per pass" is part of the contract.
func findLogRecord(t *testing.T, recs []map[string]any, msg string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, r := range recs {
		if r["msg"] == msg {
			found = append(found, r)
		}
	}
	require.Len(t, found, 1, "expected exactly one %q record; emitted records: %v", msg, recs)
	return found[0]
}

// hasLogRecord reports whether any record carries the given message.
func hasLogRecord(recs []map[string]any, msg string) bool {
	for _, r := range recs {
		if r["msg"] == msg {
			return true
		}
	}
	return false
}

// TestVerifyCandidates_DegradedPassIsCountedAndEmitsEveryCandidate is the
// behavioural guard on the counter's insertion point. summarizeVerifyPass runs
// between g.Wait() and the emission loop, so this proves it OBSERVES and nothing
// more: every candidate is still emitted, in input order, with its score inside
// the needs_review band — including the ones whose WHOIS leg was truncated.
func TestVerifyCandidates_DegradedPassIsCountedAndEmitsEveryCandidate(t *testing.T) {
	logs := captureSlog(t)

	// A salvaged record that DID carry a registrant org: proof the flag is
	// orthogonal to scoring even when the truncated lookup still corroborated.
	salvagedWithOrg := org("Acme Corp")
	salvagedWithOrg.Incomplete = whoisIncompleteReferral

	stub := &stubResolver{
		byDomain: map[string]registrantResult{
			"clean-hit.example.com":    org("Acme Corp"),                      // corroborated, complete
			"truncated.example.com":    {Incomplete: whoisIncompleteReferral}, // salvaged, no registrant
			"deadline.example.com":     {Incomplete: whoisIncompleteDeadline}, // budget expired mid-chain
			"hops.example.com":         {Incomplete: whoisIncompleteHops},     // referral budget exhausted
			"salvaged-org.example.com": salvagedWithOrg,                       // truncated BUT corroborated
			"clean-miss.example.com":   org("Globex GmbH"),                    // mismatch, complete
		},
		errBy: map[string]error{"broken.example.com": errors.New("whois transport failed")},
	}
	order := []string{
		"clean-hit.example.com",
		"truncated.example.com",
		"deadline.example.com",
		"hops.example.com",
		"broken.example.com",
		"salvaged-org.example.com",
		"clean-miss.example.com",
	}
	cands := make([]candidate, 0, len(order))
	for _, d := range order {
		cands = append(cands, candidate{domain: d, finding: plugins.Finding{Value: d}})
	}

	findings, err := verifyCandidates(context.Background(), stub, "Acme Corp", cands)
	require.NoError(t, err)
	require.Len(t, findings, len(order), "a degraded pass must still emit EVERY candidate")
	// Per-candidate VALUE anchors, not just the band. The three band assertions
	// below carry de-rank-never-drop and are kept, but a band is satisfied by ANY
	// score inside it: band-only assertions still pass when incompleteness leaks
	// into the ranking (e.g. every truncated candidate pushed to the 0.40 floor
	// while staying inside [0.35, 0.65)) — precisely what "the flag is purely
	// observational and never enters scoring" forbids. Only an exact expectation
	// per candidate can catch that. salvaged-org.example.com is the load-bearing
	// row: truncated AND corroborated at once, so it proves the flag is
	// orthogonal to scoring even when both hold simultaneously.
	//
	// Literals, NOT the package constants — same convention as the de-rank
	// ordering test above, so a constant edit cannot move the expectation
	// together with the emission.
	wantConfidence := map[string]float64{
		"clean-hit.example.com":    0.60, // corroborated, complete lookup
		"truncated.example.com":    0.50, // salvaged, no registrant org -> unverified
		"deadline.example.com":     0.50, // salvaged, no registrant org -> unverified
		"hops.example.com":         0.50, // salvaged, no registrant org -> unverified
		"broken.example.com":       0.50, // lookup error -> unverified
		"salvaged-org.example.com": 0.60, // TRUNCATED yet corroborated: same as a clean hit
		"clean-miss.example.com":   0.40, // registrant org disjoint from query -> mismatch
	}
	for i, d := range order {
		assert.Equal(t, d, findings[i].Value, "input order must survive the summary")
		got := plugins.TotalConfidence(findings[i])
		assert.GreaterOrEqual(t, got, 0.35, "%s must stay above the discard floor", d)
		assert.Less(t, got, 0.65, "%s must stay inside the needs_review band", d)
		assert.True(t, plugins.NeedsReview(findings[i]), "%s must remain flagged for review", d)

		want, ok := wantConfidence[d]
		require.True(t, ok, "%s has no expected confidence: the fixture and the expectation table have drifted apart", d)
		assert.InDelta(t, want, got, 0.001,
			"%s must emit exactly %.2f — its confidence is decided by registrant corroboration ALONE, never by whether the WHOIS leg finished", d, want)
	}

	rec := findLogRecord(t, logs(), verifyPassMsgDegraded)
	assert.Equal(t, slog.LevelWarn.String(), rec["level"])
	assert.EqualValues(t, len(order), rec["candidates"])
	// "attempted", not "resolved": the key counts lookups STARTED, and this pass is
	// the proof the old name misled — every one of these seven was attempted, yet
	// several were truncated and one failed outright, so none of them "resolved".
	assert.EqualValues(t, len(order), rec["attempted"])
	assert.EqualValues(t, 1, rec["incomplete_deadline"])
	assert.EqualValues(t, 2, rec["incomplete_referral"], "truncated.example.com AND salvaged-org.example.com")
	assert.EqualValues(t, 1, rec["incomplete_referral_budget"])
	assert.EqualValues(t, 1, rec["lookup_failed"])
	assert.EqualValues(t, 0, rec["panicked"])
}

// waveBarrier releases arriving goroutines in waves of `width`, so a test can
// prove a FULL complement of workers was in flight simultaneously rather than
// hoping the scheduler overlapped them. The timeout arm is a safety valve: a
// final partial wave must never hang the suite.
type waveBarrier struct {
	width int

	mu      sync.Mutex
	waiting int
	gate    chan struct{}
}

func newWaveBarrier(width int) *waveBarrier {
	return &waveBarrier{width: width, gate: make(chan struct{})}
}

func (b *waveBarrier) arrive() {
	b.mu.Lock()
	b.waiting++
	gate := b.gate
	if b.waiting == b.width {
		b.waiting = 0
		b.gate = make(chan struct{}) // re-arm for the next wave
		close(gate)                  // the whole wave proceeds together
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	select {
	case <-gate:
	case <-time.After(5 * time.Second): // never deadlock a partial wave
	}
}

// incompleteResolver returns a canned per-domain result only AFTER synchronising
// on a wave barrier. Unlike stubResolver — whose every return is whoisComplete —
// it exists to make concurrent workers actually write the incompleteness state,
// which is the precondition for -race to have anything to say about the tally.
type incompleteResolver struct {
	barrier  *waveBarrier
	byDomain map[string]registrantResult // read-only once the pass starts
}

func (r *incompleteResolver) resolveRegistrant(_ context.Context, domain string) (registrantResult, error) {
	r.barrier.arrive()
	return r.byDomain[domain], nil
}

// TestVerifyCandidates_IncompleteTallyIsRaceFreeUnderConcurrency proves the
// per-reason tally is correct AND race-free when every worker writes it.
//
// The shape is load-bearing (ENG-5405 F5): -race is not evidence for this counter
// unless a test makes concurrent workers write it. Every pre-existing
// multi-candidate test — including TestVerifyCandidates_CapLimitsCallsNotRecall,
// which drives 501 candidates — uses a resolver that returns whoisComplete, so
// under a genuinely racy shared-scalar counter the write never happens and -race
// reports clean. Hence: 18 candidates (3 x reverseWhoisWorkers, so waves overlap
// by construction via the barrier), ALL incomplete, spanning all three reasons.
func TestVerifyCandidates_IncompleteTallyIsRaceFreeUnderConcurrency(t *testing.T) {
	logs := captureSlog(t)

	const waves = 3
	total := waves * reverseWhoisWorkers
	reasons := []whoisIncompleteness{whoisIncompleteDeadline, whoisIncompleteReferral, whoisIncompleteHops}

	byDomain := make(map[string]registrantResult, total)
	cands := make([]candidate, 0, total)
	want := map[whoisIncompleteness]int{}
	for i := 0; i < total; i++ {
		d := fmt.Sprintf("cand-%02d.example.com", i)
		reason := reasons[i%len(reasons)] // interleaved, so each wave mixes reasons
		// A resolved org on every candidate keeps the deny-list assertion below
		// non-vacuous: real PII flows through the pass it must not log.
		res := org("Acme Corp")
		res.Incomplete = reason
		byDomain[d] = res
		want[reason]++
		cands = append(cands, candidate{domain: d, finding: plugins.Finding{Value: d}})
	}
	res := &incompleteResolver{barrier: newWaveBarrier(reverseWhoisWorkers), byDomain: byDomain}

	findings, err := verifyCandidates(context.Background(), res, "Acme Corp", cands)
	require.NoError(t, err)
	require.Len(t, findings, total, "de-rank never drop: an all-incomplete pass still emits everything")

	rec := findLogRecord(t, logs(), verifyPassMsgDegraded)
	assert.Equal(t, slog.LevelWarn.String(), rec["level"])
	assert.EqualValues(t, total, rec["candidates"])
	assert.EqualValues(t, total, rec["attempted"])
	assert.EqualValues(t, want[whoisIncompleteDeadline], rec["incomplete_deadline"])
	assert.EqualValues(t, want[whoisIncompleteReferral], rec["incomplete_referral"])
	assert.EqualValues(t, want[whoisIncompleteHops], rec["incomplete_referral_budget"])
	assert.EqualValues(t, 0, rec["lookup_failed"], "no lookup returned an error")
	assert.EqualValues(t, 0, rec["panicked"], "no worker panicked")

	// The deny-list invariant on the real pass, not a hand-built one: neither the
	// resolved registrant org nor any candidate hostname may reach the record.
	raw, err := json.Marshal(rec)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "Acme", "registrant org (PII) must never be logged")
	assert.NotContains(t, string(raw), "example.com", "no candidate hostname may be logged")
}

// TestSummarizeVerifyPass_TalliesEachReasonAndLeaksNoPayload drives the summary
// directly over a hand-built []candidateOutcome covering every bucket. Two halves
// matter equally: the degraded record must break the tally out per reason, and the
// CLEAN input must still log at Info — the positive control that distinguishes
// "this pass was not degraded" from "this summary never ran at all".
func TestSummarizeVerifyPass_TalliesEachReasonAndLeaksNoPayload(t *testing.T) {
	t.Run("degraded pass warns with a per-reason breakdown", func(t *testing.T) {
		logs := captureSlog(t)
		outcomes := []candidateOutcome{
			{incomplete: whoisIncompleteDeadline},
			{incomplete: whoisIncompleteDeadline},
			{incomplete: whoisIncompleteReferral},
			{incomplete: whoisIncompleteHops},
			{failed: true},
			{panicked: true},
			{}, // one genuinely clean candidate
		}
		// budgetExpired=false: every degradation in this pass comes from a reason
		// bucket, so the pass-wide budget is not what ended it. The false case is
		// load-bearing on the Warn record — it is what lets an operator read
		// "incomplete_deadline=2 budget_expired=false" as six per-lookup timeouts
		// rather than one exhausted pass budget.
		summarizeVerifyPass(len(outcomes), len(outcomes), false, outcomes)

		recs := logs()
		assert.False(t, hasLogRecord(recs, verifyPassMsgClean),
			"a degraded pass must not ALSO claim it completed cleanly")
		rec := findLogRecord(t, recs, verifyPassMsgDegraded)
		assert.Equal(t, slog.LevelWarn.String(), rec["level"])
		assert.EqualValues(t, 7, rec["candidates"])
		assert.EqualValues(t, 7, rec["attempted"])
		assert.EqualValues(t, 2, rec["incomplete_deadline"])
		assert.EqualValues(t, 1, rec["incomplete_referral"])
		assert.EqualValues(t, 1, rec["incomplete_referral_budget"])
		assert.EqualValues(t, 1, rec["lookup_failed"])
		assert.EqualValues(t, 1, rec["panicked"])
		// budget_ms, in MILLISECONDS: this subtest leaves reverseWhoisTotalBudget at
		// its package default of 90s, so the effective budget is 90_000ms. The
		// literal is spelled out rather than derived from the var so that a change to
		// the default cannot move expectation and emission together.
		assert.EqualValues(t, 90_000, rec["budget_ms"],
			"the EFFECTIVE budget is logged, so the line is self-diagnosing")
		// lookup_timeout_ms rides beside budget_ms because a pass is bounded by
		// whichever binds first and one bound alone cannot say which. Whole
		// milliseconds, spelled as a literal: reverseWhoisLookupTimeout is 10s, so a
		// `/time.Second` divisor — the exact bug that produced the floored
		// budget_seconds this file already regression-tests below — would emit 10 here
		// and be caught.
		require.Contains(t, rec, "lookup_timeout_ms",
			"the per-lookup bound must be on the record, not only the pass-wide one")
		assert.EqualValues(t, 10_000, rec["lookup_timeout_ms"],
			"reverseWhoisLookupTimeout (10s) must report as 10000 whole milliseconds")
		// budget_expired is present-and-false, not absent: an absent field would be
		// indistinguishable from a build that never emitted it.
		require.Contains(t, rec, "budget_expired",
			"budget_expired must be emitted unconditionally, including when false")
		assert.Equal(t, false, rec["budget_expired"],
			"no pass-wide budget fired here, so the flag must not claim one did")

		// The deny-list invariant, asserted two ways. First structurally: every
		// attribute other than slog's own time/level/msg must be a COUNT or a BOOLEAN
		// FLAG, so no untrusted string can ride along in a future attribute either.
		// Both admitted shapes are information-theoretically incapable of carrying
		// attacker-influenced text: a JSON number is a tally, and a JSON bool is one
		// bit — neither can smuggle raw WHOIS payload, a registrant org (PII), or the
		// unbounded attacker-chosen referral hostname. Everything else, string
		// emphatically included, still fails here; that generality is the point, since
		// the fields this must catch have not been written yet.
		for k, v := range rec {
			switch k {
			case "time", "level", "msg":
				continue
			}
			switch v.(type) {
			case float64, bool: // counts and compile-time flags only
			default:
				assert.Failf(t, "untrusted-content deny-list violated",
					"attribute %q must be a count or a boolean flag, not text or structured data "+
						"(got %v of type %T) — counts, booleans, and compile-time constants only", k, v, v)
			}
		}
		// Then by sentinel: nothing recognisable from a WHOIS payload, a registrant
		// org, or a referral hostname may appear anywhere in the record.
		raw, err := json.Marshal(rec)
		require.NoError(t, err)
		for _, sentinel := range []string{
			"Registrant", "Registry Domain ID", "Example Registrar",
			"Acme", "REDACTED", ".example", "iana.org",
		} {
			assert.NotContains(t, string(raw), sentinel,
				"the summary must leak no WHOIS payload, registrant org, or hostname")
		}
	})

	// ENG-5405 fix A4. The degraded subtest above pins budget_ms at the 90s default,
	// where seconds and milliseconds are both non-zero and the old field looked
	// fine. This is the case that exposed the bug: int(budget/time.Second)
	// floor-divides ANY sub-second budget to 0, so the self-diagnosing denominator
	// read "budget 0s" — indistinguishable from a misconfigured budget — for a
	// budget that was perfectly valid. reverseWhoisTotalBudget is a package var
	// precisely so tests can shorten it; save/restore follows the pattern the
	// budget-expiry tests already use.
	t.Run("a sub-second budget reports whole milliseconds, not a floored zero", func(t *testing.T) {
		orig := reverseWhoisTotalBudget
		reverseWhoisTotalBudget = 250 * time.Millisecond
		defer func() { reverseWhoisTotalBudget = orig }()

		logs := captureSlog(t)
		// One failed candidate is the minimum degradation needed to reach the Warn
		// line, which is the only line carrying budget_ms. budgetExpired=true matches
		// this scenario's intent: a 250ms pass-wide budget with a lookup that did not
		// finish is a pass the budget ended, and it pins that the two budget fields
		// coexist — a shortened budget that fired must report BOTH a non-zero
		// denominator and the expiry flag, since "budget_expired=true budget_ms=0"
		// would read as a misconfigured budget rather than a small one.
		summarizeVerifyPass(1, 1, true, []candidateOutcome{{failed: true}})

		rec := findLogRecord(t, logs(), verifyPassMsgDegraded)
		require.IsType(t, float64(0), rec["budget_ms"], "budget_ms must be emitted as a count")
		// Both the exact value AND non-zero-ness, because they fail for different
		// reasons: a wrong divisor breaks the first, a seconds-truncating divisor
		// breaks both, and only the second names the operator-visible symptom.
		assert.EqualValues(t, 250, rec["budget_ms"],
			"a 250ms budget must report 250, not a value truncated toward a whole second")
		assert.Greater(t, rec["budget_ms"].(float64), float64(0),
			"a sub-second budget must never report as zero — zero reads as misconfigured")
		assert.Equal(t, true, rec["budget_expired"],
			"the flag must travel with the denominator so the line says WHICH bound fired")
		// The per-lookup bound is unaffected by shortening the pass-wide one: they are
		// independent bounds, and conflating them is what budget_expired exists to
		// prevent. reverseWhoisLookupTimeout is a const, so this stays 10000 here.
		assert.EqualValues(t, 10_000, rec["lookup_timeout_ms"],
			"shortening the pass budget must not move the per-lookup bound")
	})

	t.Run("clean pass logs at info as the positive control", func(t *testing.T) {
		logs := captureSlog(t)
		summarizeVerifyPass(3, 3, false, []candidateOutcome{{}, {}, {}})

		recs := logs()
		assert.False(t, hasLogRecord(recs, verifyPassMsgDegraded),
			"nothing was degraded, so nothing may warn")
		rec := findLogRecord(t, recs, verifyPassMsgClean)
		assert.Equal(t, slog.LevelInfo.String(), rec["level"])
		assert.EqualValues(t, 3, rec["candidates"])
		assert.EqualValues(t, 3, rec["attempted"])
		// budget_expired is on the Info record too, not just the Warn record: a clean
		// pass that the budget happened to end is still worth distinguishing from one
		// that finished with budget to spare, and an operator cannot infer it from
		// absence.
		require.Contains(t, rec, "budget_expired",
			"budget_expired must ride on the clean record as well as the degraded one")
		assert.Equal(t, false, rec["budget_expired"])
		for _, k := range []string{
			"incomplete_deadline", "incomplete_referral", "incomplete_referral_budget",
			"lookup_failed", "panicked",
		} {
			assert.NotContains(t, rec, k, "the clean line carries counts only, no zeroed reason keys")
		}
		// The two bounds are diagnostics for a pass that lost something; the clean
		// line does not carry them, so their absence here pins the split.
		for _, k := range []string{"budget_ms", "lookup_timeout_ms"} {
			assert.NotContains(t, rec, k,
				"the bound denominators belong on the degraded line, which is the one an operator debugs")
		}
		// The same structural deny-list the degraded record is held to, applied here
		// too. The absence checks above name only the keys that exist TODAY; they say
		// nothing about the type of a key added tomorrow, so without this sweep the
		// clean line is the unguarded half of the pair — and it is emitted on every
		// successful pass, which makes it the higher-volume leak if a string ever
		// lands on it. Counts and boolean flags only; slog's own time/level/msg are
		// the framing, not attributes.
		for k, v := range rec {
			switch k {
			case "time", "level", "msg":
				continue
			}
			switch v.(type) {
			case float64, bool: // counts and compile-time flags only
			default:
				assert.Failf(t, "untrusted-content deny-list violated on the CLEAN record",
					"attribute %q must be a count or a boolean flag, not text or structured data "+
						"(got %v of type %T) — the clean line is held to the same bar as the degraded one", k, v, v)
			}
		}
	})

	// ENG-5405 Phase 12. THE assertion that stops budget_expired from being folded
	// into the degraded predicate. bctx's deadline can fire in the window AFTER the
	// last worker returned and BEFORE budgetExpired is read, in which case the pass
	// lost nothing at all: every reason bucket is zero and attempted >= total. If
	// budgetExpired were a fifth arm of that predicate, this input would Warn
	// "some candidates were not fully verified" about a pass in which all of them
	// were — a false degradation manufactured out of a race, which is the same class
	// of misreporting (an untrue pass verdict) that ENG-5405 exists to remove, only
	// inverted. The flag rides as a FIELD; it never votes.
	t.Run("an expired budget on an otherwise clean pass still logs info", func(t *testing.T) {
		logs := captureSlog(t)
		summarizeVerifyPass(3, 3, true, []candidateOutcome{{}, {}, {}})

		recs := logs()
		assert.False(t, hasLogRecord(recs, verifyPassMsgDegraded),
			"budget_expired must NOT be a term in the degraded predicate: nothing was lost, "+
				"so warning here would report a degradation that did not happen")
		// findLogRecord requires exactly one match, so this also proves the summary
		// did not emit both records.
		rec := findLogRecord(t, recs, verifyPassMsgClean)
		assert.Equal(t, slog.LevelInfo.String(), rec["level"])
		assert.Equal(t, true, rec["budget_expired"],
			"the expiry is still REPORTED — not suppressed — it just does not change the verdict")
		assert.EqualValues(t, 3, rec["candidates"])
		assert.EqualValues(t, 3, rec["attempted"])
	})
}

// TestVerifyCandidates_BudgetExpiredReportsWhichBoundEndedThePass drives
// budget_expired through verifyCandidates rather than handing the bool to
// summarizeVerifyPass, so what is under test is the DERIVATION
// (`budgetExpired := errors.Is(context.Cause(bctx), errReverseWhoisBudgetExpired)`)
// and not the parameter's ability to be printed. Passing the bool in directly — as
// the summarizeVerifyPass subtests above necessarily do — cannot distinguish a
// correct derivation from a hardcoded false, which is exactly the blindness
// ENG-5405 is about.
//
// This test is one half of the guard on that derivation; the other half is
// TestReverseWhoisBudgetSentinel_DiscriminatesOwnExpiryFromAncestorCancellation,
// which pins the CAUSE comparison against every regime that can end bctx —
// including the ancestor-deadline regime whose end-to-end form is unreachable (see
// that test's comment for why). What THIS test uniquely holds is the
// context.WithTimeoutCause construction: it is the only test in which a real
// pass-budget expiry has to carry errReverseWhoisBudgetExpired as its cause, so
// reverting that call to a plain context.WithTimeout fails here.
//
// Why the field has to exist at all: whoisQuery cannot make this distinction. At
// the WHOIS layer a per-lookup reverseWhoisLookupTimeout and the pass-wide
// reverseWhoisTotalBudget are both just `ctx.Err() != nil` on a derived context, so
// both arrive as whoisIncompleteDeadline. verifyCandidates owns bctx and has
// already re-checked that the caller's ctx is clean, so it — and only it — can say
// which bound fired. The two readings send an operator opposite ways: resize the
// pass budget, or raise the per-lookup timeout.
func TestVerifyCandidates_BudgetExpiredReportsWhichBoundEndedThePass(t *testing.T) {
	cands := func(domains ...string) []candidate {
		out := make([]candidate, 0, len(domains))
		for _, d := range domains {
			out = append(out, candidate{domain: d, finding: plugins.Finding{Value: d}})
		}
		return out
	}

	t.Run("a budget that fires with lookups in flight reports true", func(t *testing.T) {
		// A budget short enough to fire while every lookup is still blocked. This is
		// the genuine article: blockingResolver holds each lookup until its context is
		// cancelled, so bctx's deadline is what ends the pass and bctx.Err() is
		// non-nil by the time the summary reads it.
		orig := reverseWhoisTotalBudget
		reverseWhoisTotalBudget = 100 * time.Millisecond
		defer func() { reverseWhoisTotalBudget = orig }()

		logs := captureSlog(t)
		in := cands("a.example.com", "b.example.com", "c.example.com", "d.example.com")

		// A live caller ctx: the expiry under test must be OUR internal budget, and a
		// cancelled caller would have aborted with an error before the summary ran.
		ctx := context.Background()
		findings, err := verifyCandidates(ctx, blockingResolver{}, "Acme Corp", in)

		require.NoError(t, err, "an INTERNAL budget expiry is recall-safe, not an error")
		require.Len(t, findings, len(in), "every candidate is still emitted (de-rank, never drop)")
		require.NoError(t, ctx.Err(),
			"the caller ctx must be clean, so budget_expired can only be reporting bctx")

		rec := findLogRecord(t, logs(), verifyPassMsgDegraded)
		assert.Equal(t, true, rec["budget_expired"],
			"the pass-wide budget is what ended this pass and the record must say so")
		// The companion counts, so the record is read as a whole rather than one field
		// in isolation: every blocked lookup returned its ctx error, so all four land
		// in the lookup_failed bucket and none in a WHOIS-incompleteness bucket (the
		// resolver never reached WHOIS).
		assert.EqualValues(t, len(in), rec["candidates"])
		assert.EqualValues(t, len(in), rec["attempted"])
		assert.EqualValues(t, len(in), rec["lookup_failed"])
		assert.EqualValues(t, 100, rec["budget_ms"],
			"the EFFECTIVE (shortened) budget is logged, which is what makes the line self-diagnosing")
		assert.EqualValues(t, 10_000, rec["lookup_timeout_ms"],
			"the per-lookup bound did NOT fire here — 100ms of budget elapsed, not 10s of lookup — "+
				"and recording both is the only way the line shows which one bound the pass")
	})

	t.Run("a pass that finishes inside its budget reports false", func(t *testing.T) {
		// The negative control, and the half that makes the assertion above
		// non-vacuous: same code path, budget left at its 90s default, lookups that
		// return immediately. A hardcoded `true` fails here; a hardcoded `false` fails
		// above.
		logs := captureSlog(t)
		res := &stubResolver{byDomain: map[string]registrantResult{
			"first.example.com":  org("Acme Corp"),
			"second.example.com": org("Acme Corp"),
		}}
		in := cands("first.example.com", "second.example.com")

		findings, err := verifyCandidates(context.Background(), res, "Acme Corp", in)
		require.NoError(t, err)
		require.Len(t, findings, len(in))

		// Both candidates corroborate, nothing failed, attempted == candidates: this
		// pass is clean, so the verdict is the Info record.
		rec := findLogRecord(t, logs(), verifyPassMsgClean)
		assert.Equal(t, slog.LevelInfo.String(), rec["level"])
		assert.Equal(t, false, rec["budget_expired"],
			"a pass that finished with budget to spare must not claim the budget fired")
	})
}

// TestVerifyCandidates_PanickingCandidateIsCountedNotSilentlyComplete is the
// direct regression test for ENG-5405 F4. The worker's deferred recover() fires
// BEFORE the outcomes[i] assignment ever runs, so without the write from inside
// the deferred func a panicking candidate would tally as complete-and-not-failed
// — and with it the only degraded candidate in this pass, the summary would flip
// to the clean Info line, reproducing ENG-5405's exact blindness inside the
// mechanism built to end it. A panic also gets its OWN bucket: it is not a WHOIS
// incompleteness and must never be conflated with one.
func TestVerifyCandidates_PanickingCandidateIsCountedNotSilentlyComplete(t *testing.T) {
	logs := captureSlog(t)
	res := &panickingResolver{
		panicOn: map[string]bool{"boom.example.com": true},
		byOK: map[string]registrantResult{
			"first.example.com": org("Acme Corp"),
			"third.example.com": org("Acme Corp"),
		},
	}
	cands := []candidate{
		{domain: "first.example.com", finding: plugins.Finding{Value: "first.example.com"}},
		{domain: "boom.example.com", finding: plugins.Finding{Value: "boom.example.com"}},
		{domain: "third.example.com", finding: plugins.Finding{Value: "third.example.com"}},
	}

	findings, err := verifyCandidates(context.Background(), res, "Acme Corp", cands)
	require.NoError(t, err)
	require.Len(t, findings, 3, "a panic on one candidate must not drop any finding")

	recs := logs()
	assert.False(t, hasLogRecord(recs, verifyPassMsgClean),
		"F4: a pass that recovered a panic must NOT report itself clean")
	rec := findLogRecord(t, recs, verifyPassMsgDegraded)
	assert.Equal(t, slog.LevelWarn.String(), rec["level"])
	assert.EqualValues(t, 1, rec["panicked"])
	assert.EqualValues(t, 3, rec["candidates"])
	assert.EqualValues(t, 0, rec["lookup_failed"], "a panic is not a lookup error")
	assert.EqualValues(t, 0, rec["incomplete_deadline"])
	assert.EqualValues(t, 0, rec["incomplete_referral"])
	assert.EqualValues(t, 0, rec["incomplete_referral_budget"],
		"a panic gets its own bucket and is never conflated with a WHOIS incompleteness")
}

// ancestorDeadlineRegime names the one row of the table below on which the old and
// new budget_expired expressions disagree. It is declared once and used twice — in
// the table and in the post-loop assertion — so the "exactly one regime disagrees"
// claim cannot drift away from the row it is about.
const ancestorDeadlineRegime = "an ANCESTOR deadline fires: the defect"

// TestReverseWhoisBudgetSentinel_DiscriminatesOwnExpiryFromAncestorCancellation is
// the ENG-5405 / PR #108 budget_expired defect (credit: Codex, P2) written as an
// executable fact, and the regression guard for the sentinel that closed it.
//
// verifyCandidates derives bctx from the CALLER's ctx, which in production carries
// the runner's own deadline. When a parent's deadline fires, Go propagates the
// cancellation down to the child carrying the PARENT's error — and that error is
// also context.DeadlineExceeded. So the old predicate
//
//	errors.Is(bctx.Err(), context.DeadlineExceeded)
//
// could not tell "bctx's own 90s pass budget fired" from "the caller's deadline
// fired": it reported budget_expired=true for a pass the pass-wide budget never
// bounded, sending an operator to resize a bound that was not the binding one. The
// fix pairs context.WithTimeoutCause with a private sentinel and reads the CAUSE,
// which only bctx's own timer can install — the predicate production exposes as
// budgetFired().
//
// The table evaluates BOTH expressions over every way bctx can reach done, and each
// row asserts both columns plus the bctx.Err()/context.Cause(bctx) pair they read.
// The load-bearing row is ancestorDeadlineRegime: old==true (wrong), new==false
// (right). Note that bctx.Err() there is byte-identical to the two real-expiry rows
// — that identity IS the defect, and it is why no amount of care with bctx.Err()
// could have fixed this. The post-loop assertion pins that exactly one regime
// disagrees and which one, so a future "simplification" back toward an Err()-shaped
// test cannot quietly re-widen the match.
//
// The new column calls the production budgetFired() rather than restating its body,
// so this is a mutation guard and not a self-fulfilling one: reverting that function
// to the errors.Is(bctx.Err(), context.DeadlineExceeded) identity match makes the
// ancestorDeadlineRegime row fail (and the post-loop assertion with it). Calling it
// also makes deleting or renaming budgetFired — or its sentinel — a compile error
// here.
//
// Why this is a unit test over the two expressions and NOT an end-to-end pass where
// a caller deadline fires and a record is still emitted: that pass does not exist.
// The window the defect lives in is between two ADJACENT statements in
// verifyCandidates — the `if err := ctx.Err(); err != nil { return nil, err }`
// re-check and the budgetExpired read a few lines later. If the caller's ctx is
// done, the re-check returns the error FIRST and summarizeVerifyPass is never
// reached, so there is no record to assert budget_expired on. Hitting the window
// deterministically would require adding a production seam (an injected hook
// between those two statements) for the sake of a log field, which is not a trade
// worth making. This gap is deliberate and reasoned, not an oversight — do not
// "fill" it with a sleep-and-hope test, which would be flaky in exchange for
// nothing. The complementary half of the production expression — the
// WithTimeoutCause construction itself — is covered end-to-end by
// TestVerifyCandidates_BudgetExpiredReportsWhichBoundEndedThePass: revert that call
// to a plain context.WithTimeout and a genuine expiry stops carrying the sentinel
// as its cause, so the flag reports false and that test fails.
//
// Hermetic and deterministic (ENG-5405 AC5): no network, no WHOIS, no RDAP, no
// resolver, and no mutation of reverseWhoisTotalBudget. Every row waits on
// <-bctx.Done() instead of sleeping a fixed slice, so the single-digit-millisecond
// deadlines carry no timing flake — a slow machine makes the wait longer, never
// wrong.
func TestReverseWhoisBudgetSentinel_DiscriminatesOwnExpiryFromAncestorCancellation(t *testing.T) {
	const (
		// soon fires promptly; far cannot fire within the test. Neither is ever slept
		// through — they are only ever waited on via <-bctx.Done().
		soon = 5 * time.Millisecond
		far  = 30 * time.Second
	)

	tests := []struct {
		name string
		// parent builds the ancestor bctx is derived from, exactly as
		// verifyCandidates receives its caller ctx. endParent is invoked AFTER the
		// child exists, so a cancelling ancestor cancels a live child rather than
		// handing WithTimeoutCause an already-done parent; it is a no-op for the rows
		// whose ancestor ends on its own timer.
		parent func(t *testing.T) (ctx context.Context, endParent func())
		// childTimeout stands in for the pass-wide reverseWhoisTotalBudget.
		childTimeout time.Duration
		// wantErr is bctx.Err() once done — what the OLD predicate read. Three of the
		// four rows agree here, which is precisely why it could not discriminate.
		wantErr error
		// wantCause is context.Cause(bctx) once done — what the NEW predicate reads.
		wantCause error
		wantOld   bool // errors.Is(bctx.Err(), context.DeadlineExceeded) — pre-fix
		wantNew   bool // budgetFired(bctx) — shipped
	}{
		{
			// A real pass-budget expiry with no ancestor bound at all: the simplest
			// form of the case budget_expired exists to report.
			name: "bctx's own timer fires with no ancestor deadline: a real budget expiry",
			parent: func(*testing.T) (context.Context, func()) {
				return context.Background(), func() {}
			},
			childTimeout: soon,
			wantErr:      context.DeadlineExceeded,
			wantCause:    errReverseWhoisBudgetExpired,
			wantOld:      true,
			wantNew:      true,
		},
		{
			// The PRODUCTION shape of a real expiry: the runner's ctx does carry a
			// deadline, the 90s budget is just nearer. Kept as its own row because a
			// parent WITH a deadline takes a different branch inside
			// context.WithDeadlineCause than a parent without one, and the fix has to
			// hold on the branch production actually takes.
			name: "bctx's own timer fires inside a FAR ancestor deadline: production shape",
			parent: func(t *testing.T) (context.Context, func()) {
				ctx, cancel := context.WithTimeout(context.Background(), far)
				t.Cleanup(cancel)
				return ctx, func() {}
			},
			childTimeout: soon,
			wantErr:      context.DeadlineExceeded,
			wantCause:    errReverseWhoisBudgetExpired,
			wantOld:      true,
			wantNew:      true,
		},
		{
			// THE defect. The ancestor's deadline fires and Go propagates it into bctx
			// with the ancestor's error, so bctx.Err() is context.DeadlineExceeded —
			// indistinguishable from the two rows above — while the pass-wide budget
			// still had ~30s left and never bounded anything. old==true is the bug
			// reported as a fact; new==false is the fix.
			name: ancestorDeadlineRegime,
			parent: func(t *testing.T) (context.Context, func()) {
				ctx, cancel := context.WithTimeout(context.Background(), soon)
				t.Cleanup(cancel)
				return ctx, func() {}
			},
			childTimeout: far,
			wantErr:      context.DeadlineExceeded,
			wantCause:    context.DeadlineExceeded,
			wantOld:      true,
			wantNew:      false,
		},
		{
			// An explicit ancestor cancel (user interrupt). The old predicate already
			// got this one right — context.Canceled is not context.DeadlineExceeded —
			// so it is the control proving the new expression did not merely trade one
			// wrong answer for another: it must still say false here.
			name: "an ANCESTOR cancel fires: not a budget expiry either",
			parent: func(t *testing.T) (context.Context, func()) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				return ctx, cancel
			},
			childTimeout: far,
			wantErr:      context.Canceled,
			wantCause:    context.Canceled,
			wantOld:      false,
			wantNew:      false,
		},
	}

	// Subtests below are sequential, so appending from inside them needs no
	// synchronization and the post-loop assertion sees a complete list.
	var disagreed []string

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			parent, endParent := tc.parent(t)

			// Constructed EXACTLY as verifyCandidates constructs it: the caller's ctx,
			// the pass-wide budget, the private sentinel as the cause. A less faithful
			// construction would not be testing the fix.
			bctx, cancelBudget := context.WithTimeoutCause(parent, tc.childTimeout, errReverseWhoisBudgetExpired)
			defer cancelBudget()

			endParent()

			// Wait for the transition instead of sleeping past it: the two expressions
			// are only meaningful once bctx is done, and context.Cause is nil before
			// then. A regime that somehow never fires hangs here and surfaces as a test
			// timeout — a loud failure, never a wrong answer read too early.
			<-bctx.Done()

			// The two expressions under comparison, evaluated on the same context in
			// the same instant. oldPredicate is the pre-fix production line written out
			// verbatim — it has to be inline, because the whole point is that it no
			// longer exists in production. newPredicate calls the SHIPPED
			// budgetFired(), not a copy of its body: that is what makes every row below
			// a live guard on production code rather than a tautology about a string
			// this test also wrote.
			oldPredicate := errors.Is(bctx.Err(), context.DeadlineExceeded)
			newPredicate := budgetFired(bctx)

			// The inputs first, so a failure below reads as "the context did something
			// unexpected" rather than "the predicate is wrong".
			require.ErrorIs(t, bctx.Err(), tc.wantErr,
				"bctx.Err() is the OLD predicate's only input; this row's regime must produce it")
			require.ErrorIs(t, context.Cause(bctx), tc.wantCause,
				"context.Cause(bctx) is the NEW predicate's only input, and WithTimeoutCause "+
					"installs the sentinel if and only if bctx's OWN timer fired")

			assert.Equal(t, tc.wantOld, oldPredicate,
				"errors.Is(bctx.Err(), context.DeadlineExceeded) — the pre-fix expression")
			assert.Equal(t, tc.wantNew, newPredicate,
				"budgetFired(bctx) — the shipped predicate; true here must mean the pass-wide "+
					"budget, and nothing else, ended the pass")

			if oldPredicate != newPredicate {
				disagreed = append(disagreed, tc.name)
			}
		})
	}

	// The whole point of the fix, stated once over the whole table: the two
	// expressions differ on exactly ONE regime, and it is the ancestor-deadline one.
	// Zero disagreements would mean the fix changed nothing (or that the
	// ancestor-deadline row stopped exercising propagation); more than one would mean
	// it changed a case it had no business changing.
	require.Equal(t, []string{ancestorDeadlineRegime}, disagreed,
		"the cause sentinel must fix the ancestor-deadline regime and ONLY that regime")
}
