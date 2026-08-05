package domains

import (
	"errors"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file is the recorded CALIBRATION BASIS for simCorroborate (0.60) and
// simMismatch (0.30) — the artifact the ENG-5374 comment block in
// reverse_whois_verify.go points at. It is deliberately corpus-free.
//
// A hand-authored fixture corpus was considered and rejected: establishing "0.60
// is the right cutoff" is a precision/recall claim at a decision boundary, and
// it needs candidate sets from the real ViewDNS/Whoxy return distribution, live
// resolved registrant strings, and per-candidate ownership labels of
// INDEPENDENT provenance. The last two are forbidden by this ticket's hermetic
// requirement, and fixtures authored here could not substitute — their labels
// would be assigned by the same judgment that chose the threshold, so any
// resulting precision figure would restate the prior while carrying the
// authority of a measurement.
//
// What IS establishable hermetically is stronger on the question that actually
// mattered, and it is established by enumeration rather than sampling: because
// tokenSimilarity is the containment coefficient m/k with k = min(kq,kc), the
// set of values it can EVER return is fully determined by k. That settles
// deductively what a labeled corpus could only have gestured at statistically —
// see TestSimilarityReachabilityByTokenCount.

// arm names for the three mutually exclusive classifications decideConfidence
// can return. They are classifications of one verification operation, not
// additive signals, so exactly one is produced per call.
const (
	armCorroborated = "corroborated"
	armUnverified   = "unverified"
	armMismatch     = "mismatch"
)

// calibrationTokens are neutral filler tokens used to construct org-name pairs
// with exact token counts. Every one is lowercase alphanumeric, so tokenize is
// the identity on a space-joined slice of them, and none appears in
// orgLegalSuffixes, so normalizeOrg strips nothing. The constructed strings
// therefore survive normalization unchanged — which newCalibrationPair asserts
// rather than assumes, so a future edit to orgLegalSuffixes that swallowed one
// of these tokens would fail loudly instead of silently changing every k in the
// enumeration below.
var calibrationTokens = []string{
	"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
	"india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
}

// newCalibrationPair builds a (query, candidate) org pair whose normalized token
// counts are both exactly k and which share exactly m tokens, so
// tokenSimilarity's containment coefficient is exactly m/k with
// k = min(kq,kc) = k.
//
// The two sides' unshared tokens are drawn from disjoint slices of
// calibrationTokens, so m is the shared count and nothing else collides. Note
// the one structural consequence the tests rely on: when m == k there are no
// unshared tokens on either side, so the two strings are IDENTICAL — that is the
// only way a constructed pair reaches decideConfidence's exact-equality
// exemption, and it is why "corroborates only at m == k" and "corroborates only
// on exact equality" are the same statement at k = 1.
func newCalibrationPair(t *testing.T, k, m int) (string, string) {
	t.Helper()
	require.GreaterOrEqual(t, k, 1, "k must be at least 1")
	require.LessOrEqual(t, m, k, "shared tokens cannot exceed the token count")
	require.LessOrEqual(t, 2*k-m, len(calibrationTokens),
		"calibrationTokens pool is too small for k=%d m=%d", k, m)

	shared := calibrationTokens[:m]
	query := strings.Join(append(append([]string{}, shared...), calibrationTokens[m:k]...), " ")
	candidate := strings.Join(append(append([]string{}, shared...), calibrationTokens[k:2*k-m]...), " ")

	require.Equal(t, query, normalizeOrg(query), "query must survive normalizeOrg unchanged")
	require.Equal(t, candidate, normalizeOrg(candidate), "candidate must survive normalizeOrg unchanged")
	require.Len(t, tokenize(query), k, "query token count")
	require.Len(t, tokenize(candidate), k, "candidate token count")
	require.Equal(t, m == k, query == candidate, "the two sides are identical exactly when m == k")
	return query, candidate
}

// newAsymmetricCalibrationPair builds a pair with DIFFERENT token counts on the
// two sides — kq on the query, kc on the candidate, sharing exactly m tokens —
// so that k = min(kq,kc) = kq while the two strings are never equal.
//
// This shape is what newCalibrationPair structurally cannot produce, and the gap
// mattered: with equal counts, the only k=1 pair that shares a token has m == k,
// which makes both sides one identical token and reaches corroboration through
// decideConfidence's exact-equality exemption rather than through the similarity
// value. So the equal-count enumeration alone cannot tell the ENG-5374 guard from
// its absence. kq=1, kc>=2, m=1 is precisely the defect's shape: containment
// divides by the shorter side, sim saturates at 1.0, and the strings differ.
func newAsymmetricCalibrationPair(t *testing.T, kq, kc, m int) (string, string) {
	t.Helper()
	require.Greater(t, kc, kq, "the candidate side must be strictly longer")
	require.GreaterOrEqual(t, kq, 1, "the query side needs at least one token")
	require.LessOrEqual(t, m, kq, "shared tokens cannot exceed the shorter side")
	require.LessOrEqual(t, kq+kc-m, len(calibrationTokens),
		"calibrationTokens pool is too small for kq=%d kc=%d m=%d", kq, kc, m)

	shared := calibrationTokens[:m]
	query := strings.Join(append(append([]string{}, shared...), calibrationTokens[m:kq]...), " ")
	candidate := strings.Join(append(append([]string{}, shared...), calibrationTokens[kq:kq+kc-m]...), " ")

	require.Equal(t, query, normalizeOrg(query), "query must survive normalizeOrg unchanged")
	require.Equal(t, candidate, normalizeOrg(candidate), "candidate must survive normalizeOrg unchanged")
	require.Len(t, tokenize(query), kq, "query token count")
	require.Len(t, tokenize(candidate), kc, "candidate token count")
	require.NotEqual(t, query, candidate,
		"unequal token counts must never produce equal strings, or the exact-equality exemption masks the guard")
	return query, candidate
}

// armForScore maps a decideConfidence score back to the arm that produced it, so
// the enumeration table can be written in terms of classifications instead of
// magic floats. Exact float comparison is correct here: the scores are returned
// verbatim from the three constants, never computed.
func armForScore(t *testing.T, score float64) string {
	t.Helper()
	switch score {
	case confReverseWhoisCorroborated:
		return armCorroborated
	case confReverseWhoisUnverified:
		return armUnverified
	case confReverseWhoisMismatch:
		return armMismatch
	}
	require.Failf(t, "unrecognized confidence score",
		"decideConfidence returned %v, which is none of its three documented outcomes", score)
	return ""
}

// assertInsideReviewBand pins the de-rank-never-drop invariant on a single
// decision: every outcome must land inside [ConfidenceLow, ConfidenceHigh) so
// the candidate is re-ranked and flagged for review, never discarded and never
// promoted to clean. It checks NeedsReview on a real finding rather than only
// the raw bounds, because NeedsReview is derived (and compares against
// ConfidenceHigh - confidenceEpsilon), so the bounds alone would not prove the
// operator-visible outcome.
func assertInsideReviewBand(t *testing.T, dec confidenceDecision, context string) {
	t.Helper()
	assert.GreaterOrEqual(t, dec.Score, plugins.ConfidenceLow,
		"%s: score must stay at or above the noise floor or the candidate is dropped", context)
	assert.Less(t, dec.Score, plugins.ConfidenceHigh,
		"%s: score must stay below ConfidenceHigh or an unverified candidate reads as clean", context)
	assert.NotEmpty(t, dec.Justification, "%s: every outcome must carry a justification", context)

	var f plugins.Finding
	plugins.AddConfidence(&f, dec.Score, dec.Justification)
	assert.True(t, plugins.NeedsReview(f), "%s: outcome must still need review", context)
}

// TestSimilarityReachabilityByTokenCount is the enumeration that confirms
// simCorroborate and simMismatch rather than moving them.
//
// sim is always m/k for k = min(kq,kc) and m in [0,k], so for each k the
// reachable value set is a fixed ladder of k+1 rationals — no cutoff can select
// between values the metric cannot produce. The table below is written out by
// hand (expected sim AND expected arm per cell) rather than recomputed from the
// production expression, so it is an independent statement of intended behavior;
// the loop checks production against it, and the derived assertions afterwards
// re-derive the headline conclusions from the table. A regression that changed
// an arm would have to be mirrored in BOTH encodings to pass.
//
// Read the k=1 rows first. That is the whole ENG-5374 result: the ladder there is
// exactly {0.0, 1.0}, the ambiguous middle arm is unreachable, and so every
// possible simCorroborate in (0,1] partitions those two values identically.
// Re-setting 0.60 to 0.7, 0.8 or 0.95 would not have changed a single verdict —
// the defect was the metric's RESOLUTION, not the threshold's value, which is why
// the fix is the exact-equality guard and the constants stay put.
func TestSimilarityReachabilityByTokenCount(t *testing.T) {
	type cell struct {
		k, m    int
		wantSim float64
		wantArm string
	}
	table := []cell{
		// k=1: ladder {0.0, 1.0}. Zero resolution — corroboration here is
		// meaningful only because the guard now demands exact equality (m == k).
		{k: 1, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 1, m: 1, wantSim: 1.0000, wantArm: armCorroborated},
		// k=2: the ambiguous arm becomes reachable, so the cutoffs start doing work.
		{k: 2, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 2, m: 1, wantSim: 0.5000, wantArm: armUnverified},
		{k: 2, m: 2, wantSim: 1.0000, wantArm: armCorroborated},
		// k=3.
		{k: 3, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 3, m: 1, wantSim: 0.3333, wantArm: armUnverified},
		{k: 3, m: 2, wantSim: 0.6667, wantArm: armCorroborated},
		{k: 3, m: 3, wantSim: 1.0000, wantArm: armCorroborated},
		// k=4: the first k at which simMismatch=0.30 is reachable with m > 0
		// (0.25 < 0.30). Below this, "mismatch" is exactly "no shared tokens".
		{k: 4, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 4, m: 1, wantSim: 0.2500, wantArm: armMismatch},
		{k: 4, m: 2, wantSim: 0.5000, wantArm: armUnverified},
		{k: 4, m: 3, wantSim: 0.7500, wantArm: armCorroborated},
		{k: 4, m: 4, wantSim: 1.0000, wantArm: armCorroborated},
		// k=5: m=3 lands exactly on simCorroborate (3.0/5.0 and the literal 0.60
		// round to the same float64), so the boundary is inclusive as written.
		{k: 5, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 5, m: 1, wantSim: 0.2000, wantArm: armMismatch},
		{k: 5, m: 2, wantSim: 0.4000, wantArm: armUnverified},
		{k: 5, m: 3, wantSim: 0.6000, wantArm: armCorroborated},
		{k: 5, m: 4, wantSim: 0.8000, wantArm: armCorroborated},
		{k: 5, m: 5, wantSim: 1.0000, wantArm: armCorroborated},
		// k=6.
		{k: 6, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 6, m: 1, wantSim: 0.1667, wantArm: armMismatch},
		{k: 6, m: 2, wantSim: 0.3333, wantArm: armUnverified},
		{k: 6, m: 3, wantSim: 0.5000, wantArm: armUnverified},
		{k: 6, m: 4, wantSim: 0.6667, wantArm: armCorroborated},
		{k: 6, m: 5, wantSim: 0.8333, wantArm: armCorroborated},
		{k: 6, m: 6, wantSim: 1.0000, wantArm: armCorroborated},
	}

	for _, c := range table {
		query, candidate := newCalibrationPair(t, c.k, c.m)

		sim := tokenSimilarity(query, candidate)
		assert.InDelta(t, c.wantSim, sim, 0.0001,
			"k=%d m=%d: similarity must be exactly m/k", c.k, c.m)

		dec := decideConfidence(query, org(candidate), nil)
		assert.Equal(t, c.wantArm, armForScore(t, dec.Score),
			"k=%d m=%d (sim=%.4f): wrong arm selected", c.k, c.m, sim)
		assertInsideReviewBand(t, dec, "k/m enumeration")
	}

	// The same ladder, now with UNEQUAL token counts, which is where containment's
	// min() denominator is load-bearing and where the ENG-5374 defect actually
	// lived. sim is still m/k for k = min(kq,kc) — the ladder does not change — but
	// the two sides are never equal, so the exact-equality exemption cannot fire
	// and each row reports what the similarity value alone decides.
	//
	// The kq=1 rows are the defect verbatim: "Apple" against a longer unrelated
	// name saturates at 1.0 and, pre-fix, corroborated. Post-fix they are
	// unverified. The kq>=2 rows record the deliberately OUT-OF-SCOPE class:
	// full containment still saturates to 1.0 and still corroborates there, which
	// is intended (crossing the cutoff at k>=2 requires m>=2 genuinely shared
	// tokens) and is pinned here so narrowing or widening that scope is a visible
	// change rather than a silent one.
	asymmetric := []struct {
		kq, kc, m int
		wantSim   float64
		wantArm   string
	}{
		{kq: 1, kc: 2, m: 1, wantSim: 1.0000, wantArm: armUnverified},
		{kq: 1, kc: 3, m: 1, wantSim: 1.0000, wantArm: armUnverified},
		{kq: 1, kc: 5, m: 1, wantSim: 1.0000, wantArm: armUnverified},
		{kq: 1, kc: 3, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{kq: 2, kc: 4, m: 2, wantSim: 1.0000, wantArm: armCorroborated},
		{kq: 2, kc: 5, m: 1, wantSim: 0.5000, wantArm: armUnverified},
		{kq: 3, kc: 6, m: 3, wantSim: 1.0000, wantArm: armCorroborated},
		{kq: 3, kc: 6, m: 1, wantSim: 0.3333, wantArm: armUnverified},
		{kq: 4, kc: 8, m: 1, wantSim: 0.2500, wantArm: armMismatch},
	}

	for _, c := range asymmetric {
		query, candidate := newAsymmetricCalibrationPair(t, c.kq, c.kc, c.m)

		sim := tokenSimilarity(query, candidate)
		assert.InDelta(t, c.wantSim, sim, 0.0001,
			"kq=%d kc=%d m=%d: similarity must be m/min(kq,kc)", c.kq, c.kc, c.m)

		dec := decideConfidence(query, org(candidate), nil)
		assert.Equal(t, c.wantArm, armForScore(t, dec.Score),
			"kq=%d kc=%d m=%d (sim=%.4f): wrong arm selected", c.kq, c.kc, c.m, sim)
		assertInsideReviewBand(t, dec, "asymmetric enumeration")

		// The two rules the guard encodes, stated directly and checked against
		// PRODUCTION rather than against this table's own wantArm. That is the point:
		// the row assertion above pins production to the table, while these pin
		// production to the rule, so relaxing a kq=1 row's expectation to make a
		// regression pass still fails here.
		if c.kq == 1 && c.m == 1 {
			assert.Equal(t, armUnverified, armForScore(t, decideConfidence(query, org(candidate), nil).Score),
				"kq=1 with a shared token but no exact equality must never corroborate (ENG-5374)")
		}
		if c.m == c.kq && c.kq >= minCorroborateTokens {
			assert.Equal(t, armCorroborated, armForScore(t, decideConfidence(query, org(candidate), nil).Score),
				"full containment at k>=%d is deliberately still corroboration", minCorroborateTokens)
		}
	}

	// Derived result 1 — the decisive ENG-5374 finding. At k=1 the reachable
	// ladder is {0.0, 1.0} and NOTHING lands in the ambiguous arm, so the cutoff
	// value is not what separates those two outcomes.
	var k1Sims []float64
	var k1CorroboratingM, k1UnverifiedM []int
	for _, c := range table {
		if c.k != 1 {
			continue
		}
		k1Sims = append(k1Sims, c.wantSim)
		switch c.wantArm {
		case armCorroborated:
			k1CorroboratingM = append(k1CorroboratingM, c.m)
		case armUnverified:
			k1UnverifiedM = append(k1UnverifiedM, c.m)
		}
	}
	assert.Equal(t, []float64{0.0, 1.0}, k1Sims,
		"at k=1 the reachable similarity set must be exactly {0.0, 1.0}")
	assert.Empty(t, k1UnverifiedM,
		"at k=1 the ambiguous arm must be unreachable through the similarity value")

	// Derived result 2 — what the guard bought. At k=1 corroboration happens ONLY
	// on exact token equality. The claim has two halves and they are verified by
	// the two tables: equality still corroborates (the m == k row of the
	// equal-count table below), and a shared token WITHOUT equality does not (the
	// kq=1 rows of the asymmetric table above — the equal-count construction
	// cannot express that shape, which is why the asymmetric table exists).
	// Pre-fix, any single shared token corroborated.
	assert.Equal(t, []int{1}, k1CorroboratingM,
		"at k=1 corroboration must require exact equality (m == k), not merely a shared token")

	// Derived result 3 — why k >= 2 is deliberately left alone. Crossing
	// simCorroborate there always requires at least two shared normalized tokens,
	// which is genuine corroborating evidence rather than a saturation artifact.
	for _, c := range table {
		if c.k >= 2 && c.wantArm == armCorroborated {
			assert.GreaterOrEqual(t, c.m, 2,
				"k=%d: corroborating at k>=2 must require m>=2 shared tokens", c.k)
		}
	}

	// Derived result 4 — and the ambiguous arm IS reachable at every k >= 2, so
	// the cutoffs retain real discriminating power outside the k=1 regime. That is
	// the other half of the reason the k>=2 saturation class was left out of scope.
	for k := 2; k <= 6; k++ {
		reachable := false
		for _, c := range table {
			if c.k == k && c.wantArm == armUnverified {
				reachable = true
			}
		}
		assert.True(t, reachable, "k=%d: the ambiguous arm must be reachable", k)
	}

	// Derived result 5 — the recorded KNOWN LIMITATION, unchanged by this fix:
	// below k=4, simMismatch=0.30 is reachable only at m=0, so in that range
	// "mismatch" means precisely "no shared tokens at all" and the 0.30 value
	// itself does no work. Not fixed here: it never mis-ranks (every outcome above
	// is inside the review band), and fixing it means changing the shared
	// tokenSimilarity, which github_org's floor assertion forbids and this ticket
	// does not scope.
	firstKWithSharedTokenMismatch := 0
	for _, c := range table {
		if c.wantArm != armMismatch || c.m == 0 {
			continue
		}
		if firstKWithSharedTokenMismatch == 0 || c.k < firstKWithSharedTokenMismatch {
			firstKWithSharedTokenMismatch = c.k
		}
	}
	assert.Equal(t, 4, firstKWithSharedTokenMismatch,
		"simMismatch must first become reachable with a shared token at k=4")
}

// TestDecideConfidenceEveryReturnPointStaysInsideTheReviewBand proves the
// de-rank-never-drop invariant across every path out of decideConfidence.
//
// decideConfidence has five return statements — the
// lookupErr/masked/empty-org guard, the empty-after-normalization guard, and the
// three switch arms. Every one is exercised below, every one must land inside
// [ConfidenceLow, ConfidenceHigh), and every one declares the arm it expects.
//
// Two distinct claims, deliberately kept apart. The per-case wantArm is the
// behavioral assertion, checked against production. The closing Len(covered, 5)
// is only a claim about this table's SHAPE — that five distinct return-point
// labels are enumerated — because three of the five (both guards and the default
// arm) return the same unverified value, so the return point taken cannot be
// recovered from the score.
//
// Be exact about that closing assertion's reach, because an earlier version of
// this comment overclaimed it (PR #127 review). `covered` is keyed on the
// returnPoint label DECLARED IN THE TABLE BELOW, never on anything production
// reports, so the assertion observes this table and nothing else: it fires when a
// label is added to — or dropped from — the cases without the expected count
// being updated to match. It does NOT observe decideConfidence. A sixth `return`
// statement added there with no case here leaves `covered` at five keys and this
// assertion still passing, so keeping the count in step with decideConfidence's
// actual return statements stays a MANUAL step. And the labels are declarations
// either way: the assertion cannot prove which return point ran.
func TestDecideConfidenceEveryReturnPointStaysInsideTheReviewBand(t *testing.T) {
	cases := []struct {
		name        string
		returnPoint string
		wantArm     string
		queryOrg    string
		res         registrantResult
		lookupErr   error
	}{
		{
			name:        "lookup failed outright",
			returnPoint: "guard: lookupErr/masked/empty-org",
			wantArm:     armUnverified,
			queryOrg:    "Alpha Bravo",
			res:         registrantResult{},
			lookupErr:   errors.New("rdap and whois both failed"),
		},
		{
			name:        "registrant behind a privacy service",
			returnPoint: "guard: lookupErr/masked/empty-org",
			wantArm:     armUnverified,
			queryOrg:    "Alpha Bravo",
			res:         org("REDACTED FOR PRIVACY"),
		},
		{
			name:        "no registrant org on record",
			returnPoint: "guard: lookupErr/masked/empty-org",
			wantArm:     armUnverified,
			queryOrg:    "Alpha Bravo",
			res:         registrantResult{},
		},
		{
			// UNVERIFIABLE, not a mismatch: an all-suffix org normalizes to nothing,
			// so similarity is undefined and must score mid-band rather than bottom.
			name:        "query side normalizes to nothing",
			returnPoint: "guard: empty after normalization",
			wantArm:     armUnverified,
			queryOrg:    "Co., Ltd.",
			res:         org("Alpha Bravo"),
		},
		{
			name:        "candidate side normalizes to nothing",
			returnPoint: "guard: empty after normalization",
			wantArm:     armUnverified,
			queryOrg:    "Alpha Bravo",
			res:         org("Co., Ltd."),
		},
		{
			name:        "corroborated",
			returnPoint: "arm: corroborate",
			wantArm:     armCorroborated,
			queryOrg:    "Alpha Bravo",
			res:         org("Alpha Bravo"),
		},
		{
			name:        "clear mismatch",
			returnPoint: "arm: mismatch",
			wantArm:     armMismatch,
			queryOrg:    "Alpha",
			res:         org("Bravo"),
		},
		{
			name:        "ambiguous partial overlap",
			returnPoint: "arm: default",
			wantArm:     armUnverified,
			queryOrg:    "Alpha Bravo",
			res:         org("Alpha Charlie"),
		},
		{
			// ENG-5374 reaches the same default arm, and that is the point: a
			// saturated k=1 similarity and a genuine partial overlap are both "could
			// not corroborate", so they share one PII-free justification. This is also
			// the row that fails if the guard is reverted — the score alone would go
			// back to 0.60, which is still inside the band, so the band assertion
			// could not have caught it.
			name:        "saturated k=1 similarity (ENG-5374)",
			returnPoint: "arm: default",
			wantArm:     armUnverified,
			queryOrg:    "Apple",
			res:         org("Apple Tree Landscaping"),
		},
	}

	covered := make(map[string]bool, 5)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := decideConfidence(tc.queryOrg, tc.res, tc.lookupErr)
			assert.Equal(t, tc.wantArm, armForScore(t, dec.Score),
				"%s: wrong classification", tc.returnPoint)
			assertInsideReviewBand(t, dec, tc.returnPoint)

			// The resolved registrant string is WHOIS/RDAP PII this plugin declines to
			// log, so no justification may reproduce it. Checked at every return
			// point, not only the ones that read the string.
			if tc.res.Org != "" {
				assert.NotContains(t, strings.ToLower(dec.Justification), strings.ToLower(tc.res.Org),
					"justification must never reproduce the resolved registrant")
			}
		})
		covered[tc.returnPoint] = true
	}

	assert.Len(t, covered, 5,
		"this table must enumerate all five decideConfidence return points; a new one needs a case here")
}

// TestTokenSimilaritySaturatesUnderUnmatchedTokens pins the metric defect itself
// so the reasoning recorded in reverse_whois_verify.go cannot rot away from the
// code.
//
// Containment divides by min(kq,kc), discarding the longer side's unmatched
// tokens, so the value is invariant under adding DISCONFIRMING evidence: every
// longer superstring of "Apple" scores exactly 1.0. That violates specificity
// monotonicity — a similarity feeding a threshold must be non-increasing when
// unmatched tokens are added to either side.
//
// The test asserts both halves deliberately: the metric still saturates
// (tokenSimilarity is shared with github_org and was left byte-identical, so this
// is documented behavior, not a bug to be fixed here) AND decideConfidence no
// longer corroborates on it. If someone "fixes" the metric instead, the first
// assertion fails and forces the github_org blast radius to be considered.
func TestTokenSimilaritySaturatesUnderUnmatchedTokens(t *testing.T) {
	unrelated := []string{
		"Apple Tree Landscaping",
		"Apple Tree Landscaping Of Tampa Bay",
		"Apple Tree Landscaping Of Tampa Bay And Sarasota County",
	}
	for _, candidate := range unrelated {
		nq, nc := normalizeOrg("Apple"), normalizeOrg(candidate)
		assert.InDelta(t, 1.0, tokenSimilarity(nq, nc), 1e-9,
			"containment still saturates at 1.0 for %q — the metric is unchanged", candidate)

		dec := decideConfidence("Apple", org(candidate), nil)
		assert.InDelta(t, confReverseWhoisUnverified, dec.Score, 1e-9,
			"%q must not corroborate: k=1 gives the metric no resolution", candidate)
		assertInsideReviewBand(t, dec, "saturated k=1")
	}

	// The contrast case, and the reason the exemption is load-bearing: a genuine
	// single-token match still corroborates, because normalizeOrg strips the legal
	// form and both sides reduce to one IDENTICAL token. A bare k>=2 floor without
	// the exemption would de-rank exactly the matches this plugin exists to find.
	for _, legitimate := range []struct{ queryOrg, registrant string }{
		{"Praetorian", "Praetorian Inc"},
		{"Acme", "Acme Corp"},
		{"Walmart", "Walmart Incorporated"},
	} {
		dec := decideConfidence(legitimate.queryOrg, org(legitimate.registrant), nil)
		assert.InDelta(t, confReverseWhoisCorroborated, dec.Score, 1e-9,
			"%q vs %q reduces to identical tokens and must still corroborate",
			legitimate.queryOrg, legitimate.registrant)
		assertInsideReviewBand(t, dec, "exact equality after suffix stripping")
	}
}

// TestTokenSimilarityIsMonotonicInSharedTokens pins that for a fixed token count
// the metric strictly increases as shared tokens replace unshared ones. Without
// this, a "shares more tokens" pair could score no better than a "shares fewer"
// pair and the cutoffs would be ordering nothing — it is the property that makes
// a threshold on this quantity coherent at all, for every k where the metric has
// resolution.
func TestTokenSimilarityIsMonotonicInSharedTokens(t *testing.T) {
	for k := 1; k <= 6; k++ {
		previous := -1.0
		for m := 0; m <= k; m++ {
			query, candidate := newCalibrationPair(t, k, m)
			sim := tokenSimilarity(query, candidate)
			assert.Greater(t, sim, previous,
				"k=%d m=%d: similarity must strictly increase as shared tokens are added", k, m)
			previous = sim
		}
	}
}

// TestCorroborationIsSymmetricUnderArgumentSwap pins that which side is the query
// and which is the resolved registrant cannot change the verdict. It matters
// because the guard is the only place a length comparison entered the decision:
// min() and == are both symmetric, so the property must hold, and an asymmetric
// reformulation (say, keying on the QUERY's token count alone) would silently
// make a candidate's score depend on lookup direction. The unequal-length pairs
// are the ones that would actually catch it — that is where min() is load-bearing.
func TestCorroborationIsSymmetricUnderArgumentSwap(t *testing.T) {
	assertSymmetric := func(t *testing.T, a, b string) {
		t.Helper()
		assert.InDelta(t, tokenSimilarity(a, b), tokenSimilarity(b, a), 1e-9,
			"tokenSimilarity(%q, %q) must be symmetric", a, b)
		assert.Equal(t, corroborationHasResolution(a, b), corroborationHasResolution(b, a),
			"corroborationHasResolution(%q, %q) must be symmetric", a, b)
		assert.InDelta(t,
			decideConfidence(a, org(b), nil).Score,
			decideConfidence(b, org(a), nil).Score, 1e-9,
			"decideConfidence must not depend on which of %q/%q was the query", a, b)
	}

	for k := 1; k <= 6; k++ {
		for m := 0; m <= k; m++ {
			query, candidate := newCalibrationPair(t, k, m)
			assertSymmetric(t, query, candidate)
		}
	}

	for _, pair := range [][2]string{
		{"alpha", "alpha bravo charlie"},
		{"alpha bravo", "alpha bravo charlie delta echo"},
		{"alpha bravo", "charlie delta echo"},
		{"alpha bravo charlie", "alpha bravo delta echo foxtrot golf"},
	} {
		assertSymmetric(t, pair[0], pair[1])
	}
}
