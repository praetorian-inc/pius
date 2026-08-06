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
// jaccardTokenSets is m/|union| = m/(kq+kc-m) over DISTINCT token sets, the set
// of values it can EVER return is fully determined by the shape (kq,kc,m). That
// settles deductively what a labeled corpus could only have gestured at
// statistically — see TestJaccardReachabilityByTokenCount.

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
// jaccardTokenSets is exactly m/(2k-m).
//
// The two sides' unshared tokens are drawn from disjoint slices of
// calibrationTokens, so m is the shared count and nothing else collides. Every
// token on a side is also distinct, so the constructed multiset and the DISTINCT
// set that Jaccard actually consumes coincide — every count below is a set size,
// and no row can be inflated by a repeated token (see Derived result 3, where
// that distinction is the whole point).
//
// Note the one structural consequence the tests rely on: when m == k there are no
// unshared tokens on either side, so the two strings are IDENTICAL and Jaccard is
// exactly 1.0. At k = 1 that is the only way a constructed equal-count pair leaves
// 0.0, which is why "corroborates only at m == k" and "corroborates only on
// identical token sets" are the same statement there.
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
// so jaccardTokenSets is m/(kq+kc-m) while the two strings are never equal.
//
// This shape is what newCalibrationPair structurally cannot produce, and the gap
// matters twice over.
//
// First, with equal counts the only k=1 pair that shares a token has m == k, which
// makes both sides one identical token — so the equal-count enumeration alone
// cannot separate "shares a token" from "is the same name". kq=1, kc>=2, m=1 is
// precisely the ENG-5374 defect's shape: the strings differ, and the retired
// containment coefficient divided by the shorter side and saturated at 1.0 there.
//
// Second, this is the ONLY construction here that produces pure containment — m ==
// kq means the query's token set is a strict subset of the candidate's — which is
// the case tokenSetContained exists to recognize (ENG-5172). An equal-count pair is
// contained only when it is identical, so without this shape the guard would be
// untestable through these helpers.
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

// TestJaccardReachabilityByTokenCount is the enumeration that confirms
// simCorroborate and simMismatch rather than moving them.
//
// sim is always m/(kq+kc-m) over DISTINCT token sets, so for each shape (kq,kc)
// the reachable value set is a fixed ladder of min(kq,kc)+1 rationals — no cutoff
// can select between values the metric cannot produce. The table below is written
// out by hand (expected sim AND expected arm per cell) rather than recomputed from
// the production expression, so it is an independent statement of intended
// behavior; the loop checks production against it, and the derived assertions
// afterwards re-derive the headline conclusions from the table. A regression that
// changed an arm would have to be mirrored in BOTH encodings to pass.
//
// Read the kq=kc=1 rows first. That is the whole ENG-5374 result, and it survived
// PR #122's metric swap untouched because it never depended on WHICH metric was
// used: the ladder at one token per side is exactly {0.0, 1.0} — containment gave
// m/1, Jaccard gives m/(2-m), and both collapse to the same two-point set — the
// ambiguous middle arm is unreachable, and so every possible simCorroborate in
// (0,1] partitions those two values identically. Re-setting 0.60 to 0.7, 0.8 or
// 0.95 would not have changed a single verdict. That is why neither ENG-5374 nor
// ENG-5172 was a threshold re-tuning: the defect was the metric's RESOLUTION, so
// both tickets changed what is measured and left the constants where they were.
func TestJaccardReachabilityByTokenCount(t *testing.T) {
	type cell struct {
		k, m    int
		wantSim float64
		wantArm string
	}
	table := []cell{
		// k=1: ladder {0.0, 1.0}. Zero resolution — the only equal-count pair that
		// corroborates here is one whose token sets are identical (m == k).
		{k: 1, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 1, m: 1, wantSim: 1.0000, wantArm: armCorroborated},
		// k=2: the ambiguous arm becomes reachable, so the cutoffs start doing work.
		{k: 2, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 2, m: 1, wantSim: 0.3333, wantArm: armUnverified},
		{k: 2, m: 2, wantSim: 1.0000, wantArm: armCorroborated},
		// k=3: the first equal-count k at which simMismatch=0.30 is reachable WITH a
		// shared token (0.20 < 0.30). Below this, "mismatch" means exactly "no shared
		// tokens". Under the retired containment coefficient that k was 4, so the
		// known limitation SHRANK rather than moved — see Derived result 5.
		{k: 3, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 3, m: 1, wantSim: 0.2000, wantArm: armMismatch},
		{k: 3, m: 2, wantSim: 0.5000, wantArm: armUnverified},
		{k: 3, m: 3, wantSim: 1.0000, wantArm: armCorroborated},
		// k=4: m=3 lands exactly ON simCorroborate — 3.0/5.0 and the literal 0.60 are
		// the same float64 — so the boundary is INCLUSIVE as written (`sim >=`). This
		// is the one cell where flipping `>=` to `>` changes an arm.
		{k: 4, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 4, m: 1, wantSim: 0.1429, wantArm: armMismatch},
		{k: 4, m: 2, wantSim: 0.3333, wantArm: armUnverified},
		{k: 4, m: 3, wantSim: 0.6000, wantArm: armCorroborated},
		{k: 4, m: 4, wantSim: 1.0000, wantArm: armCorroborated},
		// k=5.
		{k: 5, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 5, m: 1, wantSim: 0.1111, wantArm: armMismatch},
		{k: 5, m: 2, wantSim: 0.2500, wantArm: armMismatch},
		{k: 5, m: 3, wantSim: 0.4286, wantArm: armUnverified},
		{k: 5, m: 4, wantSim: 0.6667, wantArm: armCorroborated},
		{k: 5, m: 5, wantSim: 1.0000, wantArm: armCorroborated},
		// k=6.
		{k: 6, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{k: 6, m: 1, wantSim: 0.0909, wantArm: armMismatch},
		{k: 6, m: 2, wantSim: 0.2000, wantArm: armMismatch},
		{k: 6, m: 3, wantSim: 0.3333, wantArm: armUnverified},
		{k: 6, m: 4, wantSim: 0.5000, wantArm: armUnverified},
		{k: 6, m: 5, wantSim: 0.7143, wantArm: armCorroborated},
		{k: 6, m: 6, wantSim: 1.0000, wantArm: armCorroborated},
	}

	for _, c := range table {
		query, candidate := newCalibrationPair(t, c.k, c.m)
		qTokens, cTokens := normalizeOrgTokens(query), normalizeOrgTokens(candidate)

		sim := jaccardTokenSets(qTokens, cTokens)
		assert.InDelta(t, c.wantSim, sim, 0.0001,
			"k=%d m=%d: similarity must be exactly m/(2k-m)", c.k, c.m)

		dec := decideConfidence(query, org(candidate), nil)
		assert.Equal(t, c.wantArm, armForScore(t, dec.Score),
			"k=%d m=%d (sim=%.4f): wrong arm selected", c.k, c.m, sim)
		assertInsideReviewBand(t, dec, "k/m enumeration")

		// tokenSetContained is the ENG-5172 guard that holds an UNDER-SPECIFIED
		// candidate out of the de-rank arm. On equal-count pairs it can only fire
		// when the two sides are identical — a strict subset needs a strictly
		// smaller set — so it never rescues a row in THIS table, and every arm above
		// is decided by the value alone. Pinned against production because Derived
		// result 5 and the paired-contrast test both depend on that being true here.
		assert.Equal(t, c.m == c.k, tokenSetContained(qTokens, cTokens),
			"k=%d m=%d: equal-count pairs must be contained exactly when identical", c.k, c.m)
	}

	// The same metric with UNEQUAL token counts — where the retired containment
	// coefficient's min() denominator was load-bearing, where the ENG-5374 defect
	// lived, and the only shape these helpers can build that is PURE CONTAINMENT.
	// sim is still m/(kq+kc-m), but the two sides are never equal, so no row reaches
	// 1.0 and each one reports what the value AND the tokenSetContained guard decide
	// between them.
	//
	// Two classes to read deliberately, because PR #122 moved both:
	//
	//   - The kq=1 rows are the ENG-5374 defect verbatim. Pre-#122, a one-token query
	//     against a longer unrelated name divided by the shorter side and saturated at
	//     1.0, so it corroborated. Now it scores 1/kc.
	//   - The m == kq rows at kq>=2 are the class the old table pinned as
	//     deliberately OUT OF SCOPE, recording that full containment "still
	//     corroborates" at 1.0. That is the behavior #122 CHANGED: containment now
	//     scores exactly kq/kc, so these land in the ambiguous arm instead.
	//
	// Note {kq:1, kc:5, m:1}: 0.2000 is BELOW simMismatch, and it is unverified only
	// because tokenSetContained holds it out of the de-rank arm. Its non-contained
	// sibling {kq:2, kc:5, m:1} is a mismatch at a nearby value. That pair is the
	// entire case for the guard and is isolated in
	// TestJaccardContainmentGuardIsWhatSeparatesUnderSpecifiedFromDisagreeing.
	asymmetric := []struct {
		kq, kc, m int
		wantSim   float64
		wantArm   string
	}{
		{kq: 1, kc: 2, m: 1, wantSim: 0.5000, wantArm: armUnverified},
		{kq: 1, kc: 3, m: 1, wantSim: 0.3333, wantArm: armUnverified},
		{kq: 1, kc: 5, m: 1, wantSim: 0.2000, wantArm: armUnverified},
		{kq: 1, kc: 3, m: 0, wantSim: 0.0000, wantArm: armMismatch},
		{kq: 2, kc: 4, m: 2, wantSim: 0.5000, wantArm: armUnverified},
		{kq: 2, kc: 5, m: 1, wantSim: 0.1667, wantArm: armMismatch},
		{kq: 3, kc: 6, m: 3, wantSim: 0.5000, wantArm: armUnverified},
		{kq: 3, kc: 6, m: 1, wantSim: 0.1250, wantArm: armMismatch},
		{kq: 4, kc: 8, m: 1, wantSim: 0.0909, wantArm: armMismatch},
	}

	for _, c := range asymmetric {
		query, candidate := newAsymmetricCalibrationPair(t, c.kq, c.kc, c.m)
		qTokens, cTokens := normalizeOrgTokens(query), normalizeOrgTokens(candidate)

		sim := jaccardTokenSets(qTokens, cTokens)
		assert.InDelta(t, c.wantSim, sim, 0.0001,
			"kq=%d kc=%d m=%d: similarity must be m/(kq+kc-m)", c.kq, c.kc, c.m)

		dec := decideConfidence(query, org(candidate), nil)
		assert.Equal(t, c.wantArm, armForScore(t, dec.Score),
			"kq=%d kc=%d m=%d (sim=%.4f): wrong arm selected", c.kq, c.kc, c.m, sim)
		assertInsideReviewBand(t, dec, "asymmetric enumeration")

		// Pure containment is exactly m == kq on this construction: the query side's
		// tokens are distinct and m of them are the shared prefix, so the query's set
		// is a subset of the candidate's precisely when none of it is unshared.
		assert.Equal(t, c.m == c.kq, tokenSetContained(qTokens, cTokens),
			"kq=%d kc=%d m=%d: contained exactly when the query side is fully shared",
			c.kq, c.kc, c.m)

		// The two rules the decision encodes, stated directly and checked against
		// PRODUCTION rather than against this table's own wantArm. That is the point:
		// the row assertion above pins production to the table, while these pin
		// production to the rule, so relaxing a row's expectation to make a
		// regression pass still fails here.
		if c.kq == 1 && c.m == 1 {
			assert.Equal(t, armUnverified, armForScore(t, decideConfidence(query, org(candidate), nil).Score),
				"kq=1 with a shared token but unequal token sets must never corroborate (ENG-5374)")
		}
		if c.m == c.kq && c.kq >= 2 {
			// INVERTED by PR #122, deliberately. This assertion used to demand
			// armCorroborated and called full containment at kq>=2 "deliberately still
			// corroboration" — which was the containment coefficient saturating to 1.0
			// while the candidate carried kc-kq tokens of DISCONFIRMING evidence.
			// Jaccard is specificity-monotone, so it counts those tokens: containment
			// now scores kq/kc and the pair reads as UNDER-SPECIFIED rather than
			// confirmed. This is a behavior change, not a bug fix to the test.
			//
			// Scope the claim honestly: both rows of this class here have kc == 2*kq,
			// hence exactly 0.5. Containment as such no longer forces any particular
			// arm — a kq=3, kc=4, m=3 row would corroborate at 0.75, on the VALUE and
			// not on being contained. What #122 removed is containment's power to
			// corroborate REGARDLESS of how much longer the candidate is.
			assert.Equal(t, armUnverified, armForScore(t, decideConfidence(query, org(candidate), nil).Score),
				"full containment at kq=%d kc=%d must no longer corroborate under Jaccard (PR #122)",
				c.kq, c.kc)
		}
	}

	// Derived result 1 — the decisive ENG-5374 finding, and the reason neither
	// ENG-5374 nor ENG-5172 is a threshold re-tuning. At kq=kc=1 the reachable ladder
	// is exactly {0.0, 1.0} and NOTHING lands in the ambiguous arm, so the cutoff
	// VALUE is not what separates those two outcomes.
	//
	// State it as METRIC-INDEPENDENT, because it is: containment returned m/1 there
	// and Jaccard returns m/(2-m), and both produce the same two-point set at one
	// token per side. So the cutoffs have zero discriminating power at k=1 for EVERY
	// value in (0,1] — under either metric, before #122 and after it. A ticket
	// reaching for a different constant would have been reaching for the one knob
	// that provably cannot move this case, which is why both tickets changed what is
	// measured instead.
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

	// Derived result 2 — the ONLY shape that corroborates on a single shared token is
	// kq=kc=1. Both halves are verified across the two tables: identical token sets
	// still corroborate (the m == k row of the equal-count table), and a shared token
	// WITHOUT set equality does not (the kq=1 rows of the asymmetric table — the
	// equal-count construction cannot express that shape, which is why the asymmetric
	// table exists). Pre-#122, every one of those kq=1 rows corroborated.
	assert.Equal(t, []int{1}, k1CorroboratingM,
		"at k=1 corroboration must require identical token sets (m == k), not merely a shared token")

	// Record the CLOSED FORM so this reads as exact rather than as a limit on how far
	// the table searched: corroborating on m=1 needs 1/(kq+kc-1) >= 0.60, so
	// kq+kc-1 <= 1/0.6 = 1.667, so kq+kc <= 2 over the integers, so kq = kc = 1. There
	// is no larger shape to find, at any k, and the assertion below collects the m==1
	// corroborating shapes from BOTH tables and demands exactly that one.
	//
	// WARNING to anyone tempted to bolt a shared-evidence floor on top ("require >= 2
	// distinct shared tokens before corroborating"): the closed form already gives you
	// that for free at every k>=2, and such a floor with a STRING-EQUALITY exemption
	// is actively wrong here. "Acme Acme" against "Acme" has the same singleton
	// DISTINCT token set on both sides — Jaccard 1.0, correctly corroborated — yet the
	// two joined strings are NOT equal, so the exemption misses and the floor de-ranks
	// a pair the metric scores right. Pinned against production below rather than left
	// as advice.
	var m1CorroboratingShapes [][2]int
	for _, c := range table {
		if c.m == 1 && c.wantArm == armCorroborated {
			m1CorroboratingShapes = append(m1CorroboratingShapes, [2]int{c.k, c.k})
		}
	}
	for _, c := range asymmetric {
		if c.m == 1 && c.wantArm == armCorroborated {
			m1CorroboratingShapes = append(m1CorroboratingShapes, [2]int{c.kq, c.kc})
		}
	}
	assert.Equal(t, [][2]int{{1, 1}}, m1CorroboratingShapes,
		"the only (kq,kc) that can corroborate on one shared token is (1,1)")

	const duplicateQuery, duplicateCandidate = "Acme Acme", "Acme"
	require.NotEqual(t, normalizeOrg(duplicateQuery), normalizeOrg(duplicateCandidate),
		"the duplicate-token pair must normalize to UNEQUAL strings, or it cannot demonstrate the exemption miss")
	assert.Equal(t, armCorroborated,
		armForScore(t, decideConfidence(duplicateQuery, org(duplicateCandidate), nil).Score),
		"a repeated token collapses in the DISTINCT set, so this pair must corroborate and a string-equality floor would wrongly de-rank it")

	// Derived result 3 — the SATURATION class is GONE, and the distinct-shared-token
	// floor that used to close it is gone with it (deleted in PR #122, not kept).
	//
	// The history is worth keeping because the reasoning failed once. "Crossing
	// simCorroborate at k>=2 already forces m>=2" was offered here as the reason the
	// k>=2 saturation class needed no guard, and under the containment coefficient
	// that inference was FALSE (PR #127 review, Codex): m counted matching
	// OCCURRENCES, not distinct tokens, because tokenSimilarity walks the shorter
	// side's token SLICE against a membership set built from the longer side, so one
	// shared token repeated on the shorter side scored a match per occurrence.
	// "acme acme holdings" against "acme landscaping tampa" reached m=2 at k=3 for
	// 0.667 >= simCorroborate on ONE distinct shared token.
	//
	// Under Jaccard the same inference is true BY CONSTRUCTION rather than by luck:
	// both sides are deduplicated into SETS before the ratio is taken, so m is the
	// distinct shared count by definition, and m=1 at k>=2 can only reach
	// 1/(2k-1) <= 1/3 < simCorroborate. A repeated token cannot inflate anything, so
	// no floor is needed — which is why the floor was removed rather than ported.
	//
	// The pair above is pinned against production below: it is now a MISMATCH. That
	// is also specificity monotonicity doing its job — the candidate's two unmatched
	// tokens LOWER the score instead of being discarded by a min() denominator.
	//
	// The loop then pins this table's shape, so an added or altered k>=2 corroborating
	// row still has to carry m>=2. Under Jaccard that is a derivation about the metric
	// and not merely an observation about the enumeration, which is exactly what
	// changed.
	assert.Equal(t, armMismatch,
		armForScore(t, decideConfidence("acme acme holdings", org("acme landscaping tampa"), nil).Score),
		"a token repeated on one side must not manufacture a second piece of shared evidence")
	for _, c := range table {
		if c.k >= 2 && c.wantArm == armCorroborated {
			assert.GreaterOrEqual(t, c.m, 2,
				"k=%d: corroborating at k>=2 must require m>=2 shared tokens", c.k)
		}
	}

	// Derived result 4 — the ambiguous arm IS reachable at every equal-count k in
	// 2..6, so the cutoffs retain real discriminating power everywhere outside the
	// k=1 regime. Read with Derived result 1 that is the entire calibration claim:
	// the constants do nothing at k=1 because nothing CAN, and they do real work from
	// k=2 up, so 0.60 and 0.30 are confirmed where they are decidable and irrelevant
	// where they are not.
	for k := 2; k <= 6; k++ {
		reachable := false
		for _, c := range table {
			if c.k == k && c.wantArm == armUnverified {
				reachable = true
			}
		}
		assert.True(t, reachable, "k=%d: the ambiguous arm must be reachable", k)
	}

	// Derived result 5 — the recorded KNOWN LIMITATION, REDUCED by PR #122 rather than
	// inherited from it. Keep that distinction exact.
	//
	// The frame is EQUAL-COUNT pairs, and that is the right frame rather than a
	// convenience: containment cannot apply when neither side is a subset of the
	// other, so no equal-count row is ever rescued by tokenSetContained (asserted in
	// the first loop above) and the arm is decided by the value alone. In that frame,
	// the first k at which simMismatch=0.30 becomes reachable WITH a shared token
	// moves from k=4 under the containment coefficient (0.25 at m=1) to k=3 under
	// Jaccard (0.20 at m=1). Below that k, "mismatch" still means precisely "no shared
	// tokens at all" and the 0.30 value itself does no work there — one k less of it
	// than before.
	//
	// Be exact about what this is NOT. It is not the claim that kq+kc >= 5 suffices to
	// reach the de-rank arm with a shared token. That bound is about the metric VALUE
	// crossing simMismatch, and its natural witness — kq=1, kc=4, m=1 at 0.25 — is
	// PURE CONTAINMENT, so tokenSetContained holds it at unverified and the de-rank
	// arm never fires on it. Value reachability and ARM reachability are different
	// questions once the guard exists, and only the second one is the limitation.
	//
	// Still not fixed here, and still not mis-ranking: every outcome above is inside
	// the review band, so nothing is dropped either way. Narrowing it further is a
	// question about real candidate distributions rather than about enumeration
	// (ENG-5166). And the retired containment coefficient is still live in github_org
	// for a differently weighted name hint, where its multiset-versus-set behavior is
	// tracked on its own (ENG-5890) — this file no longer shares a metric with it, so
	// that constraint no longer blocks anything here.
	firstKWithSharedTokenMismatch := 0
	for _, c := range table {
		if c.wantArm != armMismatch || c.m == 0 {
			continue
		}
		if firstKWithSharedTokenMismatch == 0 || c.k < firstKWithSharedTokenMismatch {
			firstKWithSharedTokenMismatch = c.k
		}
	}
	assert.Equal(t, 3, firstKWithSharedTokenMismatch,
		"simMismatch must first become reachable with a shared token at equal-count k=3")
}

// TestJaccardRetiresContainmentSaturationAtFullContainment pins the first of PR
// #122's two behavior changes on one shape, so the change is an explicit
// expectation rather than something a reader has to infer from a table cell.
//
// kq=2, kc=4, m=2: the query's whole token set is contained in the candidate's,
// which is the exact shape the old enumeration recorded as "deliberately still
// corroboration". The containment coefficient scored it 1.0 by dividing by the
// shorter side; Jaccard scores it 2/4 = 0.5, because the candidate's two unmatched
// tokens are disconfirming evidence and a specificity-monotone metric has to count
// them. The verdict moves from corroborated (0.60) to unverified (0.50) —
// under-specified, not confirmed.
//
// Note WHICH mechanism decides it, because the next test turns on the difference:
// 0.5 is above simMismatch, so this row reaches the default arm on the VALUE alone.
// tokenSetContained is true here and does no work.
func TestJaccardRetiresContainmentSaturationAtFullContainment(t *testing.T) {
	query, candidate := newAsymmetricCalibrationPair(t, 2, 4, 2)
	qTokens, cTokens := normalizeOrgTokens(query), normalizeOrgTokens(candidate)

	require.True(t, tokenSetContained(qTokens, cTokens),
		"this shape must be pure containment, or it is not the class PR #122 changed")

	sim := jaccardTokenSets(qTokens, cTokens)
	assert.InDelta(t, 0.5, sim, 1e-9,
		"full containment must score kq/kc, never saturate at 1.0")
	assert.Greater(t, sim, simMismatch,
		"this row must sit ABOVE simMismatch, so its arm is decided by the value and not by the containment guard")

	dec := decideConfidence(query, org(candidate), nil)
	assert.Equal(t, armUnverified, armForScore(t, dec.Score),
		"pure containment at kq=2 kc=4 must be unverified, not the corroborated it used to be (PR #122)")
	assertInsideReviewBand(t, dec, "retired containment saturation")
}

// TestJaccardContainmentGuardIsWhatSeparatesUnderSpecifiedFromDisagreeing pins the
// second of PR #122's behavior changes, and it is the entire justification for
// keeping tokenSetContained (ENG-5172).
//
// Both pairs below score BELOW simMismatch, so the value alone would send both to
// the de-rank arm. They differ in one thing only — whether the query's token set is
// a subset of the candidate's:
//
//   - kq=1, kc=5, m=1 → 0.2000, CONTAINED. Pre-#122 containment scored this 1.0 and
//     CORROBORATED it. Post-#122 the value alone would de-rank it. It is unverified
//     instead, rescued from the de-rank arm ONLY by tokenSetContained: a query org
//     that is a strict subset of the registrant org is UNDER-SPECIFICATION, not
//     disagreement.
//   - kq=2, kc=5, m=1 → 0.1667, NOT contained. The query carries a token the
//     candidate does not, which is positive evidence of disagreement, so the de-rank
//     arm fires and this one is a mismatch.
//
// The require calls come first on purpose. If a future edit lifted either similarity
// to or above simMismatch, both rows would reach the default arm for a reason having
// nothing to do with containment, and the contrast would silently degenerate into
// "one of them was above the threshold" while still passing. Every arm below is read
// from PRODUCTION, never from a table's own expectation.
func TestJaccardContainmentGuardIsWhatSeparatesUnderSpecifiedFromDisagreeing(t *testing.T) {
	containedQuery, containedCandidate := newAsymmetricCalibrationPair(t, 1, 5, 1)
	disagreeingQuery, disagreeingCandidate := newAsymmetricCalibrationPair(t, 2, 5, 1)

	containedQT, containedCT := normalizeOrgTokens(containedQuery), normalizeOrgTokens(containedCandidate)
	disagreeingQT, disagreeingCT := normalizeOrgTokens(disagreeingQuery), normalizeOrgTokens(disagreeingCandidate)

	containedSim := jaccardTokenSets(containedQT, containedCT)
	disagreeingSim := jaccardTokenSets(disagreeingQT, disagreeingCT)

	require.Less(t, containedSim, simMismatch,
		"kq=1 kc=5 m=1 must sit below simMismatch, or the containment guard is not what decides its arm")
	require.Less(t, disagreeingSim, simMismatch,
		"kq=2 kc=5 m=1 must sit below simMismatch, or this is not a contrast")
	require.True(t, tokenSetContained(containedQT, containedCT),
		"kq=1 kc=5 m=1 must be pure containment")
	require.False(t, tokenSetContained(disagreeingQT, disagreeingCT),
		"kq=2 kc=5 m=1 must NOT be contained — the query holds a token the candidate lacks")

	assert.InDelta(t, 0.2000, containedSim, 0.0001, "kq=1 kc=5 m=1 similarity must be 1/5")
	assert.InDelta(t, 0.1667, disagreeingSim, 0.0001, "kq=2 kc=5 m=1 similarity must be 1/6")

	containedDec := decideConfidence(containedQuery, org(containedCandidate), nil)
	assert.Equal(t, armUnverified, armForScore(t, containedDec.Score),
		"a CONTAINED query below simMismatch is under-specified and must not be de-ranked (ENG-5172)")
	assertInsideReviewBand(t, containedDec, "contained below simMismatch")

	disagreeingDec := decideConfidence(disagreeingQuery, org(disagreeingCandidate), nil)
	assert.Equal(t, armMismatch, armForScore(t, disagreeingDec.Score),
		"an UNCONTAINED query below simMismatch is disagreement and must be de-ranked")
	assertInsideReviewBand(t, disagreeingDec, "uncontained below simMismatch")

	assert.NotEqual(t, armForScore(t, containedDec.Score), armForScore(t, disagreeingDec.Score),
		"containment must be the only thing separating these two arms")
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
			// one-token query and a genuine partial overlap are both "could not
			// corroborate", so they share one PII-free justification.
			//
			// The case NAME below is historical — read it as a label, not a claim.
			// Under PR #122 this row is not saturated at all: the distinct token sets
			// are {apple} and {apple, tree, landscaping}, so Jaccard is 1/3 = 0.3333,
			// squarely in the AMBIGUOUS band (above simMismatch, below
			// simCorroborate), and it reaches the default arm on the VALUE. The
			// containment coefficient was what saturated this shape to 1.0. The old
			// comment also claimed this was the row that fails if "the guard" is
			// reverted; that guard no longer exists, so the claim is retired rather
			// than restated — the reversion it described is not expressible against
			// current production. Inputs and expected arm are unchanged: the arm was
			// right for the old reason and is right for the new one.
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
// is documented behavior, not a bug to be fixed here) AND decideConfidence does
// not corroborate on these pairs. If someone "fixes" the metric instead, the first
// assertion fails and forces the github_org blast radius to be considered.
//
// Since PR #122 the two halves are independent rather than a before/after of one
// change: reverse-whois scores with jaccardTokenSets and no longer consults
// tokenSimilarity at all, so the second half now holds because Jaccard counts the
// candidate's unmatched tokens (1/3, 1/6 and 1/9 here, with tokenSetContained
// keeping the two below simMismatch out of the de-rank arm). That makes this test a
// tripwire on the SHARED metric — it fires if github_org's coefficient is changed
// under it — plus a standing proof that the reverse-whois decision is immune to the
// saturation, which is the property that mattered.
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

	// The contrast case, and the reason no token-count floor may be added: a genuine
	// single-token match still corroborates, because normalizeOrg strips the legal
	// form and both sides reduce to one IDENTICAL token, which Jaccard scores 1.0
	// without needing any exemption. A bare k>=2 floor would de-rank exactly the
	// matches this plugin exists to find.
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
// pair and a cutoff on it would be ordering nothing — it is the property that makes
// a threshold on such a quantity coherent at all, for every k where the metric has
// resolution.
//
// This covers the containment coefficient, which since PR #122 is github_org's
// metric rather than reverse-whois's. The equivalent property for the metric that
// now decides reverse-whois is enumerated cell by cell in
// TestJaccardReachabilityByTokenCount: m/(2k-m) is strictly increasing in m for
// fixed k, and every row of that ladder is written out with the arm it selects.
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
// and which is the resolved registrant cannot change the verdict.
//
// It matters because the decision keeps acquiring side-sensitive machinery. The
// retired containment coefficient divided by the SHORTER side; tokenSetContained
// asks an inherently DIRECTIONAL question — is one set a subset of the other. Both
// are symmetric as written: min() is symmetric, and tokenSetContained deliberately
// accepts a subset in EITHER direction, because under-specification is
// under-specification whichever of the two names is the shorter one. But an
// asymmetric reformulation — keying on the QUERY's token count alone, or on
// containment in one direction only — would silently make a candidate's score depend
// on lookup direction, and nothing else in this file would notice.
//
// decideConfidence's score is the only thing asserted, and that is the whole
// property worth pinning: it is the composition of every side-sensitive step, so it
// fails if ANY of them acquires a direction. Jaccard itself cannot break it (union
// and intersection are both symmetric), which leaves the guard and the arms as where
// a regression would actually land. The unequal-length pairs are the ones that would
// catch it — a length comparison is a no-op on equal-count pairs, and containment is
// unreachable there except at identity.
func TestCorroborationIsSymmetricUnderArgumentSwap(t *testing.T) {
	assertSymmetric := func(t *testing.T, a, b string) {
		t.Helper()
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
