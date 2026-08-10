package plugins

import "math"

// Confidence thresholds used by name-to-identifier resolution plugins.
// Plugins that map an org name to a third-party identifier (GitHub org,
// domain registrant, etc.) attach scored, justified evidence to their findings
// using AddConfidence so users can distinguish authoritative from ambiguous
// results.
const (
	// ConfidenceHigh is the minimum total score for a finding to be emitted
	// cleanly. Findings at or above this threshold appear normally in terminal
	// output.
	ConfidenceHigh = 0.65

	// ConfidenceLow is the noise floor. Findings below this total are discarded.
	// Findings between ConfidenceLow and ConfidenceHigh are emitted needing
	// review for user verification (and future agent disambiguation).
	ConfidenceLow = 0.35

	// confidenceEpsilon absorbs float64 accumulation error when comparing a
	// summed total against ConfidenceHigh.
	//
	// Decomposed evidence is summed at runtime, and a sum that should land
	// exactly on the threshold often does not: wikidata's 0.30 + 0.35 is
	// 0.6499999999999999 in float64, which a bare < would read as needing
	// review. Whether a finding reads as clean must not depend on how its score
	// was spelled, so the comparison tolerates a margin far smaller than any
	// score a plugin assigns.
	confidenceEpsilon = 1e-9
)

// AddConfidence appends one piece of scored, justified evidence to f.
//
// Use this in plugins that perform name-to-identifier resolution where the
// mapping might be ambiguous (e.g., org name → GitHub org, org name → WHOIS
// registrant). Deterministic lookups (RDAP handle → CIDRs) should not use this.
//
// Call it once per independently observed signal rather than once with a
// pre-summed score: the evidence list is what Guard surfaces to a human, so a
// single opaque entry throws away exactly the information it exists to carry.
// AddConfidence always appends and never materializes the total.
func AddConfidence(f *Finding, score float64, justification string) {
	f.Confidences = append(f.Confidences, Confidence{
		Score:         score,
		Justification: justification,
	})
}

// TotalConfidence returns the sum of a finding's evidence scores, capped at 1.0.
//
// A finding with no evidence totals 0.0 — absence of evidence is not confidence.
// That is deliberately indistinguishable from an explicit zero-score entry by
// score alone; use len(f.Confidences) to tell "unscored" from "scored zero".
func TotalConfidence(f Finding) float64 {
	total := 0.0
	for _, confidence := range f.Confidences {
		total += confidence.Score
	}
	return math.Round(min(total, 1.0)*1e12) / 1e12
}

// NeedsReview reports whether a finding falls short of ConfidenceHigh, which
// includes a finding nothing has vouched for at all.
//
// It reads directly off the total: no evidence totals 0.0 and needs review, an
// explicit zero-score entry totals 0.0 and needs review, and anything scored
// below the threshold needs review. Callers that must distinguish "never
// assessed" from "assessed and found wanting" test len(f.Confidences) rather
// than asking here — the SDK emitter and the Guard adapter both do, because
// only unscored findings may fall back to a downstream default.
func NeedsReview(f Finding) bool {
	return len(f.Confidences) == 0 || TotalConfidence(f) < ConfidenceHigh-confidenceEpsilon
}
