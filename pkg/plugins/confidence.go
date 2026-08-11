package plugins

// Confidence thresholds used by name-to-identifier resolution plugins.
// Plugins that map an org name to a third-party identifier (GitHub org,
// domain registrant, etc.) attach scored, justified evidence to their findings
// using AddConfidence so users can distinguish authoritative from ambiguous
// results.
const (
	// ConfidenceHigh is the minimum total score for a finding to be emitted
	// cleanly. Findings at or above this threshold appear normally in terminal
	// output.
	ConfidenceHigh = 65

	// ConfidenceLow is a noise floor a plugin may choose to apply to its own
	// candidates before emitting them; github-org is the one that does. The
	// framework neither enforces it nor discards anything: NeedsReview has no
	// lower bound, so a finding below this total is still emitted, and is emitted
	// needing review for user verification (and future agent disambiguation)
	// exactly like one between here and ConfidenceHigh.
	ConfidenceLow = 35
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
// AddConfidence clamps score to 0-100, always appends, and never materializes
// the total.
func AddConfidence(f *Finding, score int, justification string) {
	f.Confidences = append(f.Confidences, Confidence{
		Score:         max(0, min(score, 100)),
		Justification: justification,
	})
}

// TotalConfidence returns the sum of a finding's evidence scores, capped at 100.
//
// A finding with no evidence totals 0 — absence of evidence is not confidence.
// That is deliberately indistinguishable from an explicit zero-score entry by
// score alone; use len(f.Confidences) to tell "unscored" from "scored zero".
func TotalConfidence(f Finding) int {
	total := 0
	for _, confidence := range f.Confidences {
		total += max(0, min(confidence.Score, 100))
	}
	return min(total, 100)
}

// NeedsReview reports whether a finding falls short of ConfidenceHigh, which
// includes a finding nothing has vouched for at all.
//
// It reads directly off the total: no evidence totals 0 and needs review, an
// explicit zero-score entry totals 0 and needs review, and anything scored
// below the threshold needs review. Callers that must distinguish "never
// assessed" from "assessed and found wanting" can inspect f.Confidences.
func NeedsReview(f Finding) bool {
	return len(f.Confidences) == 0 || TotalConfidence(f) < ConfidenceHigh
}
