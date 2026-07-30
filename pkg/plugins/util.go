package plugins

// Confidence thresholds used by name-to-identifier resolution plugins.
// Plugins that map an org name to a third-party identifier (GitHub org,
// domain registrant, etc.) annotate their findings with a confidence score
// using SetConfidence so users can distinguish authoritative from ambiguous results.
const (
	// ConfidenceHigh is the minimum score for a finding to be emitted cleanly.
	// Findings at or above this threshold appear normally in terminal output.
	ConfidenceHigh = 0.65

	// ConfidenceLow is the noise floor. Findings below this score are discarded.
	// Findings between ConfidenceLow and ConfidenceHigh are emitted with a
	// needs_review flag for user verification (and future agent disambiguation).
	ConfidenceLow = 0.35
)

// SetConfidence annotates f with a confidence score and sets needs_review
// when the score falls below ConfidenceHigh.
//
// Use this in plugins that perform name-to-identifier resolution where the
// mapping might be ambiguous (e.g., org name → GitHub org, org name → WHOIS
// registrant). Deterministic lookups (RDAP handle → CIDRs) should not use this.
func SetConfidence(f *Finding, confidence float64) {
	if f.Data == nil {
		f.Data = make(map[string]any)
	}
	f.Data["confidence"] = confidence
	f.Data["needs_review"] = confidence < ConfidenceHigh
}

// Confidence returns the confidence score from a finding's Data.
// Returns 1.0 for findings that have not been scored (unscored = high confidence).
func Confidence(f Finding) float64 {
	if c, ok := f.Data["confidence"].(float64); ok {
		return c
	}
	return 1.0
}

// NeedsReview returns true if the finding has been flagged for human review.
// Returns false for unscored findings (unscored = high confidence).
func NeedsReview(f Finding) bool {
	if v, ok := f.Data["needs_review"].(bool); ok {
		return v
	}
	return false
}

// Unique returns items with duplicates removed, preserving the order of first
// occurrence.
func Unique[T comparable](items []T) []T {
	return UniqueBy(items, func(item T) T { return item })
}

// UniqueBy is Unique for values that are not themselves comparable, or that
// should be deduplicated on one field. The FIRST item for a given key wins
func UniqueBy[T any, K comparable](items []T, key func(T) K) []T {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[K]struct{}, len(items))
	out := make([]T, 0, len(items))
	for _, item := range items {
		k := key(item)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, item)
	}
	return out
}
