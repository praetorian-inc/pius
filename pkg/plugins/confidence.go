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

	// ConfidenceLow is the noise floor. Findings below this total are discarded.
	// Findings between ConfidenceLow and ConfidenceHigh are emitted needing
	// review for user verification (and future agent disambiguation).
	ConfidenceLow = 35
)

// AddConfidence appends one piece of scored, justified evidence to f.
func AddConfidence(f *Finding, score int, justification string, references ...Reference) {
	normalized := normalizeReferences(references)
	f.Confidences = append(f.Confidences, Confidence{
		Score:         max(0, min(score, 100)),
		Justification: justification,
		Reference:     combineNormalizedReferences(normalized),
		References:    normalized,
	})
}

// AddConfidenceWithReference is the explicit form for evidence with source
// material. New plugins should prefer it over the migration-compatible
// variadic form of AddConfidence.
func AddConfidenceWithReference(f *Finding, score int, justification string, reference Reference) {
	AddConfidence(f, score, justification, reference)
}

func normalizeReferences(references []Reference) []Reference {
	if len(references) == 0 {
		return nil
	}
	normalized := make([]Reference, len(references))
	for i, reference := range references {
		normalized[i] = normalizeReference(reference)
	}
	return normalized
}

func combineNormalizedReferences(references []Reference) *Reference {
	if len(references) == 0 {
		return nil
	}
	if len(references) == 1 {
		return &references[0]
	}

	return &Reference{
		Label: "Supporting source records",
		Type:  ReferenceTypeJSON,
		Data:  references,
	}
}

func normalizeReference(reference Reference) Reference {
	if reference.Type == "" && reference.URL != "" {
		reference.Type = ReferenceTypeURL
		reference.Data = URLReferenceData{URL: reference.URL}
	}
	return reference
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
