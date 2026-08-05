package plugins

import "strings"

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

// RegistryUnknown is the Finding.Data["registry"] value a handle carries when
// the plugin that found it could not tell which RIR will recognize it — EDGAR
// scraping a token out of a filing, for one.
//
// It is shared because two packages have to agree on it: the runner broadcasts
// such a handle to every registry in RIRRegistries, and handleProvenance treats
// it as matching every registry so the broadcast keeps its provenance. Spelled
// separately, a change to either would silently stop provenance from matching.
const RegistryUnknown = "unknown"

// RIRRegistries lists the regional internet registries the pipeline queries.
var RIRRegistries = []string{"arin", "ripe", "apnic", "afrinic", "lacnic"}

// Compose combines upstream evidence with the local observation that extends it.
//
// This is the composition rule the whole confidence contract turns on. A chain
// of dependent observations — organization → RIR handle → CIDR, seed domain →
// permutation → DNS resolution — is ONE piece of evidence per upstream source,
// scored at the weaker of the two legs, never the sum. Adding instead is how a
// review-level guess becomes a clean finding: a 0.45 org-name match plus a 0.85
// deterministic lookup sums past 1.0 and reports near-certainty about a company
// that merely shares a name prefix.
//
// Separate upstream findings DO produce separate entries, and those add
// legitimately: two plugins reaching the same value by different routes
// corroborate the step that was actually in doubt.
//
// With no upstream provenance the local observation stands alone at ceiling.
// That is the caller-asserted case — an API caller supplying handles through
// Meta, or a plugin invoked outside the pipeline — where there is no inferred
// leg to bound, because the value was asserted rather than derived.
//
// describe renders the justification for one upstream source, receiving the
// upstream finding so it can name who observed the value and what they were
// looking for. It is called with nil for the no-provenance case, where the
// justification describes the local observation alone — consumers weave the
// attribution in wherever their sentence needs it, which is mid-sentence for
// some and trailing for others.
func Compose(upstream []Finding, ceiling float64, describe func(upstream *Finding) string) []Confidence {
	if len(upstream) == 0 {
		return []Confidence{{Score: ceiling, Justification: describe(nil)}}
	}

	confidences := make([]Confidence, 0, len(upstream))
	for _, source := range upstream {
		confidences = append(confidences, Confidence{
			Score:         min(TotalConfidence(source), ceiling),
			Justification: describe(&source),
		})
	}
	return confidences
}

// UpstreamFor returns every upstream finding of the given type carrying value.
//
// All matches are returned rather than the first: two plugins that independently
// discovered one value are two pieces of evidence, and Compose turns each into
// its own entry. Matching is case- and space-insensitive, which covers the RIR
// handles and DNS names that make up every value flowing through the pipeline.
func UpstreamFor(input Input, typ FindingType, value string) []Finding {
	wanted := normalizeUpstreamValue(value)

	var matches []Finding
	for _, f := range input.UpstreamFindings {
		if f.Type == typ && normalizeUpstreamValue(f.Value) == wanted {
			matches = append(matches, f)
		}
	}
	return matches
}

// normalizeUpstreamValue canonicalizes a value for provenance matching.
func normalizeUpstreamValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// JoinPhrase renders a list the way prose does: "a", "a and b", "a, b and c".
//
// It exists for justifications. Grouped evidence — four ARIN entity searches
// that matched one handle, three nameservers that served one record — has to
// name every observation in a single entry, and a bare comma-joined list reads
// as truncated where the prose form reads as complete.
func JoinPhrase(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
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
	return min(total, 1.0)
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
