package plugins

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddConfidence_AppendsEntry(t *testing.T) {
	var f Finding
	AddConfidence(&f, 60, "blog URL matches the known domain")

	require.Len(t, f.Confidences, 1)
	assert.Equal(t, 60, f.Confidences[0].Score)
	assert.Equal(t, "blog URL matches the known domain", f.Confidences[0].Justification)
}

func TestAddConfidence_CopiesReferences(t *testing.T) {
	references := []Reference{{Label: "source", URL: "https://example.com/evidence"}}
	var finding Finding

	AddConfidence(&finding, 60, "source supports finding", references...)
	references[0].URL = "https://example.com/mutated"

	require.Len(t, finding.Confidences, 1)
	require.Len(t, finding.Confidences[0].References, 1)
	assert.Equal(t, "source", finding.Confidences[0].References[0].Label)
	assert.Equal(t, "https://example.com/evidence", finding.Confidences[0].References[0].URL)
}

func TestAddConfidence_ClampsScore(t *testing.T) {
	var f Finding
	AddConfidence(&f, -1, "below range")
	AddConfidence(&f, 101, "above range")

	require.Len(t, f.Confidences, 2)
	assert.Equal(t, 0, f.Confidences[0].Score)
	assert.Equal(t, 100, f.Confidences[1].Score)
}

func TestAddConfidence_PreservesOrder(t *testing.T) {
	var f Finding
	AddConfidence(&f, 10, "first")
	AddConfidence(&f, 20, "second")
	AddConfidence(&f, 30, "third")

	require.Len(t, f.Confidences, 3)
	assert.Equal(t, []string{"first", "second", "third"}, []string{
		f.Confidences[0].Justification,
		f.Confidences[1].Justification,
		f.Confidences[2].Justification,
	})
}

// TestAddConfidence_NeverWritesData is the structural half of the migration: a
// finding's confidence lives in Confidences and nowhere else, so a consumer can
// never again read a stale scalar out of the metadata map.
func TestAddConfidence_NeverWritesData(t *testing.T) {
	f := Finding{Data: map[string]any{"org": "Acme Corp"}}
	AddConfidence(&f, 42, "some evidence")

	assert.Equal(t, map[string]any{"org": "Acme Corp"}, f.Data)
	assert.NotContains(t, f.Data, "confidence")
	assert.NotContains(t, f.Data, "needs_review")
}

// TestAddConfidence_FindingsDoNotShareBacking guards the aliasing trap: two
// findings copied from one template must not append into the same array.
func TestAddConfidence_FindingsDoNotShareBacking(t *testing.T) {
	template := Finding{Type: FindingDomain, Value: "example.com"}

	a, b := template, template
	AddConfidence(&a, 30, "evidence for a")
	AddConfidence(&b, 70, "evidence for b")

	require.Len(t, a.Confidences, 1)
	require.Len(t, b.Confidences, 1)
	assert.Equal(t, "evidence for a", a.Confidences[0].Justification)
	assert.Equal(t, "evidence for b", b.Confidences[0].Justification)
	assert.Empty(t, template.Confidences, "the template itself stays unscored")
}

func TestTotalConfidence_NoEntriesIsZero(t *testing.T) {
	assert.Equal(t, 0, TotalConfidence(Finding{}))
}

func TestTotalConfidence_ExplicitZeroEntryIsZero(t *testing.T) {
	var f Finding
	AddConfidence(&f, 0, "the candidate could not be substantiated at all")

	assert.Equal(t, 0, TotalConfidence(f))
}

// TestTotalConfidence_EmptyAndExplicitZeroDifferByLength pins the distinction
// the whole slice exists to carry: both total 0, and only the entry count
// separates "never scored" from "scored, and it came to nothing".
func TestTotalConfidence_EmptyAndExplicitZeroDifferByLength(t *testing.T) {
	unscored := Finding{}

	var explicitZero Finding
	AddConfidence(&explicitZero, 0, "explicitly scored zero")

	assert.Equal(t, TotalConfidence(unscored), TotalConfidence(explicitZero),
		"the two are indistinguishable by score alone")
	assert.Empty(t, unscored.Confidences)
	assert.Len(t, explicitZero.Confidences, 1)
}

func TestTotalConfidence_SumsEntries(t *testing.T) {
	var f Finding
	AddConfidence(&f, 25, "first")
	AddConfidence(&f, 30, "second")
	AddConfidence(&f, 20, "third")

	assert.Equal(t, 75, TotalConfidence(f))
}

func TestTotalConfidence_CapsAtHundred(t *testing.T) {
	var f Finding
	AddConfidence(&f, 60, "first")
	AddConfidence(&f, 65, "second")

	assert.Equal(t, 100, TotalConfidence(f), "125 of evidence caps at 100")
}

func TestTotalConfidence_ClampsDirectEntries(t *testing.T) {
	tests := []struct {
		name        string
		confidences []Confidence
		want        int
	}{
		{name: "below range", confidences: []Confidence{{Score: -10}, {Score: 50}}, want: 50},
		{name: "above range", confidences: []Confidence{{Score: 150}, {Score: -100}}, want: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, TotalConfidence(Finding{Confidences: tt.confidences}))
		})
	}
}

func TestTotalConfidence_ClampsJSONEntries(t *testing.T) {
	var finding Finding
	require.NoError(t, json.Unmarshal([]byte(`{"Confidences":[{"score":-10},{"score":50}]}`), &finding))

	assert.Equal(t, 50, TotalConfidence(finding))
}

func TestNeedsReview_TrueForEmptyEvidence(t *testing.T) {
	assert.True(t, NeedsReview(Finding{}),
		"nothing has vouched for an unscored finding, and it totals 0")
}

// TestNeedsReview_DoesNotSeparateUnscoredFromExplicitZero is the caveat that
// comes with reading straight off the total: both cases need review, so
// NeedsReview can no longer tell them apart. Anything that must — the SDK
// emitter and the Guard adapter, where only an unscored finding may fall back
// to a downstream default — tests len(Confidences) instead.
func TestNeedsReview_DoesNotSeparateUnscoredFromExplicitZero(t *testing.T) {
	unscored := Finding{}

	var explicitZero Finding
	AddConfidence(&explicitZero, 0, "explicitly scored zero")

	assert.Equal(t, NeedsReview(unscored), NeedsReview(explicitZero),
		"the predicate alone cannot separate them")
	assert.Empty(t, unscored.Confidences)
	assert.Len(t, explicitZero.Confidences, 1, "the entry count is what still separates them")
}

func TestNeedsReview_TrueForExplicitZero(t *testing.T) {
	var f Finding
	AddConfidence(&f, 0, "explicitly scored zero")

	assert.True(t, NeedsReview(f), "an explicit zero IS a judgement, and it needs review")
}

func TestNeedsReview_TrueBelowConfidenceHigh(t *testing.T) {
	var f Finding
	AddConfidence(&f, 55, "borderline evidence")

	assert.True(t, NeedsReview(f))
}

func TestNeedsReview_FalseAtConfidenceHigh(t *testing.T) {
	var f Finding
	AddConfidence(&f, ConfidenceHigh, "authoritative evidence")

	assert.False(t, NeedsReview(f))
}

func TestNeedsReview_FalseWhenCappedSumClears(t *testing.T) {
	var f Finding
	AddConfidence(&f, 40, "first")
	AddConfidence(&f, 40, "second")

	assert.Equal(t, 80, TotalConfidence(f))
	assert.False(t, NeedsReview(f), "independent signals can aggregate past the review bar")
}

// TestFinding_JSONIncludesConfidences covers both the `json` and `ndjson` output
// modes, which encode a Finding directly.
func TestFinding_JSONIncludesConfidences(t *testing.T) {
	f := Finding{Type: FindingDomain, Value: "example.com", Source: "github-org"}
	AddConfidence(&f, 60, "blog URL matches the known domain", Reference{
		Label: "Organization profile",
		URL:   "https://github.com/acme",
	})
	AddConfidence(&f, 5, "organization has 86 public repositories")

	encoded, err := json.Marshal(f)
	require.NoError(t, err)

	var decoded Finding
	require.NoError(t, json.Unmarshal(encoded, &decoded))

	require.Len(t, decoded.Confidences, 2)
	assert.Equal(t, 60, decoded.Confidences[0].Score)
	assert.Equal(t, "blog URL matches the known domain", decoded.Confidences[0].Justification)
	require.Len(t, decoded.Confidences[0].References, 1)
	assert.Equal(t, "https://github.com/acme", decoded.Confidences[0].References[0].URL)
	assert.Equal(t, 5, decoded.Confidences[1].Score)
	assert.Equal(t, 65, TotalConfidence(decoded))

	assert.Contains(t, string(encoded), `"score"`)
	assert.Contains(t, string(encoded), `"justification"`)
	assert.Contains(t, string(encoded), `"references"`)
}

func TestTotalConfidence_NormalizesFloatAccumulation(t *testing.T) {
	var f Finding
	AddConfidence(&f, 30, "relationship evidence")
	AddConfidence(&f, 35, "website evidence")

	assert.Equal(t, ConfidenceHigh, TotalConfidence(f))
	assert.False(t, NeedsReview(f))
}

func TestNeedsReview_TrueOnePointBelowConfidenceHigh(t *testing.T) {
	var f Finding
	AddConfidence(&f, 64, "just short of the bar")

	assert.True(t, NeedsReview(f))
}

// TestFinding_JSONIncludesDerivedValues covers the `json` and `ndjson` output
// modes: the aggregate and the review verdict appear alongside the evidence so
// a reader does not have to sum the entries.
func TestFinding_JSONIncludesDerivedValues(t *testing.T) {
	f := Finding{Type: FindingDomain, Value: "example.com", Source: "github-org"}
	AddConfidence(&f, 60, "blog URL matches the known domain")
	AddConfidence(&f, 5, "organization has 86 public repositories")

	encoded, err := json.Marshal(f)
	require.NoError(t, err)

	var decoded struct {
		Value           string
		Confidences     []Confidence
		TotalConfidence int
		NeedsReview     bool
	}
	require.NoError(t, json.Unmarshal(encoded, &decoded))

	assert.Equal(t, "example.com", decoded.Value)
	assert.Len(t, decoded.Confidences, 2, "the evidence still travels")
	assert.Equal(t, 65, decoded.TotalConfidence)
	assert.False(t, decoded.NeedsReview, "65 clears the bar")
}

func TestFinding_JSONDerivedValuesReflectReviewState(t *testing.T) {
	f := Finding{Type: FindingDomain, Value: "example.com", Source: "gleif"}
	AddConfidence(&f, ConfidenceLow, "secondary legal-name search match")

	encoded, err := json.Marshal(f)
	require.NoError(t, err)

	var decoded struct {
		TotalConfidence int
		NeedsReview     bool
	}
	require.NoError(t, json.Unmarshal(encoded, &decoded))

	assert.Equal(t, ConfidenceLow, decoded.TotalConfidence)
	assert.True(t, decoded.NeedsReview)
}

// TestFinding_JSONRoundTripIgnoresDerivedValues pins that the derived fields are
// output-only. Findings round-trip through this encoding in the plugin caches,
// and rehydrating must rebuild the totals from Confidences rather than trusting
// whatever was written — otherwise a stale cache entry could carry a total that
// disagrees with its own evidence.
func TestFinding_JSONRoundTripIgnoresDerivedValues(t *testing.T) {
	original := Finding{Type: FindingDomain, Value: "example.com", Source: "github-org"}
	AddConfidence(&original, 30, "first")
	AddConfidence(&original, 25, "second")

	encoded, err := json.Marshal(original)
	require.NoError(t, err)

	var restored Finding
	require.NoError(t, json.Unmarshal(encoded, &restored))

	assert.Equal(t, original.Confidences, restored.Confidences)
	assert.Equal(t, TotalConfidence(original), TotalConfidence(restored))
	assert.Equal(t, NeedsReview(original), NeedsReview(restored))
}
