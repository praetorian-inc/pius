package strutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestJaccardTokenSets pins the Jaccard metric (|A ∩ B| / |A ∪ B|) that org-name
// corroboration uses (ENG-5172). The load-bearing difference from
// TokenSimilarity is the containment case: "Praetorian" vs "Praetorian Security"
// is 1.0 under containment but 0.5 under Jaccard, because the extra "security"
// token counts against the union.
//
// The table holds raw strings and tokenizes at the call site, so the tokenize
// step stays inside what these cases cover.
func TestJaccardTokenSets(t *testing.T) {
	tests := []struct {
		a, b string
		want float64
	}{
		{"Praetorian", "Praetorian", 1.0},                           // identical single token
		{"Praetorian", "Praetorian Security", 0.5},                  // {p} vs {p, security} = 1/2 — the containment case Jaccard fixes
		{"Praetorian Security", "Praetorian Inc", 0.333333},         // {p, security} vs {p, inc} = 1/3
		{"Acme Global Data Cloud", "Acme Global Data Widgets", 0.6}, // 3 shared / 5 union
		{"Google", "Apple", 0.0},                                    // disjoint
		{"Alpha Beta", "Alpha Beta", 1.0},                           // identical multi-token
		{"Acme Acme Beta", "Acme Gamma", 1.0 / 3.0},                 // duplicates collapse to the distinct set: {acme, beta} vs {acme, gamma} = 1/3
		{"", "Google", 0.0},                                         // empty side
		{"Google", "", 0.0},                                         // empty other side
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			assert.InDelta(t, tt.want, JaccardTokenSets(Tokenize(tt.a), Tokenize(tt.b)), 0.0001,
				"jaccard %q vs %q", tt.a, tt.b)
		})
	}
}

// TestJaccardTokenSets_PenalizesContainmentUnlikeTokenSimilarity states the
// contrast between the two metrics directly, so the reason both exist survives
// as an assertion rather than only as a comment. Whichever metric a caller
// picks, it is picking this difference.
func TestJaccardTokenSets_PenalizesContainmentUnlikeTokenSimilarity(t *testing.T) {
	const short, long = "Acme", "Acme Enterprises Holdings"

	assert.InDelta(t, 1.0, TokenSimilarity(short, long), 0.0001,
		"containment divides by the shorter set, so a contained name scores a full 1.0")
	assert.InDelta(t, 1.0/3.0, JaccardTokenSets(Tokenize(short), Tokenize(long)), 0.0001,
		"Jaccard divides by the union, so the two descriptor tokens count against the score")
}

// TestTokenSetContained pins the predicate that separates UNDER-SPECIFICATION
// from DISAGREEMENT for Corroborate's mismatch arm (ENG-5172). Jaccard scores
// both shapes low, so this is the only thing standing between "one org name is a
// less-specific spelling of the other" and "these two names contradict each
// other". It is deliberately tested on raw token slices: the direction-symmetry
// and duplicate-collapse behaviors below are unreachable from a scoring
// assertion alone.
func TestTokenSetContained(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{
			// The ENG-5172 shape itself: the pivot org's single token is a subset of
			// the registrant's descriptor-laden set.
			name: "smaller set contained in larger (first argument)",
			a:    []string{"walmart"},
			b:    []string{"walmart", "global", "enterprises"},
			want: true,
		},
		{
			// Symmetric — the predicate compares the smaller distinct set against
			// the larger, so argument order must not change the answer.
			name: "smaller set contained in larger (second argument)",
			a:    []string{"walmart", "global", "enterprises"},
			b:    []string{"walmart"},
			want: true,
		},
		{
			// Equal sets are subsets of each other. Such a pair already matches on
			// Jaccard 1.0 and never reaches the mismatch arm, but the predicate must
			// still be total rather than accidentally excluding its own boundary.
			name: "equal sets are contained",
			a:    []string{"leica", "biosystems"},
			b:    []string{"biosystems", "leica"},
			want: true,
		},
		{
			// The walmart.com-from-a-Leica-query false positive: zero shared tokens
			// is genuine disagreement, so the mismatch arm must stay open.
			name: "disjoint sets are not contained",
			a:    []string{"leica", "biosystems"},
			b:    []string{"walmart"},
			want: false,
		},
		{
			// The distinction the whole predicate exists to draw: each side
			// contributes a token the other lacks, so neither name is merely a
			// less-specific spelling — this is disagreement, not under-specification.
			name: "partial overlap with private tokens on both sides is not contained",
			a:    []string{"alpha", "bravo", "charlie"},
			b:    []string{"alpha", "bravo", "delta"},
			want: false,
		},
		{
			// The empty set is vacuously a subset of anything; reading that as "one
			// name specializes the other" would be meaningless, so it reports false
			// in both argument positions.
			name: "empty first side is not contained",
			a:    nil,
			b:    []string{"walmart"},
			want: false,
		},
		{
			name: "empty second side is not contained",
			a:    []string{"walmart"},
			b:    nil,
			want: false,
		},
		{
			// Containment is over DISTINCT tokens: a repeated token must not inflate
			// the apparent set size and flip which side is treated as the smaller
			// one. By raw slice length {a,a,a} looks larger than {a,b}, and comparing
			// the wrong direction would answer false.
			name: "duplicate tokens collapse before comparison",
			a:    []string{"acme", "acme", "acme"},
			b:    []string{"acme", "widgets"},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, TokenSetContained(tt.a, tt.b))
		})
	}
}
