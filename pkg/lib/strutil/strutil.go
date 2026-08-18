package strutil

import "strings"

// ContainsFold reports whether substr occurs in s case-insensitively.
func ContainsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// Tokenize lowercases s and splits on non-alphanumeric characters.
func Tokenize(s string) []string {
	s = strings.ToLower(s)
	var buf strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			buf.WriteRune(c)
		} else {
			buf.WriteByte(' ')
		}
	}
	return strings.Fields(buf.String())
}

// TokenSimilarity computes the ratio of shared tokens between two strings.
// Uses the shorter set as the denominator so partial matches score well.
func TokenSimilarity(a, b string) float64 {
	aT := Tokenize(a)
	bT := Tokenize(b)
	if len(aT) == 0 || len(bT) == 0 {
		return 0
	}
	shorter, longer := aT, bT
	if len(aT) > len(bT) {
		shorter, longer = bT, aT
	}
	inLonger := make(map[string]bool, len(longer))
	for _, t := range longer {
		inLonger[t] = true
	}
	matches := 0
	for _, t := range shorter {
		if inLonger[t] {
			matches++
		}
	}
	return float64(matches) / float64(len(shorter))
}

// JaccardTokenSets computes the Jaccard similarity of two token slices:
// |A ∩ B| / |A ∪ B|, over their DISTINCT tokens. Unlike TokenSimilarity, which
// divides by the SHORTER set (containment), Jaccard counts tokens present on
// only one side against the score, so a short string merely CONTAINED in a
// longer one no longer scores 1.0.
//
// This is the metric org-name corroboration needs (ENG-5172). A single-token
// query org such as "Acme" against a registrant "Acme Enterprises LLC"
// (normalized {acme} vs {acme, enterprises}) scores 1/2 = 0.5 under Jaccard,
// not the 1/1 = 1.0 containment gave — so it lands mid-band and needs review
// instead of spuriously corroborating.
//
// It takes tokenized input so callers that must normalize first (whois's
// legal-suffix stripping) tokenize only once. Returns 0 when either side is
// empty; past that guard both sets hold at least one token, so the union is
// always >= 1 and the division is safe.
func JaccardTokenSets(aT, bT []string) float64 {
	if len(aT) == 0 || len(bT) == 0 {
		return 0
	}
	inA := distinct(aT)
	inB := distinct(bT)
	intersection := 0
	for t := range inA {
		if inB[t] {
			intersection++
		}
	}
	union := len(inA) + len(inB) - intersection
	return float64(intersection) / float64(union)
}

// TokenSetContained reports whether either side's DISTINCT token set is a
// subset of the other's. It exists to separate the two things a low Jaccard
// score conflates: DISAGREEMENT and UNDER-SPECIFICATION.
//
// Genuine disagreement means each name contributes at least one token the
// other lacks. Containment is not that: when one token set is a subset of the
// other, one name is simply a LESS-SPECIFIC spelling of the same name
// ("Walmart" vs "Walmart Global Enterprises Holdings"), which is unverifiable
// rather than contradictory. Jaccard alone cannot tell them apart, because it
// divides by the union — a fully contained single-token org drops below any
// mismatch floor as soon as the other side adds a few descriptor tokens.
//
// Comparing only the smaller set against the larger is exhaustive: a strictly
// larger set can never be a subset of a smaller one, and equal-sized sets are
// subsets only when equal, which either direction detects. An empty side
// returns false — the empty set is vacuously a subset of anything, and reading
// that as "one name specializes the other" would be meaningless.
func TokenSetContained(aT, bT []string) bool {
	if len(aT) == 0 || len(bT) == 0 {
		return false
	}
	inA := distinct(aT)
	inB := distinct(bT)
	smaller, larger := inA, inB
	if len(inB) < len(inA) {
		smaller, larger = inB, inA
	}
	for t := range smaller {
		if !larger[t] {
			return false
		}
	}
	return true
}

// distinct collapses a token slice into a set, so duplicate tokens cannot
// inflate an apparent set size.
func distinct(tokens []string) map[string]bool {
	set := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		set[t] = true
	}
	return set
}

// UniqueFunc returns a new slice containing only the first occurrence of each
// element as determined by the key function, preserving order.
func UniqueFunc[T any, K comparable](s []T, key func(T) K) []T {
	seen := make(map[K]struct{}, len(s))
	out := make([]T, 0, len(s))
	for _, v := range s {
		k := key(v)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	return out
}

// Unique returns a new slice containing only the first occurrence of each
// element, preserving order.
func Unique[T comparable](s []T) []T {
	return UniqueFunc(s, func(v T) T { return v })
}
