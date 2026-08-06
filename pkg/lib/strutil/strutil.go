package strutil

import "strings"

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
