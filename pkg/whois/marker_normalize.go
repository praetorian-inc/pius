package whois

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// markerTokenize prepares a value for redaction-marker matching. It is
// deliberately NOT strutil.Tokenize, and deliberately not a replacement for it.
//
// strutil.Tokenize keeps only ASCII [a-z0-9] and treats every other rune as a
// separator. That is correct for org-similarity scoring, where the token space
// is compared against itself and dropping unmappable runes costs only recall.
// It is wrong for marker matching, where the token space is compared against a
// FIXED vocabulary: a wording whose runes are dropped fragments into tokens that
// match no marker, and the value escapes detection entirely (ENG-5420).
//
// Two transformations are needed, and neither is sufficient alone:
//
//   - Diacritic folding, so a Latin-script wording reduces to the ASCII spelling
//     the vocabulary is written in ("protégées" → "protegees").
//   - Preserving non-Latin scripts as tokens rather than deleting them, so a
//     Cyrillic, Greek or CJK wording survives to be matched at all ("скрыто"
//     stays "скрыто" instead of vanishing).
//
// This lives beside the marker vocabulary rather than inside strutil because
// widening strutil.Tokenize would change every org-similarity comparison in the
// codebase — a different blast radius with its own regression surface
// (Corroborate's thresholds, JaccardTokenSets' union sizes). Marker matching is
// a leaf concern and is normalized locally.
func markerTokenize(s string) []string {
	folded := foldForMarkers(s)

	var buf strings.Builder
	buf.Grow(len(folded))
	for _, r := range folded {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			buf.WriteRune(r)
		} else {
			buf.WriteRune(' ')
		}
	}
	return strings.Fields(buf.String())
}

// foldForMarkers lowercases s and reduces Latin letters to their unaccented
// spelling, leaving non-Latin scripts intact.
//
// Two passes are required because Unicode normalization only handles one of the
// two ways a letter can carry a diacritic. NFD/NFKD decomposes PRECOMPOSED
// letters into a base rune plus a combining mark, which the Mn filter then
// drops ("é" → "e" + U+0301 → "e"). But a letter whose diacritic is part of an
// ATOMIC codepoint has no decomposition at all and passes through untouched —
// "ø", "ß", "æ", "ł" and "þ" are single runes with no canonical base letter, so
// normalization alone leaves "Ørsted" as "Ørsted". atomicLatinFolds supplies
// the transliteration Unicode declines to.
//
// NFKD rather than NFD: the compatibility mappings additionally fold fullwidth
// and circled forms ("ＲＥＤＡＣＴＥＤ" → "REDACTED"), which cost nothing here and
// close an obvious evasion. The looser mappings NFKD is otherwise cautioned
// against (ligature splitting, superscript flattening) are harmless against a
// fixed vocabulary — the worst case is a token that matches no marker, which is
// the same outcome as not folding at all.
func foldForMarkers(s string) string {
	lowered := strings.ToLower(s)

	var expanded strings.Builder
	expanded.Grow(len(lowered))
	for _, r := range lowered {
		if repl, ok := atomicLatinFolds[r]; ok {
			expanded.WriteString(repl)
			continue
		}
		expanded.WriteRune(r)
	}

	var out strings.Builder
	out.Grow(expanded.Len())
	var base rune
	for _, r := range norm.NFKD.String(expanded.String()) {
		if !unicode.Is(unicode.Mn, r) {
			base = r
			out.WriteRune(r)
			continue
		}
		// r is a nonspacing combining mark that NFKD just separated from `base`.
		// Whether dropping it is a fold or a corruption depends entirely on the
		// script of the base letter, so the decision is made per-base rather
		// than globally:
		//
		//   - Latin and Greek: the mark is a diacritic or accent layered onto a
		//     letter that stands alone without it. "é"→"e" and "ό"→"ο" are the
		//     folds this function exists to perform.
		//   - Everything else: the mark is part of the letter's identity, and
		//     dropping it changes the word. Japanese dakuten is the case that
		//     matters here — "デ" decomposes to "テ" + U+3099, so a blanket Mn
		//     filter silently rewrites "データ保護" ("data protection") to
		//     "テータ保護", which matches nothing. Cyrillic is excluded for the
		//     same reason: "й" and "ё" are distinct letters from "и" and "е",
		//     not accented forms of them. Indic vowel signs, Hebrew niqqud and
		//     Arabic harakat fall out correctly under the same rule.
		if base != 0 && unicode.In(base, unicode.Latin, unicode.Greek) {
			continue
		}
		out.WriteRune(r)
	}

	// Recompose. NFKD's decomposition is not confined to the marks stripped
	// above: it also splits precomposed Hangul syllables into conjoining Jamo,
	// which are not Mn and so survive the filter in decomposed form. Without
	// this pass "비공개" folds to a Jamo sequence that is no longer byte-equal to
	// the vocabulary entry spelled as syllables. NFC restores both that and the
	// marks deliberately kept above (Jamo → syllable, "テ"+U+3099 → "デ"), while
	// leaving stripped Latin and Greek bases with nothing left to recombine
	// with — so the fold survives it.
	return norm.NFC.String(out.String())
}

// atomicLatinFolds transliterates Latin letters that carry their diacritic or
// modification as an indivisible codepoint, which NFKD therefore cannot
// decompose. Verified by TestAtomicLatinFoldsAreActuallyAtomic, which fails if
// Unicode ever gains a decomposition for one of these — at which point the
// entry is redundant and should be dropped rather than left to shadow the
// standard mapping.
//
// Multi-rune expansions follow the conventional transliterations rather than
// visual approximation: "ß" → "ss" and "æ" → "ae" are how the words are
// actually spelled when the letter is unavailable, and "þ" → "th" likewise.
var atomicLatinFolds = map[rune]string{
	'ø': "o", 'ß': "ss", 'æ': "ae", 'œ': "oe",
	'ł': "l", 'đ': "d", 'ħ': "h", 'ı': "i",
	'ð': "d", 'þ': "th", 'ŋ': "n", 'ŧ': "t",
	'ĸ': "k",
	// NOTE: "ſ" (long s) is deliberately absent — it has an NFKD compatibility
	// mapping to "s", so NFKD already handles it and a manual entry would
	// shadow the standard mapping. TestAtomicLatinFoldsAreActuallyAtomic
	// rejects it if re-added.
}
