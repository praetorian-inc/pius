package whois

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/unicode/norm"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
)

// TestMarkerTokenizePreservesWhatStrutilDeletes is the regression test for the
// root cause in ENG-5420. strutil.Tokenize keeps only ASCII [a-z0-9], so a
// non-ASCII wording either fragments (Latin-with-diacritics) or vanishes
// entirely (non-Latin scripts). markerTokenize must do neither.
func TestMarkerTokenizePreservesWhatStrutilDeletes(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		strutil []string // what the similarity tokenizer produces — the bug
		marker  []string // what marker matching needs
	}{
		{
			name:    "latin diacritics fragment under strutil",
			in:      "Données protégées",
			strutil: []string{"donn", "es", "prot", "g", "es"},
			marker:  []string{"donnees", "protegees"},
		},
		{
			name:    "cyrillic vanishes under strutil",
			in:      "Данные защищены",
			strutil: []string{},
			marker:  []string{"данные", "защищены"},
		},
		{
			name:    "cjk vanishes under strutil",
			in:      "データ保護",
			strutil: []string{},
			marker:  []string{"データ保護"},
		},
		{
			name:    "greek tonos folds to bare vowel",
			in:      "Απόκρυψη δεδομένων",
			strutil: []string{},
			marker:  []string{"αποκρυψη", "δεδομενων"},
		},
		{
			name:    "ascii is unchanged by either",
			in:      "REDACTED FOR PRIVACY",
			strutil: []string{"redacted", "for", "privacy"},
			marker:  []string{"redacted", "for", "privacy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.strutil, strutil.Tokenize(tt.in),
				"strutil.Tokenize baseline changed — if this is intentional, the "+
					"similarity-scoring tests must be re-run (ENG-5420 AC5)")
			assert.Equal(t, tt.marker, markerTokenize(tt.in))
		})
	}
}

// TestFoldForMarkersHandlesBothDiacriticForms covers the two-pass structure:
// precomposed letters fold via NFKD, atomic letters via atomicLatinFolds.
func TestFoldForMarkersHandlesBothDiacriticForms(t *testing.T) {
	tests := []struct{ in, want string }{
		// Precomposed — NFKD decomposes, Mn filter strips.
		{"rédacted", "redacted"},
		{"DONNÉES PROTÉGÉES", "donnees protegees"},
		{"geschwärzt", "geschwarzt"},
		{"gizlenmiş", "gizlenmis"},
		{"zastrzeżone", "zastrzezone"},
		{"chráněná", "chranena"},

		// Atomic — no decomposition exists; atomicLatinFolds supplies it.
		{"Ørsted", "orsted"},
		{"Straße", "strasse"},
		{"Æther", "aether"},
		{"Łódź", "lodz"},
		{"Þagnarskylda", "thagnarskylda"},

		// NFKD compatibility forms — fullwidth evasion.
		{"ＲＥＤＡＣＴＥＤ", "redacted"},

		// Non-Latin passes through, lowercased where the script has case.
		{"СКРЫТО", "скрыто"},
		{"データ保護", "データ保護"},

		{"", ""},
	}
	for _, tt := range tests {
		assert.Equalf(t, tt.want, foldForMarkers(tt.in), "foldForMarkers(%q)", tt.in)
	}
}

// TestAtomicLatinFoldsAreActuallyAtomic guards the premise of the second fold
// pass: every entry must be a letter Unicode does NOT decompose. If Unicode
// gains a decomposition for one, the manual entry is redundant and should be
// removed rather than left to shadow the standard mapping.
func TestAtomicLatinFoldsAreActuallyAtomic(t *testing.T) {
	for r := range atomicLatinFolds {
		s := string(r)
		var stripped strings.Builder
		for _, d := range norm.NFKD.String(s) {
			if !unicode.Is(unicode.Mn, d) {
				stripped.WriteRune(d)
			}
		}
		assert.Equalf(t, s, stripped.String(),
			"%q now has a Unicode decomposition — drop it from atomicLatinFolds "+
				"and let NFKD handle it", s)
	}
}

// TestMarkerVocabularyIsFoldStable is the invariant that keeps a mistyped
// vocabulary entry from silently never matching. Entries must be written in the
// spelling foldForMarkers produces; an entry still carrying its original accents
// ("protégées" rather than "protegees") can never be reached, and without this
// test it would sit dead in the list indefinitely.
func TestMarkerVocabularyIsFoldStable(t *testing.T) {
	for token := range markerTokens {
		assert.Equalf(t, token, foldForMarkers(token),
			"markerTokens entry %q is not fold-stable; write it as %q",
			token, foldForMarkers(token))
		assert.Equalf(t, []string{token}, markerTokenize(token),
			"markerTokens entry %q must tokenize to exactly one token — a "+
				"multi-word entry belongs in markerPhrases", token)
	}

	for _, phrase := range markerPhrases {
		require.Greaterf(t, len(phrase), 1,
			"markerPhrases entry %v has one word — it belongs in markerTokens", phrase)
		for _, word := range phrase {
			assert.Equalf(t, word, foldForMarkers(word),
				"markerPhrases word %q is not fold-stable; write it as %q",
				word, foldForMarkers(word))
		}
	}

	for _, sub := range markerSubstrings {
		assert.Equalf(t, sub, foldForMarkers(sub),
			"markerSubstrings entry %q is not fold-stable; write it as %q",
			sub, foldForMarkers(sub))
	}
}

// TestMarkerSubstringsCarryNoLatin enforces the safety premise of the
// containment pass. Whole-token matching is what prevents "Redactron Systems"
// from matching "redact"; markerSubstrings bypasses that, and is only safe
// because a non-Latin sequence cannot occur inside a Latin trading name. A
// Latin entry added here would reintroduce the false positive.
func TestMarkerSubstringsCarryNoLatin(t *testing.T) {
	for _, sub := range markerSubstrings {
		for _, r := range sub {
			assert.Falsef(t, unicode.In(r, unicode.Latin),
				"markerSubstrings entry %q contains Latin letter %q — containment "+
					"matching on Latin text reintroduces the substring false "+
					"positive; put it in markerTokens or markerPhrases instead",
				sub, r)
		}
	}
}
