package whoisfreaks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDN_Equal exercises the linkage primitive that chain validation (§3.7)
// relies on: Chain[n].Issuer.Equal(Chain[n+1].Subject). Equal is normalized
// (whitespace collapsed, ASCII case folded), so cosmetically different but
// semantically identical DNs match, while a genuine subject≠issuer mismatch
// (the mis-assembled-root case) does not.
//
// Note on Raw authority: DN.String uses Raw verbatim when set; so a linkage
// comparison is only meaningful when both DNs are expressed the same way (both
// Raw, or both structured). Each case below keeps the two sides consistent.
func TestDN_Equal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    DN
		b    DN
		want bool
	}{
		{
			name: "identical structured DNs are equal",
			a:    DN{CommonName: "Example CA", Organization: []string{"Example Inc"}, Country: []string{"US"}},
			b:    DN{CommonName: "Example CA", Organization: []string{"Example Inc"}, Country: []string{"US"}},
			want: true,
		},
		{
			name: "well-linked chain pair (issuer == next subject) is equal",
			// leaf.Issuer vs intermediate.Subject in a correctly assembled chain.
			a:    DN{CommonName: "R3", Organization: []string{"Let's Encrypt"}, Country: []string{"US"}},
			b:    DN{CommonName: "R3", Organization: []string{"Let's Encrypt"}, Country: []string{"US"}},
			want: true,
		},
		{
			name: "mis-assembled linkage pair (subject != issuer) is not equal",
			// The 2026-08-06 Actalis-style injection: the leaf's real issuer does
			// not match the subject of the wrongly-appended next cert.
			a:    DN{CommonName: "R3", Organization: []string{"Let's Encrypt"}, Country: []string{"US"}},
			b:    DN{CommonName: "Actalis Authentication Root CA", Organization: []string{"Actalis S.p.A."}, Country: []string{"IT"}},
			want: false,
		},
		{
			name: "whitespace runs are collapsed (Raw form)",
			a:    DN{Raw: "CN=Example CA, O=Example Inc"},
			b:    DN{Raw: "CN=Example CA,   O=Example   Inc"},
			want: true,
		},
		{
			name: "ASCII case is folded (Raw form)",
			a:    DN{Raw: "cn=example ca, o=example inc"},
			b:    DN{Raw: "CN=Example CA, O=Example Inc"},
			want: true,
		},
		{
			name: "different common name is not equal",
			a:    DN{CommonName: "leaf.example.com"},
			b:    DN{CommonName: "other.example.com"},
			want: false,
		},
		{
			name: "empty DNs are equal (both stringify to empty)",
			a:    DN{},
			b:    DN{},
			want: true,
		},
		{
			name: "empty vs non-empty is not equal",
			a:    DN{},
			b:    DN{CommonName: "leaf.example.com"},
			want: false,
		},
		{
			name: "empty organization entries are skipped before comparison",
			a:    DN{CommonName: "Example CA", Organization: []string{"Example Inc", "", "  "}},
			b:    DN{CommonName: "Example CA", Organization: []string{"Example Inc"}},
			want: true,
		},
		{
			name: "differing order of structured attributes is not equal",
			// Same field values, different DN ordering -> different String() form.
			a:    DN{Raw: "CN=R3, O=Let's Encrypt, C=US"},
			b:    DN{Raw: "O=Let's Encrypt, CN=R3, C=US"},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.a.Equal(tt.b)
			assert.Equal(t, tt.want, got, "Equal(%q, %q)", tt.a.String(), tt.b.String())
			// Equal must be symmetric.
			assert.Equal(t, tt.want, tt.b.Equal(tt.a), "Equal is not symmetric for %q / %q", tt.a.String(), tt.b.String())
		})
	}
}

// TestDN_String verifies the exact display form (fixed CN, O, C order; Raw
// authoritative; empty/whitespace attributes skipped; values trimmed) AND that
// String is deterministic: repeated calls on the same DN return byte-identical
// output. Determinism matters because String feeds Equal, which drives chain
// linkage decisions.
func TestDN_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dn   DN
		want string
	}{
		{
			name: "Raw is authoritative and overrides structured fields",
			dn:   DN{CommonName: "ignored", Organization: []string{"ignored"}, Country: []string{"XX"}, Raw: "CN=real, O=RealOrg"},
			want: "CN=real, O=RealOrg",
		},
		{
			name: "Raw is trimmed of surrounding whitespace",
			dn:   DN{Raw: "  CN=leaf.example.com  "},
			want: "CN=leaf.example.com",
		},
		{
			name: "structured attributes assemble in CN, O, C order",
			dn:   DN{CommonName: "Example CA", Organization: []string{"Example Inc"}, Country: []string{"US"}},
			want: "CN=Example CA, O=Example Inc, C=US",
		},
		{
			name: "multiple organizations and countries each get their prefix",
			dn:   DN{CommonName: "CA", Organization: []string{"Org1", "Org2"}, Country: []string{"US", "GB"}},
			want: "CN=CA, O=Org1, O=Org2, C=US, C=GB",
		},
		{
			name: "empty and whitespace-only attributes are skipped",
			dn:   DN{CommonName: "", Organization: []string{"", "  ", "RealOrg"}, Country: []string{""}},
			want: "O=RealOrg",
		},
		{
			name: "attribute values are trimmed",
			dn:   DN{CommonName: "  spaced cn  ", Organization: []string{"  Org  "}},
			want: "CN=spaced cn, O=Org",
		},
		{
			name: "empty DN yields empty string",
			dn:   DN{},
			want: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got1 := tt.dn.String()
			assert.Equal(t, tt.want, got1)

			// Determinism: same input -> same output across repeated calls.
			got2 := tt.dn.String()
			got3 := tt.dn.String()
			assert.Equal(t, got1, got2, "String is not deterministic across calls")
			assert.Equal(t, got1, got3, "String is not deterministic across calls")
		})
	}
}
