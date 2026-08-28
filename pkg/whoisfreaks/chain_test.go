package whoisfreaks

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise validateChain (§3.7 chain self-consistency
// classification). They assert on the function's observable contract — the
// (valid, anomalies, out) triple — never on internals: the deterministic
// anomaly ordering, the fixed anomaly strings (including the exact U+2192 "→"
// and U+2260 "≠" glyphs), the sanitized out-copy (non-hex serials blanked, a
// fabricated root dropped), and the promise that the caller's input is never
// mutated.
//
// Fixtures are inline, obviously-synthetic Certificate literals — no real
// certificates, PEM, keys, or captured provider bytes. The one oversized chain
// (truncation case) is generated in-test rather than committed as a file.

// mkCert builds a minimal, obviously-fake Certificate for chain tests. Only the
// fields validateChain reads (Subject/Issuer via DN.CommonName, SerialNumber,
// ChainOrder) are populated.
func mkCert(subjectCN, issuerCN, serial, order string) Certificate {
	return Certificate{
		Subject:      DN{CommonName: subjectCN},
		Issuer:       DN{CommonName: issuerCN},
		SerialNumber: serial,
		ChainOrder:   order,
	}
}

// assertValidInvariant checks the documented invariant valid == (len(anomalies)
// == 0). Every case asserts it so a regression that decouples the flag from the
// anomaly list is caught behaviorally.
func assertValidInvariant(t *testing.T, valid bool, anomalies []string) {
	t.Helper()
	assert.Equal(t, len(anomalies) == 0, valid,
		"valid must equal (len(anomalies)==0); anomalies=%v", anomalies)
}

// TestValidateChain_GoldenPath: a correctly linked leaf→intermediate→root chain
// with a self-signed root and hex serials is self-consistent — no anomalies,
// and out is an identical (sanitized) copy of the input.
func TestValidateChain_GoldenPath(t *testing.T) {
	t.Parallel()

	certs := []Certificate{
		mkCert("leaf.example", "Example Intermediate CA", "1a2b", "leaf"),
		mkCert("Example Intermediate CA", "Example Root CA", "0af9", "intermediate"),
		mkCert("Example Root CA", "Example Root CA", "deadBEEF", "root"),
	}

	valid, anomalies, out := validateChain(certs)

	assert.True(t, valid, "a well-linked, self-signed-root chain is self-consistent")
	assert.Empty(t, anomalies, "the golden path raises no anomalies")
	assertValidInvariant(t, valid, anomalies)

	require.Len(t, out, 3, "no cert is dropped on the golden path")
	assert.Equal(t, certs, out, "out must equal the input when nothing is sanitized")
	assert.Equal(t, "root", out[2].ChainOrder, "a valid self-signed root is retained")
	assert.Equal(t, "deadBEEF", out[2].SerialNumber, "a valid serial is preserved verbatim")
}

// TestValidateChain_MidChainLinkBreak: a Rule 1 issuer≠subject break between two
// intermediates surfaces exactly one link-break anomaly for the offending pair,
// with the exact glyphs, and leaves the (valid) root in place.
func TestValidateChain_MidChainLinkBreak(t *testing.T) {
	t.Parallel()

	certs := []Certificate{
		mkCert("leaf.example", "Intermediate A", "1a", "leaf"),
		mkCert("Intermediate A", "Mismatched Issuer", "2b", "intermediate"), // Issuer != next Subject
		mkCert("Intermediate B", "Example Root CA", "3c", "intermediate"),
		mkCert("Example Root CA", "Example Root CA", "4d", "root"),
	}

	valid, anomalies, out := validateChain(certs)

	assert.False(t, valid, "a mid-chain link break makes the chain inconsistent")
	assertValidInvariant(t, valid, anomalies)
	// Exactly the Rule 1 producer for the [1]→[2] pair — nothing else fires.
	assert.Equal(t, []string{"link break [1]→[2]: issuer≠subject"}, anomalies)

	// The into-root pair is well-linked and the root is a valid self-signed
	// root, so no Rule 2 anomaly fires and the root stays in out.
	assert.NotContains(t, anomalies, "root not self-signed")
	assert.NotContains(t, anomalies, "root subject≠prior issuer")
	require.Len(t, out, 4, "a mid-chain break does not drop the valid root")
	assert.Equal(t, "root", out[3].ChainOrder)
}

// TestValidateChain_ActalisMisassembled is the load-bearing ordering case: a
// self-signed terminal root whose subject does not match the prior cert's
// issuer, carrying a non-hex serial. Rule 3 (serial) must be reported before
// Rule 2 (root sanity); the into-root gap is a single "root subject≠prior
// issuer", never also a Rule 1 link break; and the fabricated root is dropped.
func TestValidateChain_ActalisMisassembled(t *testing.T) {
	t.Parallel()

	const badSerial = "Signature Algorithm: sha256WithRSAEncryption"
	certs := []Certificate{
		mkCert("leaf.example", "Intermediate 1", "1a2b", "leaf"),
		mkCert("Intermediate 1", "Intermediate 2", "0af9", "intermediate"),
		mkCert("Intermediate 2", "Real Root CA", "0bde", "intermediate"), // prior issuer = Real Root CA
		mkCert("Fake Root CA", "Fake Root CA", badSerial, "root"),        // self-signed, subject != prior issuer, non-hex serial
	}

	valid, anomalies, out := validateChain(certs)

	assert.False(t, valid)
	assertValidInvariant(t, valid, anomalies)
	// Exact anomaly list AND exact order: Rule 3 (index 3) precedes Rule 2.
	assert.Equal(t, []string{"non-hex serial [3]", "root subject≠prior issuer"}, anomalies)

	// The self-signed root passes the "self-signed" check, so this must NOT fire.
	assert.NotContains(t, anomalies, "root not self-signed")
	// The into-root gap is owned by Rule 2 and never double-reported as a break.
	assert.NotContains(t, anomalies, "link break [2]→[3]: issuer≠subject")

	require.Len(t, out, 3, "the fabricated root is dropped; the three good certs remain")
	assert.Equal(t, "leaf.example", out[0].Subject.CommonName)
	assert.Equal(t, "Intermediate 2", out[2].Subject.CommonName)

	// Mutation check: the caller's input element keeps its original non-hex
	// serial — only the fresh out-copy is blanked.
	assert.Equal(t, badSerial, certs[3].SerialNumber, "input serial must not be mutated")
	assert.Len(t, certs, 4, "input length must be unchanged")
}

// TestValidateChain_RootNotSelfSigned: a terminal root whose subject links to
// the prior issuer but whose issuer != its own subject raises "root not
// self-signed" only, and drops the root.
func TestValidateChain_RootNotSelfSigned(t *testing.T) {
	t.Parallel()

	certs := []Certificate{
		mkCert("leaf.example", "Intermediate CA", "1a", "leaf"),
		mkCert("Intermediate CA", "Root CA", "2b", "intermediate"),
		mkCert("Root CA", "Different Issuer", "3c", "root"), // subject==prior issuer, but issuer != subject
	}

	valid, anomalies, out := validateChain(certs)

	assert.False(t, valid)
	assertValidInvariant(t, valid, anomalies)
	assert.Equal(t, []string{"root not self-signed"}, anomalies)
	assert.NotContains(t, anomalies, "root subject≠prior issuer")
	require.Len(t, out, 2, "a non-self-signed root is dropped from out")
}

// TestValidateChain_SingleNonSelfSignedRoot_RetainsIndex0 pins the documented
// invariant that out ALWAYS retains index 0 (the leaf), even when the terminal
// root is dropped. A one-cert chain whose sole cert claims to be a root but is
// NOT self-signed is the degenerate case where last==0: dropping the "root"
// (out = out[:last]) collapses to out[:0] and erases the leaf, so a caller
// reading out[0] on a false result gets an empty slice instead of the classified
// leaf. The (valid, anomalies) classification is correct and asserted here; the
// load-bearing assertion is that the returned slice still carries the single
// input cert at index 0 rather than being emptied.
func TestValidateChain_SingleNonSelfSignedRoot_RetainsIndex0(t *testing.T) {
	t.Parallel()

	// A single cert that claims root order but is not self-signed
	// (Subject != Issuer). The serial is valid hex so Rule 3 stays silent and
	// "root not self-signed" is the only anomaly.
	cert := mkCert("Fake Root CA", "Different Issuer CA", "1a2b", "root")
	certs := []Certificate{cert}

	valid, anomalies, out := validateChain(certs)

	// Classification: a non-self-signed root is an anomaly, so the chain is
	// inconsistent and the sole anomaly is the root-sanity defect.
	assert.False(t, valid, "a non-self-signed root makes the chain inconsistent")
	assertValidInvariant(t, valid, anomalies)
	assert.Equal(t, []string{"root not self-signed"}, anomalies,
		"the only defect is the root failing the self-signed check")

	// Load-bearing invariant: out retains index 0 (the leaf) in every case. With
	// last==0, dropping the fabricated root must not empty the slice.
	require.Len(t, out, 1,
		"out must retain the single input cert at index 0; dropping the root must not empty the slice")
	assert.Equal(t, cert, out[0],
		"the retained index-0 cert must be the input cert (hex serial preserved, unmutated)")

	// The caller's input is never mutated.
	require.Len(t, certs, 1, "input length must be unchanged")
	assert.Equal(t, cert, certs[0], "input cert must not be mutated")
}

// TestValidateChain_RootBothDefects: a terminal root that is neither
// self-signed nor linked to the prior issuer raises BOTH root anomalies, in
// order, and is dropped exactly once.
func TestValidateChain_RootBothDefects(t *testing.T) {
	t.Parallel()

	certs := []Certificate{
		mkCert("leaf.example", "Intermediate CA", "1a", "leaf"),
		mkCert("Intermediate CA", "Root CA", "2b", "intermediate"),
		mkCert("Fake Root", "Other Issuer", "3c", "root"), // not self-signed AND subject != prior issuer
	}

	valid, anomalies, out := validateChain(certs)

	assert.False(t, valid)
	assertValidInvariant(t, valid, anomalies)
	assert.Equal(t, []string{"root not self-signed", "root subject≠prior issuer"}, anomalies)
	require.Len(t, out, 2, "the fabricated root is dropped exactly once")
}

// TestValidateChain_SerialRegexBoundaries drives the Rule 3 serial predicate
// (^[0-9A-Fa-f:]+$, empty counts as non-hex) through a single leaf-only cert so
// the serial is the only thing under test. Valid serials are preserved and
// raise nothing; invalid serials raise "non-hex serial [0]" and are blanked in
// out — but never mutated on the input.
func TestValidateChain_SerialRegexBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		serial    string
		wantValid bool
	}{
		{"lowercase hex", "1a2b3c", true},
		{"colon-separated hex", "01:AF:9C:DE", true},
		{"mixed-case hex", "deadBEEF", true},
		{"single zero digit", "0", true},
		{"empty serial is non-hex", "", false},
		{"embedded space", "12 34", false},
		{"0x prefix contains x", "0x1a2b", false},
		{"non-hex letter g", "g123", false},
		{"provider label leak", "Signature Algorithm: sha256WithRSAEncryption", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certs := []Certificate{mkCert("leaf.example", "Intermediate CA", tt.serial, "leaf")}
			valid, anomalies, out := validateChain(certs)

			assertValidInvariant(t, valid, anomalies)
			require.Len(t, out, 1)

			if tt.wantValid {
				assert.True(t, valid, "a valid hex serial raises no anomaly")
				assert.Empty(t, anomalies)
				assert.Equal(t, tt.serial, out[0].SerialNumber, "a valid serial is preserved")
			} else {
				assert.False(t, valid, "a non-hex serial raises an anomaly")
				assert.Equal(t, []string{"non-hex serial [0]"}, anomalies)
				assert.Equal(t, "", out[0].SerialNumber, "a non-hex serial is blanked in out")
			}
			// The caller's input serial is never mutated, either way.
			assert.Equal(t, tt.serial, certs[0].SerialNumber, "input serial must be unchanged")
		})
	}
}

// genLinkedChain builds a cleanly linked chain of count synthetic certs:
// cert[i].Issuer == cert[i+1].Subject, all-hex serials, and no terminal root
// (so the truncation anomaly is the only thing that can fire). Generated in-test
// rather than committed as a fixture file.
func genLinkedChain(count int) []Certificate {
	certs := make([]Certificate, count)
	for i := 0; i < count; i++ {
		order := "intermediate"
		if i == 0 {
			order = "leaf"
		}
		certs[i] = mkCert(
			fmt.Sprintf("node-%d", i),
			fmt.Sprintf("node-%d", i+1),
			fmt.Sprintf("%x", i+1), // hex serial, never empty
			order,
		)
	}
	return certs
}

// TestChainAndCreditCapsAreEqual pins the load-bearing invariant that the chain
// processing cap (maxProcessedChainCerts, chain.go) and the credit accounting cap
// (maxChainCertsForCredit, credits.go) hold the SAME value. They are two
// INDEPENDENT const declarations in separate files; chain.go's doc comment
// requires they stay equal so the chain validator and the credit meter agree on
// one processing bound (security T6/T7). A future edit that bumps one without the
// other would silently let a provider-inflated chain be processed and billed
// against different caps — this test fails the instant the two constants diverge.
func TestChainAndCreditCapsAreEqual(t *testing.T) {
	t.Parallel()
	assert.Equal(t, maxProcessedChainCerts, maxChainCertsForCredit,
		"the chain processing cap (chain.go) and the credit accounting cap "+
			"(credits.go) must be identical; see the doc comment on "+
			"maxProcessedChainCerts")
}

// TestValidateChain_TruncationCap: an oversized chain is capped at
// maxProcessedChainCerts with a single "chain truncated at 16" anomaly and no
// more than the cap in out; a chain exactly at the cap is not truncated. Neither
// panics.
func TestValidateChain_TruncationCap(t *testing.T) {
	t.Parallel()

	t.Run("chain longer than the cap is truncated", func(t *testing.T) {
		t.Parallel()
		certs := genLinkedChain(20)

		valid, anomalies, out := validateChain(certs)

		assertValidInvariant(t, valid, anomalies)
		assert.Contains(t, anomalies, "chain truncated at 16")
		// Linkage is clean and there is no terminal root, so truncation is the
		// sole anomaly.
		assert.Equal(t, []string{"chain truncated at 16"}, anomalies)
		assert.False(t, valid)
		assert.LessOrEqual(t, len(out), maxProcessedChainCerts, "never processes more than the cap")
		assert.Len(t, out, maxProcessedChainCerts, "exactly the cap is processed")
		assert.Len(t, certs, 20, "the oversized input is not mutated")
	})

	t.Run("chain exactly at the cap is not truncated", func(t *testing.T) {
		t.Parallel()
		certs := genLinkedChain(maxProcessedChainCerts)

		valid, anomalies, out := validateChain(certs)

		assertValidInvariant(t, valid, anomalies)
		assert.NotContains(t, anomalies, "chain truncated at 16")
		assert.True(t, valid, "a clean 16-cert chain has no anomalies")
		assert.Empty(t, anomalies)
		assert.Len(t, out, maxProcessedChainCerts)
	})
}

// TestValidateChain_EmptyNilAndSingle: the degenerate inputs. nil and empty are
// vacuously valid with nil anomalies and nil out; a single valid leaf is
// self-consistent. None panic.
func TestValidateChain_EmptyNilAndSingle(t *testing.T) {
	t.Parallel()

	t.Run("nil input is vacuously valid", func(t *testing.T) {
		t.Parallel()
		valid, anomalies, out := validateChain(nil)
		assert.True(t, valid)
		assert.Nil(t, anomalies)
		assert.Nil(t, out)
	})

	t.Run("empty slice is vacuously valid", func(t *testing.T) {
		t.Parallel()
		valid, anomalies, out := validateChain([]Certificate{})
		assert.True(t, valid)
		assert.Nil(t, anomalies)
		assert.Nil(t, out)
	})

	t.Run("single valid leaf is self-consistent", func(t *testing.T) {
		t.Parallel()
		certs := []Certificate{mkCert("leaf.example", "Intermediate CA", "1a2b", "leaf")}
		valid, anomalies, out := validateChain(certs)
		assert.True(t, valid)
		assert.Empty(t, anomalies)
		assertValidInvariant(t, valid, anomalies)
		require.Len(t, out, 1)
		assert.Equal(t, "1a2b", out[0].SerialNumber)
	})
}

// TestValidateChain_DoesNotMutateInput exercises the immutability promise on the
// case that triggers BOTH sanitizations (a blanked serial at index 3 and a
// dropped root): the caller's slice keeps all four elements and every original
// serial and ChainOrder, while out is the shorter sanitized copy.
func TestValidateChain_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	const badSerial = "Signature Algorithm: sha256WithRSAEncryption"
	certs := []Certificate{
		mkCert("leaf.example", "Intermediate 1", "1a2b", "leaf"),
		mkCert("Intermediate 1", "Intermediate 2", "0af9", "intermediate"),
		mkCert("Intermediate 2", "Real Root CA", "0bde", "intermediate"),
		mkCert("Fake Root CA", "Fake Root CA", badSerial, "root"),
	}

	wantSerials := []string{"1a2b", "0af9", "0bde", badSerial}
	wantOrders := []string{"leaf", "intermediate", "intermediate", "root"}

	_, _, out := validateChain(certs)

	// out is the sanitized copy with the root dropped; the input is untouched.
	assert.Len(t, out, 3, "out drops the fabricated root")
	require.Len(t, certs, len(wantSerials), "input slice length must be unchanged")
	for i := range certs {
		assert.Equal(t, wantSerials[i], certs[i].SerialNumber,
			"input serial at [%d] must be unchanged (incl. the out-blanked index 3)", i)
		assert.Equal(t, wantOrders[i], certs[i].ChainOrder,
			"input ChainOrder at [%d] must be unchanged", i)
	}
	assert.Equal(t, badSerial, certs[3].SerialNumber, "the non-hex serial out blanked is intact on input")
}
