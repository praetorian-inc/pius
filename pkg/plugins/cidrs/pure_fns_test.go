package cidrs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── splitHandles (rdap.go) ────────────────────────────────────────────────────

func TestSplitHandles_BasicCSV(t *testing.T) {
	result := splitHandles("ACME-1,ACME-2,ACME-3")
	assert.Equal(t, []string{"ACME-1", "ACME-2", "ACME-3"}, result)
}

func TestSplitHandles_TrimsWhitespace(t *testing.T) {
	result := splitHandles("  ACME-1 , ACME-2  ,  ACME-3  ")
	assert.Equal(t, []string{"ACME-1", "ACME-2", "ACME-3"}, result)
}

func TestSplitHandles_SkipsEmptySegments(t *testing.T) {
	result := splitHandles("ACME-1,,ACME-3,")
	assert.Equal(t, []string{"ACME-1", "ACME-3"}, result)
}

func TestSplitHandles_SingleHandle(t *testing.T) {
	result := splitHandles("GOOGL-161")
	assert.Equal(t, []string{"GOOGL-161"}, result)
}

func TestSplitHandles_EmptyString(t *testing.T) {
	result := splitHandles("")
	assert.Empty(t, result)
}

func TestSplitHandles_OnlyCommas(t *testing.T) {
	result := splitHandles(",,,")
	assert.Empty(t, result)
}

// ── isLikelyRIRHandle (edgar.go) ─────────────────────────────────────────────

func TestIsLikelyRIRHandle_AcceptsRealHandles(t *testing.T) {
	handles := []string{
		"ACME-1",        // ARIN org
		"ORG-GOOG1-RIPE", // RIPE org
		"GOOGL-161",     // ARIN handle
		"MX-USCV4-LACNIC", // LACNIC
		"ORG-AP123-AP",  // APNIC
	}
	for _, h := range handles {
		assert.True(t, isLikelyRIRHandle(h), "expected %q to be accepted", h)
	}
}

func TestIsLikelyRIRHandle_RejectsNonRIRPrefixes(t *testing.T) {
	handles := []string{
		"SEC-123",     // SEC filing ID
		"EIN-456",     // Employer ID
		"CIK-789",     // Central Index Key
		"NYSE-ACME",   // Stock exchange
		"IRS-001",     // Tax authority
		"CUSIP-1234",  // Securities ID
		"FORM-10K",    // SEC form type
	}
	for _, h := range handles {
		assert.False(t, isLikelyRIRHandle(h), "expected %q to be rejected", h)
	}
}

func TestIsLikelyRIRHandle_CaseSensitive(t *testing.T) {
	// Filter checks HasPrefix — make sure it works with uppercase (as produced by EDGAR)
	assert.False(t, isLikelyRIRHandle("SEC-FILING"))
	assert.True(t, isLikelyRIRHandle("PRAETORIAN-1")) // no blocklisted prefix
}
