package cidrs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// ── ArinRefs UnmarshalJSON (reverse_rir.go) ─────────────────────────────────

func TestArinRefs_UnmarshalArray(t *testing.T) {
	data := `[{"@handle":"ACME-1","@name":"Acme"},{"@handle":"ACME-2","@name":"Acme Inc"}]`
	var refs ArinRefs
	require.NoError(t, json.Unmarshal([]byte(data), &refs))
	require.Len(t, refs, 2)
	assert.Equal(t, "ACME-1", refs[0].Handle)
	assert.Equal(t, "ACME-2", refs[1].Handle)
}

func TestArinRefs_UnmarshalSingleObject(t *testing.T) {
	data := `{"@handle":"PS-1576","@name":"Praetorian Security, Inc."}`
	var refs ArinRefs
	require.NoError(t, json.Unmarshal([]byte(data), &refs))
	require.Len(t, refs, 1)
	assert.Equal(t, "PS-1576", refs[0].Handle)
}

func TestArinRefs_UnmarshalNull(t *testing.T) {
	data := `null`
	var refs ArinRefs
	require.NoError(t, json.Unmarshal([]byte(data), &refs))
	assert.Empty(t, refs)
}

func TestArinOrgsResponse_SingleResult(t *testing.T) {
	data := `{"orgs":{"orgRef":{"@handle":"PS-1576","@name":"Praetorian Security, Inc."}}}`
	var resp ArinOrgsResponse
	require.NoError(t, json.Unmarshal([]byte(data), &resp))
	require.Len(t, resp.Orgs.OrgRef, 1)
	assert.Equal(t, "PS-1576", resp.Orgs.OrgRef[0].Handle)
}

func TestArinOrgsResponse_MultipleResults(t *testing.T) {
	data := `{"orgs":{"orgRef":[{"@handle":"PRAET-1","@name":"Praetorian Global"},{"@handle":"PS-1576","@name":"Praetorian Security"}]}}`
	var resp ArinOrgsResponse
	require.NoError(t, json.Unmarshal([]byte(data), &resp))
	require.Len(t, resp.Orgs.OrgRef, 2)
	assert.Equal(t, "PRAET-1", resp.Orgs.OrgRef[0].Handle)
}
