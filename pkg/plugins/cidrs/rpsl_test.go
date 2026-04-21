package cidrs

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTempRPSL(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "rpsl*.db")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	_ = f.Close()
	return f.Name()
}

func TestParseRPSLInetnums_BasicParsing(t *testing.T) {
	content := "inetnum:        192.168.0.0 - 192.168.255.255\nnetname:        ACME-NET\norg:            ACME-1\n\n"
	path := writeTempRPSL(t, content)

	results, err := parseRPSLInetnums(path, []string{"ACME-1"})
	require.NoError(t, err)
	require.Contains(t, results, "ACME-1")
	require.Len(t, results["ACME-1"], 1)
	assert.Equal(t, "192.168.0.0", results["ACME-1"][0].start)
	assert.Equal(t, "192.168.255.255", results["ACME-1"][0].end)
	assert.Equal(t, "ACME-NET", results["ACME-1"][0].netname)
}

func TestParseRPSLInetnums_MultipleHandles(t *testing.T) {
	content := `inetnum:        10.0.0.0 - 10.255.255.255
netname:        ORG-A-NET
org:            ORG-A

inetnum:        172.16.0.0 - 172.31.255.255
netname:        ORG-B-NET
org:            ORG-B

inetnum:        192.168.0.0 - 192.168.255.255
netname:        ORG-C-NET
org:            ORG-C

`
	path := writeTempRPSL(t, content)

	results, err := parseRPSLInetnums(path, []string{"ORG-A", "ORG-C"})
	require.NoError(t, err)
	assert.Contains(t, results, "ORG-A")
	assert.Contains(t, results, "ORG-C")
	assert.NotContains(t, results, "ORG-B", "ORG-B was not requested")
}

func TestParseRPSLInetnums_CaseInsensitiveHandleMatching(t *testing.T) {
	content := "inetnum:        10.0.0.0 - 10.0.0.255\nnetname:        TEST-NET\norg:            ACME-UPPER\n\n"
	path := writeTempRPSL(t, content)

	// Request with lowercase — should still match
	results, err := parseRPSLInetnums(path, []string{"acme-upper"})
	require.NoError(t, err)
	// The results map key will be the lowercase form as stored in the file ("ACME-UPPER")
	// The function normalizes for matching but stores the original org value as key
	assert.NotEmpty(t, results, "lowercase handle should match uppercase org in file")
}

func TestParseRPSLInetnums_RecordWithNoOrg(t *testing.T) {
	// Record without org: field — should be skipped entirely
	content := "inetnum:        10.0.0.0 - 10.0.0.255\nnetname:        ORPHAN-NET\n\n"
	path := writeTempRPSL(t, content)

	results, err := parseRPSLInetnums(path, []string{"ORPHAN-NET"})
	require.NoError(t, err)
	assert.Empty(t, results, "record with no org: field should not produce results")
}

func TestParseRPSLInetnums_FileNotFound(t *testing.T) {
	results, err := parseRPSLInetnums("/nonexistent/path/that/does/not/exist.db", []string{"HANDLE"})
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestParseRPSLInetnums_EmptyFile(t *testing.T) {
	path := writeTempRPSL(t, "")
	results, err := parseRPSLInetnums(path, []string{"ANY-HANDLE"})
	require.NoError(t, err)
	assert.Empty(t, results)
}
