package cidrs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
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

func TestRPSLPlugin_Run_AddsConfidenceToEveryCIDR(t *testing.T) {
	cacheURL := "https://example.test/apnic.db.gz"
	pluginCache := newTestRPSLCache(t, cacheURL, `inetnum:        203.0.113.0 - 203.0.113.191
netname:        ACME-NET
org:            ORG-ACME1-AP

inetnum:        198.51.100.0 - 198.51.100.255
org:            ORG-ACME1-AP

`)
	p := newRPSLPlugin(rpslConfig{
		name: "apnic", cacheURL: cacheURL, metaKey: "apnic_handles", registry: "apnic",
	}, pluginCache)

	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.NoError(t, err)
	require.Len(t, findings, 3)

	byCIDR := make(map[string]plugins.Finding, len(findings))
	for _, finding := range findings {
		byCIDR[finding.Value] = finding
		require.Len(t, finding.Confidences, 1)
		confidence := finding.Confidences[0]
		assert.Equal(t, confRPSLHandleInetnum, confidence.Score)
		assert.NotEmpty(t, confidence.Justification)
		assert.Contains(t, confidence.Justification, "APNIC")
		assert.Contains(t, confidence.Justification, "ORG-ACME1-AP")
		assert.Contains(t, confidence.Justification, finding.Value)
		assert.NotContains(t, finding.Data, "confidence")
		assert.NotContains(t, finding.Data, "confidences")
	}

	for _, value := range []string{"203.0.113.0/25", "203.0.113.128/26"} {
		finding, ok := byCIDR[value]
		require.True(t, ok)
		justification := finding.Confidences[0].Justification
		assert.Contains(t, justification, "203.0.113.0 - 203.0.113.191")
		assert.Contains(t, justification, `with netname "ACME-NET"`)
	}

	withoutNetname, ok := byCIDR["198.51.100.0/24"]
	require.True(t, ok)
	justification := withoutNetname.Confidences[0].Justification
	assert.Contains(t, justification, "198.51.100.0 - 198.51.100.255")
	assert.NotContains(t, justification, "netname")
	assert.Equal(t, `APNIC RPSL records range "198.51.100.0 - 198.51.100.255" under organization handle "ORG-ACME1-AP"; the range contains CIDR "198.51.100.0/24"`, justification)
}

func newTestRPSLCache(t *testing.T, cacheURL, content string) *cache.Cache {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	pluginCache, err := cache.New()
	require.NoError(t, err)

	hash := sha256.Sum256([]byte(cacheURL))
	cachePath := filepath.Join(home, cache.CacheDirName, fmt.Sprintf("%x.rpsl", hash[:8]))
	require.NoError(t, os.WriteFile(cachePath, []byte(content), 0600))
	return pluginCache
}
