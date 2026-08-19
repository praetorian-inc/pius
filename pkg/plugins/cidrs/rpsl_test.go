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

// writeRPSLNamed writes content to dir under an exact filename, for tests that
// care which of several databases a record came from.
func writeRPSLNamed(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func TestParseRPSLNetblocks_BasicParsing(t *testing.T) {
	content := "inetnum:        192.168.0.0 - 192.168.255.255\nnetname:        ACME-NET\norg:            ACME-1\n\n"
	path := writeTempRPSL(t, content)

	results, err := parseRPSLNetblocks(path, []string{"ACME-1"}, "")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "ACME-1", results[0].handle)
	assert.Equal(t, "192.168.0.0", results[0].start)
	assert.Equal(t, "192.168.255.255", results[0].end)
	assert.Equal(t, "ACME-NET", results[0].netname)
	assert.False(t, results[0].isPrefix())
}

func TestParseRPSLNetblocks_Inet6num(t *testing.T) {
	content := "inet6num:       2001:db8::/32\nnetname:        ACME-V6\norg:            ACME-1\n\n"
	path := writeTempRPSL(t, content)

	results, err := parseRPSLNetblocks(path, []string{"ACME-1"}, "")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].isPrefix())
	assert.Equal(t, "2001:db8::/32", results[0].prefix)

	cidrs, err := results[0].cidrs()
	require.NoError(t, err)
	assert.Equal(t, []string{"2001:db8::/32"}, cidrs)
}

// A prefix written with host bits set must not reach the caller verbatim: it
// would key an asset no other source would ever produce.
func TestParseRPSLNetblocks_Inet6numCanonicalizesPrefix(t *testing.T) {
	path := writeTempRPSL(t, "inet6num:       2001:db8:1234::/32\norg:            ACME-1\n\n")

	results, err := parseRPSLNetblocks(path, []string{"ACME-1"}, "")
	require.NoError(t, err)
	require.Len(t, results, 1)

	cidrs, err := results[0].cidrs()
	require.NoError(t, err)
	assert.Equal(t, []string{"2001:db8::/32"}, cidrs)
	assert.Equal(t, "2001:db8:1234::/32", results[0].source(),
		"justification should cite the record as the database wrote it")
}

func TestParseRPSLNetblocks_MalformedPrefixIsRejected(t *testing.T) {
	path := writeTempRPSL(t, "inet6num:       not-a-prefix\norg:            ACME-1\n\n")

	results, err := parseRPSLNetblocks(path, []string{"ACME-1"}, "")
	require.NoError(t, err)
	require.Len(t, results, 1)

	_, err = results[0].cidrs()
	assert.Error(t, err)
}

func TestParseRPSLNetblocks_MixedFamiliesInOneFile(t *testing.T) {
	content := `inetnum:        203.0.113.0 - 203.0.113.255
netname:        ACME-V4
org:            ACME-1

inet6num:       2001:db8::/32
netname:        ACME-V6
org:            ACME-1

`
	path := writeTempRPSL(t, content)

	results, err := parseRPSLNetblocks(path, []string{"ACME-1"}, "")
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.False(t, results[0].isPrefix())
	assert.True(t, results[1].isPrefix())
}

func TestParseRPSLNetblocks_MultipleHandles(t *testing.T) {
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

	results, err := parseRPSLNetblocks(path, []string{"ORG-A", "ORG-C"}, "")
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "ORG-A", results[0].handle)
	assert.Equal(t, "ORG-C", results[1].handle, "ORG-B was not requested")
}

func TestParseRPSLNetblocks_CaseInsensitiveHandleMatching(t *testing.T) {
	content := "inetnum:        10.0.0.0 - 10.0.0.255\nnetname:        TEST-NET\norg:            ACME-UPPER\n\n"
	path := writeTempRPSL(t, content)

	// Request with lowercase — should still match.
	results, err := parseRPSLNetblocks(path, []string{"acme-upper"}, "")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "ACME-UPPER", results[0].handle,
		"handle is reported as the database wrote it")
}

// Real dumps do not reliably end with a blank line, and the final record is as
// real as any other.
func TestParseRPSLNetblocks_RecordAtEOFWithoutTrailingBlankLine(t *testing.T) {
	path := writeTempRPSL(t, "inetnum:        10.0.0.0 - 10.0.0.255\norg:            ACME-1\n")

	results, err := parseRPSLNetblocks(path, []string{"ACME-1"}, "")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "10.0.0.0", results[0].start)
}

func TestParseRPSLNetblocks_RecordWithNoOrgOrMatchingDescription(t *testing.T) {
	content := "inetnum:        10.0.0.0 - 10.0.0.255\nnetname:        ORPHAN-NET\n\n"
	path := writeTempRPSL(t, content)

	results, err := parseRPSLNetblocks(path, []string{"ORPHAN-NET"}, "Acme Corp")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestParseRPSLNetblocks_MatchesOrganizationNameInDescription(t *testing.T) {
	content := `inetnum:        203.0.113.0 - 203.0.113.255
netname:        ACME-NET
descr:          Acme Corporation, Sydney office
org:            ORG-UPSTREAM1-AP

`
	path := writeTempRPSL(t, content)

	results, err := parseRPSLNetblocks(path, []string{"ORG-ACME1-AP"}, "acme corporation")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].handle)
	assert.Equal(t, "Acme Corporation, Sydney office", results[0].description)
}

func TestParseRPSLNetblocks_DescriptionMustStartWithOrganizationName(t *testing.T) {
	content := "inetnum:        203.0.113.0 - 203.0.113.255\ndescr:          Unrelated company for Acme Corp\n\n"
	path := writeTempRPSL(t, content)

	results, err := parseRPSLNetblocks(path, []string{"ORG-ACME1-AP"}, "Acme Corp")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestParseRPSLNetblocks_FileNotFound(t *testing.T) {
	results, err := parseRPSLNetblocks("/nonexistent/path/that/does/not/exist.db", []string{"HANDLE"}, "")
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestParseRPSLNetblocks_EmptyFile(t *testing.T) {
	path := writeTempRPSL(t, "")
	results, err := parseRPSLNetblocks(path, []string{"ANY-HANDLE"}, "")
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
		networkReferenceBaseURL: "https://rdap.apnic.net/ip/",
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
	assertRPSLReference(t, withoutNetname.Confidences[0],
		"https://rdap.apnic.net/ip/198.51.100.0/24")
}

// ── Local-file construction (the embedded path) ───────────────────────────────

func TestRPSLConstructors_RequireACacheOrDatabasePath(t *testing.T) {
	constructors := map[string]func(*cache.Cache, ...string) plugins.Plugin{
		"apnic":   NewAPNICPlugin,
		"afrinic": NewAFRINICPlugin,
	}

	for registry, newPlugin := range constructors {
		t.Run(registry, func(t *testing.T) {
			p := newPlugin(nil, "", "   ")
			input := plugins.Input{Meta: map[string]string{registry + "_handles": "ORG-1"}}

			assert.False(t, p.Accepts(input))
			findings, err := p.Run(context.Background(), input)
			require.ErrorContains(t, err, "no database paths and no download cache")
			assert.Nil(t, findings)
		})
	}
}

func TestNewAFRINICPlugin_AcceptsWithoutACache(t *testing.T) {
	p := NewAFRINICPlugin(nil, writeTempRPSL(t, ""))

	assert.True(t, p.Accepts(plugins.Input{Meta: map[string]string{"afrinic_handles": "ORG-1"}}))
	assert.False(t, p.Accepts(plugins.Input{}), "still needs a handle to resolve")
	assert.Equal(t, "afrinic", p.Name())
	assert.Equal(t, 2, p.Phase())
}

func TestNewAPNICPlugin_ReadsIPv4FromLocalFile(t *testing.T) {
	path := writeRPSLNamed(t, t.TempDir(), "apnic.db.inetnum",
		"inetnum:        203.0.113.0 - 203.0.113.255\nnetname:        ACME-AP\norg:            ORG-ACME1-AP\n\n")

	p := NewAPNICPlugin(nil, path)

	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, plugins.FindingCIDR, findings[0].Type)
	assert.Equal(t, "203.0.113.0/24", findings[0].Value)
	assert.Equal(t, "apnic", findings[0].Data["registry"])
	assert.Equal(t, "ORG-ACME1-AP", findings[0].Data["handle"])
	assert.Equal(t, "Acme Corp", findings[0].Data["org"])
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t, confRPSLHandleInetnum, findings[0].Confidences[0].Score)
}

func TestNewAPNICPlugin_ReadsIPv6FromLocalFile(t *testing.T) {
	path := writeRPSLNamed(t, t.TempDir(), "apnic.db.inet6num",
		"inet6num:       2001:db8::/32\nnetname:        ACME-AP-V6\norg:            ORG-ACME1-AP\n\n")

	p := NewAPNICPlugin(nil, path)

	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "2001:db8::/32", findings[0].Value)
	assert.Equal(t, `APNIC RPSL records prefix "2001:db8::/32" under organization handle "ORG-ACME1-AP" with netname "ACME-AP-V6"; the prefix contains CIDR "2001:db8::/32"`,
		findings[0].Confidences[0].Justification)
	assertRPSLReference(t, findings[0].Confidences[0],
		"https://rdap.apnic.net/ip/2001:db8::/32")
}

// APNIC publishes the two address families as separate files, so covering IPv6
// means reading every path the caller supplied, not just the first.
func TestNewAPNICPlugin_ReadsEverySuppliedPath(t *testing.T) {
	dir := t.TempDir()
	v4 := writeRPSLNamed(t, dir, "apnic.db.inetnum",
		"inetnum:        203.0.113.0 - 203.0.113.255\norg:            ORG-ACME1-AP\n\n")
	v6 := writeRPSLNamed(t, dir, "apnic.db.inet6num",
		"inet6num:       2001:db8::/32\norg:            ORG-ACME1-AP\n\n")

	p := NewAPNICPlugin(nil, v4, v6)

	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, "203.0.113.0/24", findings[0].Value)
	assert.Equal(t, "2001:db8::/32", findings[1].Value)
}

// AFRINIC ships one combined database carrying both families.
func TestNewAFRINICPlugin_ReadsCombinedDatabase(t *testing.T) {
	path := writeRPSLNamed(t, t.TempDir(), "afrinic.db", `inetnum:        196.216.2.0 - 196.216.2.255
netname:        ACME-AFRINIC
org:            ORG-ACME1-AFRINIC

inet6num:       2c0f:fb50::/32
netname:        ACME-AFRINIC-V6
org:            ORG-ACME1-AFRINIC

`)

	p := NewAFRINICPlugin(nil, path)

	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"afrinic_handles": "org-acme1-afrinic"},
	})
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, "196.216.2.0/24", findings[0].Value)
	assert.Equal(t, "2c0f:fb50::/32", findings[1].Value)
	expectedReferences := []string{
		"https://rdap.afrinic.net/rdap/ip/196.216.2.0/24",
		"https://rdap.afrinic.net/rdap/ip/2c0f:fb50::/32",
	}
	for i, finding := range findings {
		assert.Equal(t, "afrinic", finding.Data["registry"])
		assertRPSLReference(t, finding.Confidences[0], expectedReferences[i])
	}
}

func assertRPSLReference(t *testing.T, confidence plugins.Confidence, expectedURL string) {
	t.Helper()
	require.NotNil(t, confidence.Reference)
	assert.Equal(t, plugins.ReferenceTypeRPSL, confidence.Reference.Type)
	data, ok := confidence.Reference.Data.(plugins.RPSLReferenceData)
	require.True(t, ok)
	assert.Equal(t, expectedURL, data.NetworkURL)
	assert.NotEmpty(t, data.Record)
}

// The whole point of the injected-path mode: a missing file is an error, never
// a fallback to downloading a several-hundred-megabyte dump.
func TestNewAPNICPlugin_MissingFileErrorsWithoutDownloading(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "apnic.db.inetnum")
	p := NewAPNICPlugin(nil, missing)

	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.Error(t, err)
	assert.Nil(t, findings)
	assert.Contains(t, err.Error(), "apnic")
	assert.Contains(t, err.Error(), missing, "error should identify the unreadable file")
}

// A plugin built over local paths must not consult the cache even when one is
// available and populated — the paths are the sole source of records.
func TestRPSLPlugin_LocalPathsNeverFallBackToCache(t *testing.T) {
	pluginCache := newTestRPSLCache(t, cache.APNICInetURL,
		"inetnum:        10.0.0.0 - 10.0.0.255\norg:            ORG-ACME1-AP\n\n")

	local := writeTempRPSL(t, "inetnum:        203.0.113.0 - 203.0.113.255\norg:            ORG-ACME1-AP\n\n")
	p := NewAPNICPlugin(pluginCache, local)

	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "203.0.113.0/24", findings[0].Value, "should read the injected path, not the cache")
}

// Standalone pius keeps downloading its own dumps.
func TestRPSLPlugin_CacheBackedRegistrationStillWorks(t *testing.T) {
	for _, name := range []string{"apnic", "afrinic"} {
		t.Setenv("HOME", t.TempDir())
		p, found := plugins.Get(name)
		require.True(t, found)

		rpsl, ok := p.(*rpslPlugin)
		require.True(t, ok)
		assert.Empty(t, rpsl.dbPaths, "%s registration must stay cache-backed", name)
		assert.NotNil(t, rpsl.cache)
		assert.Equal(t, name, rpsl.Name())
		assert.NotEmpty(t, rpsl.cfg.cacheURL)
	}
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
