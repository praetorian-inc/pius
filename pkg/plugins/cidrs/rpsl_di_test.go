package cidrs

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── fixtures ──────────────────────────────────────────────────────────────

// rpslDIAPNICDump is an APNIC-shaped RPSL excerpt carrying one v4 range record
// and one inet6num record for the same handle. RPSL records are terminated by a
// blank line, so every record here ends with one.
const rpslDIAPNICDump = `inetnum:        203.0.113.0 - 203.0.113.255
netname:        ACME-V4
org:            ORG-ACME1-AP

inet6num:       2001:db8::/32
netname:        ACME-V6
org:            ORG-ACME1-AP

`

// rpslDIAPNICV4Only is the APNIC inetnum file on its own: no inet6num records,
// because APNIC ships those in a separate download.
const rpslDIAPNICV4Only = `inetnum:        203.0.113.0 - 203.0.113.255
netname:        ACME-V4
org:            ORG-ACME1-AP

`

// rpslDIAPNICV6Only is the APNIC inet6num file: prefixes, never ranges.
const rpslDIAPNICV6Only = `inet6num:       2001:db8::/32
netname:        ACME-V6
org:            ORG-ACME1-AP

`

// rpslDIAFRINICDump is the AFRINIC combined dump: one file that already carries
// both inetnum and inet6num records, which is why afrinicConfig has no
// cacheURL6 to fetch.
const rpslDIAFRINICDump = `inetnum:        196.0.2.0 - 196.0.2.255
netname:        ACME-AF-V4
org:            ORG-ACME1-AF

inet6num:       2001:db8:aaaa::/48
org:            ORG-ACME1-AF

inet6num:       2001:db8:bbbb::/48
netname:        SOMEONE-ELSE-V6
org:            ORG-OTHER1-AF

`

// ─── helpers (all rpsl-prefixed to avoid colliding with the package's other
// test files) ──────────────────────────────────────────────────────────────

// rpslCacheEntryPath returns the on-disk path cache.Cache would use for url
// under home, WITHOUT creating it. Used both to seed a warm entry and to assert
// a cache is genuinely cold before a test claims it exercised the network path.
// The sha256-prefix filename scheme mirrors newTestRPSLCache in rpsl_test.go.
func rpslCacheEntryPath(home, url string) string {
	hash := sha256.Sum256([]byte(url))
	return filepath.Join(home, cache.CacheDirName, fmt.Sprintf("%x.rpsl", hash[:8]))
}

// seedRPSLCacheEntry pre-warms the cache entry for url so GetOrDownload
// short-circuits and no HTTP happens at all.
func seedRPSLCacheEntry(t *testing.T, home, url, content string) string {
	t.Helper()
	path := rpslCacheEntryPath(home, url)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// rpslTempHome points $HOME at a fresh temp dir so every cache this test builds
// is isolated and starts empty.
func rpslTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// gzipRPSLBody gzips content, because cache.Cache decompresses every download
// before writing it. Feeding raw text to a recordingTransport would fail in the
// gzip reader and mask whether the injected client was reached at all.
func gzipRPSLBody(t *testing.T, content string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return buf.String()
}

// rpslErrorTransport records every request and refuses all of them. It is the
// hermeticity backstop wherever no request is supposed to happen: on a warm
// cache via rpslErrorClient, and on the process-global http.DefaultTransport
// via rpslBlockGlobalTransport. If a download happens anyway it fails
// in-process instead of reaching a real RIR mirror, and recorded() proves
// which URL was attempted.
type rpslErrorTransport struct {
	mu   sync.Mutex
	urls []string
}

func (t *rpslErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.urls = append(t.urls, req.URL.String())
	t.mu.Unlock()
	return nil, fmt.Errorf("rpsl test transport refused to reach %s", req.URL.Host)
}

func (t *rpslErrorTransport) recorded() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.urls...)
}

// rpslErrorClient builds an *http.Client that cannot reach the network.
func rpslErrorClient() (*http.Client, *rpslErrorTransport) {
	transport := &rpslErrorTransport{}
	return &http.Client{Transport: transport}, transport
}

// rpslBlockGlobalTransport makes a cold-cache constructor test fully hermetic.
//
// NewAPNICPlugin/NewAFRINICPlugin own their URLs (the real cache.* constants),
// so a ".invalid" host is not available here the way it is for a hand-built
// config. Without this, a DI regression that dropped the injected client would
// fall back to cache.downloadClient — which sets only Timeout, leaving
// Transport nil, so net/http routes it through the http.DefaultTransport
// global — and the test would egress to a real RIR mirror.
//
// That global IS reachable from this package even though downloadClient is
// not, so swapping it for a refusing transport closes the hole: on the correct
// path nothing touches it, and on a regression the request fails in-process
// instead of leaving the machine. recorded() then names the URL that tried to
// escape. Restored via t.Cleanup. No test in this package calls t.Parallel(),
// which is what makes mutating a process-global safe here.
func rpslBlockGlobalTransport(t *testing.T) *rpslErrorTransport {
	t.Helper()
	blocked := &rpslErrorTransport{}
	orig := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = orig })
	http.DefaultTransport = blocked
	return blocked
}

// rpslRecordingClient builds an *http.Client whose transport records requests
// and answers every one of them with body. recordingTransport is reused from
// di_constructors_test.go.
func rpslRecordingClient(body string) (*http.Client, *recordingTransport) {
	transport := &recordingTransport{body: body}
	return &http.Client{Transport: transport}, transport
}

func rpslFindingValues(findings []plugins.Finding) []string {
	values := make([]string, 0, len(findings))
	for _, f := range findings {
		values = append(values, f.Value)
	}
	return values
}

func rpslFindingByValue(t *testing.T, findings []plugins.Finding, value string) plugins.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Value == value {
			return f
		}
	}
	require.FailNowf(t, "finding not emitted", "no finding with value %q; got %v", value, rpslFindingValues(findings))
	return plugins.Finding{}
}

// rpslShortCtx bounds every constructor test that starts from a COLD cache.
//
// Hermeticity is NOT this helper's job — rpslBlockGlobalTransport owns that,
// and it is what makes these tests incapable of network egress. This deadline
// is only a second line of defense: it bounds any future path that somehow
// blocks on I/O anyway, so a hang surfaces in seconds instead of stalling CI.
// The injected transport answers instantly, so the deadline is invisible on
// the correct path, and the require.NotEmpty on the recorded calls is what
// actually fails the test when the injected client goes unused.
func rpslShortCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ─── P009 / P010: the exported DI constructors ─────────────────────────────

// TestNewAPNICPlugin_UsesInjectedHTTPClientForBothRPSLFiles proves the injected
// *http.Client is threaded all the way into cache.NewWithHTTPClient: the cache
// starts COLD (asserted), so a warm short-circuit cannot make the assertion
// vacuous, and every byte the plugin parses arrives through the transport under
// test. It also pins that APNIC issues a SECOND download for cacheURL6.
func TestNewAPNICPlugin_UsesInjectedHTTPClientForBothRPSLFiles(t *testing.T) {
	home := rpslTempHome(t)
	blocked := rpslBlockGlobalTransport(t)
	hc, transport := rpslRecordingClient(gzipRPSLBody(t, rpslDIAPNICDump))

	require.NoFileExists(t, rpslCacheEntryPath(home, cache.APNICInetURL),
		"cache must be cold or the injected client is never consulted")
	require.NoFileExists(t, rpslCacheEntryPath(home, cache.APNICInet6URL),
		"cache must be cold or the injected client is never consulted")

	plugin, err := NewAPNICPlugin(hc)
	require.NoError(t, err)
	require.NotNil(t, plugin)

	findings, err := plugin.Run(rpslShortCtx(t), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.NoError(t, err)

	calls := transport.calls()
	require.NotEmpty(t, calls, "injected client was never used: the constructor fell back to the shared cache client")
	assert.Contains(t, calls, cache.APNICInetURL, "primary inetnum file must be fetched")
	assert.Contains(t, calls, cache.APNICInet6URL, "APNIC ships inet6num records in a second file that must also be fetched")

	values := rpslFindingValues(findings)
	assert.Contains(t, values, "203.0.113.0/24", "v4 range must still resolve to CIDRs")
	assert.Contains(t, values, "2001:db8::/32", "v6 prefix must reach the findings through the injected client")

	assert.Empty(t, blocked.recorded(),
		"a request escaped to http.DefaultTransport: the constructor fell back to the cache's shared client instead of the injected one")
}

// TestNewAFRINICPlugin_UsesInjectedHTTPClientForSingleCombinedFile is the
// AFRINIC half: same client threading, but exactly ONE download, because the
// AFRINIC dump already contains inet6num records and afrinicConfig therefore
// carries an empty cacheURL6.
func TestNewAFRINICPlugin_UsesInjectedHTTPClientForSingleCombinedFile(t *testing.T) {
	home := rpslTempHome(t)
	blocked := rpslBlockGlobalTransport(t)
	hc, transport := rpslRecordingClient(gzipRPSLBody(t, rpslDIAFRINICDump))

	require.NoFileExists(t, rpslCacheEntryPath(home, cache.AFRINICAllURL),
		"cache must be cold or the injected client is never consulted")

	plugin, err := NewAFRINICPlugin(hc)
	require.NoError(t, err)
	require.NotNil(t, plugin)

	findings, err := plugin.Run(rpslShortCtx(t), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"afrinic_handles": "ORG-ACME1-AF"},
	})
	require.NoError(t, err)

	calls := transport.calls()
	require.NotEmpty(t, calls, "injected client was never used: the constructor fell back to the shared cache client")
	assert.Equal(t, []string{cache.AFRINICAllURL}, calls,
		"AFRINIC ships one combined dump; an empty cacheURL6 must not produce a second download")

	values := rpslFindingValues(findings)
	assert.Contains(t, values, "196.0.2.0/24")
	assert.Contains(t, values, "2001:db8:aaaa::/48")

	assert.Empty(t, blocked.recorded(),
		"a request escaped to http.DefaultTransport: the constructor fell back to the cache's shared client instead of the injected one")
}

// TestRPSLConstructors_NilHTTPClientIsValid pins the documented nil rule: a nil
// *http.Client is legal and falls back to the cache's shared package-level
// client. It must not panic and must not report an error. Run is deliberately
// NOT called here - with no injected transport, running would egress.
func TestRPSLConstructors_NilHTTPClientIsValid(t *testing.T) {
	constructors := []struct {
		name      string
		construct func(*http.Client) (*RPSLPlugin, error)
		metaKey   string
	}{
		{"NewAPNICPlugin", NewAPNICPlugin, "apnic_handles"},
		{"NewAFRINICPlugin", NewAFRINICPlugin, "afrinic_handles"},
	}

	for _, tt := range constructors {
		t.Run(tt.name, func(t *testing.T) {
			rpslTempHome(t)

			var plugin *RPSLPlugin
			var err error
			require.NotPanics(t, func() { plugin, err = tt.construct(nil) })
			require.NoError(t, err, "a nil client is valid, not an error")
			require.NotNil(t, plugin)
			require.NotNil(t, plugin.cache, "nil client must still yield a usable cache")
			assert.NotPanics(t, func() {
				_ = plugin.Accepts(plugins.Input{Meta: map[string]string{tt.metaKey: "ORG-1"}})
			})
		})
	}
}

// TestRPSLConfigHelpers_MatchPreRefactorRegistrations guards the same
// two-sources-of-truth drift TestRegistryConfigHelpers_MatchPreRefactorRegistrations
// guards for RDAP: the helper, the plugin the registry hands out, and the
// exported constructor must all carry identical config. The per-field
// assertions pin the helper against the cache URL constants themselves, so a
// copy-pasted literal cannot drift from the constant it is supposed to track.
func TestRPSLConfigHelpers_MatchPreRefactorRegistrations(t *testing.T) {
	t.Run("apnic", func(t *testing.T) {
		rpslTempHome(t)

		want := apnicConfig()
		assert.Equal(t, "apnic", want.name)
		assert.Equal(t, "APNIC RPSL: resolves org handles to CIDR blocks", want.description)
		assert.Equal(t, cache.APNICInetURL, want.cacheURL)
		assert.Equal(t, cache.APNICInet6URL, want.cacheURL6,
			"APNIC splits inet6num records into a second file, which the config must name")
		assert.Equal(t, "apnic_handles", want.metaKey)
		assert.Equal(t, "apnic", want.registry)
		assert.Equal(t, plugins.ModePassive, want.mode)

		registered, ok := plugins.Get("apnic")
		require.True(t, ok, "plugin \"apnic\" must stay registered")
		registeredRPSL, ok := registered.(*RPSLPlugin)
		require.True(t, ok, "registry must hand out an *RPSLPlugin for \"apnic\"")
		assert.Equal(t, want, registeredRPSL.cfg, "registered plugin config drifted from the helper")
		assert.Equal(t, "apnic", registeredRPSL.Name())
		assert.Equal(t, plugins.ModePassive, registeredRPSL.Mode())
		assert.Equal(t, 2, registeredRPSL.Phase())
		assert.Equal(t, "cidr", registeredRPSL.Category())

		constructed, err := NewAPNICPlugin(nil)
		require.NoError(t, err)
		assert.Equal(t, want, constructed.cfg, "exported constructor config drifted from the helper")
	})

	t.Run("afrinic", func(t *testing.T) {
		rpslTempHome(t)

		want := afrinicConfig()
		assert.Equal(t, "afrinic", want.name)
		assert.Equal(t, "AFRINIC RPSL: resolves org handles to CIDR blocks", want.description)
		assert.Equal(t, cache.AFRINICAllURL, want.cacheURL)
		assert.Empty(t, want.cacheURL6,
			"AFRINIC ships one combined dump that already contains inet6num records; there is no second file")
		assert.Equal(t, "afrinic_handles", want.metaKey)
		assert.Equal(t, "afrinic", want.registry)
		assert.Equal(t, plugins.ModePassive, want.mode)

		registered, ok := plugins.Get("afrinic")
		require.True(t, ok, "plugin \"afrinic\" must stay registered")
		registeredRPSL, ok := registered.(*RPSLPlugin)
		require.True(t, ok, "registry must hand out an *RPSLPlugin for \"afrinic\"")
		assert.Equal(t, want, registeredRPSL.cfg, "registered plugin config drifted from the helper")
		assert.Equal(t, "afrinic", registeredRPSL.Name())
		assert.Equal(t, plugins.ModePassive, registeredRPSL.Mode())
		assert.Equal(t, 2, registeredRPSL.Phase())
		assert.Equal(t, "cidr", registeredRPSL.Category())

		constructed, err := NewAFRINICPlugin(nil)
		require.NoError(t, err)
		assert.Equal(t, want, constructed.cfg, "exported constructor config drifted from the helper")
	})
}

// ─── parseRPSLInetnums: the inet6num arm ───────────────────────────────────

// TestParseRPSLInetnums_Inet6numEmitsPrefixVerbatim pins the core rule: an
// inet6num line carries a prefix, not a start-end range, and that prefix is
// emitted BYTE-FOR-BYTE. The uppercase-hex case is the discriminator - any
// normalisation, canonicalisation, or range-to-CIDR round trip would rewrite
// "2001:DB8:1::/48" and fail here.
func TestParseRPSLInetnums_Inet6numEmitsPrefixVerbatim(t *testing.T) {
	content := `inet6num:       2001:db8::/32
netname:        ACME-V6
org:            ORG-ACME1-AP

inet6num:       2001:DB8:1::/48
org:            ORG-ACME1-AP

`
	path := writeTempRPSL(t, content)

	results, err := parseRPSLInetnums(path, []string{"ORG-ACME1-AP"})
	require.NoError(t, err)
	require.Contains(t, results, "ORG-ACME1-AP")
	require.Len(t, results["ORG-ACME1-AP"], 2)

	first := results["ORG-ACME1-AP"][0]
	assert.Equal(t, "2001:db8::/32", first.prefix)
	assert.Equal(t, "ACME-V6", first.netname)
	assert.Empty(t, first.start, "an inet6num record has no range start")
	assert.Empty(t, first.end, "an inet6num record has no range end")

	second := results["ORG-ACME1-AP"][1]
	assert.Equal(t, "2001:DB8:1::/48", second.prefix,
		"the prefix must be carried through as-is: no normalisation, no range conversion")
}

// TestParseRPSLInetnums_SkipsMalformedInet6numPrefix pins the failure mode.
// RPSL is downloaded third-party text, so a prefix net/netip.ParsePrefix
// rejects must be skipped rather than propagated or fatal - and the valid
// records around it must still parse, which is what proves "skipped" rather
// than "aborted the file".
func TestParseRPSLInetnums_SkipsMalformedInet6numPrefix(t *testing.T) {
	content := `inet6num:       not-a-prefix
org:            ORG-ACME1-AP

inet6num:       2001:db8::/999
org:            ORG-ACME1-AP

inet6num:       2001:db8::
org:            ORG-ACME1-AP

inet6num:       2001:db8:c0de::/48
netname:        SURVIVOR
org:            ORG-ACME1-AP

inetnum:        203.0.113.0 - 203.0.113.255
netname:        ACME-V4
org:            ORG-ACME1-AP

`
	path := writeTempRPSL(t, content)

	results, err := parseRPSLInetnums(path, []string{"ORG-ACME1-AP"})
	require.NoError(t, err, "malformed third-party RPSL lines must not be fatal")

	prefixes := make([]string, 0)
	ranges := make([][2]string, 0)
	for _, rec := range results["ORG-ACME1-AP"] {
		if rec.prefix != "" {
			prefixes = append(prefixes, rec.prefix)
		} else {
			ranges = append(ranges, [2]string{rec.start, rec.end})
		}
	}

	assert.Equal(t, []string{"2001:db8:c0de::/48"}, prefixes,
		"only the ParsePrefix-valid inet6num record survives")
	assert.Equal(t, [][2]string{{"203.0.113.0", "203.0.113.255"}}, ranges,
		"records after the malformed ones must still parse")
}

// TestParseRPSLInetnums_IPv4RangeRecordsCarryNoPrefix pins the other half of the
// discriminator: adding the inet6num arm must not start populating prefix on v4
// range records.
func TestParseRPSLInetnums_IPv4RangeRecordsCarryNoPrefix(t *testing.T) {
	path := writeTempRPSL(t, rpslDIAPNICV4Only)

	results, err := parseRPSLInetnums(path, []string{"ORG-ACME1-AP"})
	require.NoError(t, err)
	require.Len(t, results["ORG-ACME1-AP"], 1)

	rec := results["ORG-ACME1-AP"][0]
	assert.Equal(t, "203.0.113.0", rec.start)
	assert.Equal(t, "203.0.113.255", rec.end)
	assert.Empty(t, rec.prefix, "a v4 range record must leave prefix empty")
}

// ─── Run: v6 findings ──────────────────────────────────────────────────────

// TestNewAFRINICPlugin_Run_EmitsIPv6PrefixAsFindingValue pins the emitted v6
// finding: the prefix IS the Finding.Value (no IPv6 range-to-CIDR conversion
// exists anywhere), it carries the same confRPSLHandleInetnum score and the
// same Data keys as a v4 finding, and its justification names the prefix
// without claiming a range - a v6 record has none.
//
// The cache is pre-warmed and the plugin's client refuses every request, so the
// whole test runs with zero network egress and any accidental download fails
// loudly.
func TestNewAFRINICPlugin_Run_EmitsIPv6PrefixAsFindingValue(t *testing.T) {
	home := rpslTempHome(t)
	seedRPSLCacheEntry(t, home, cache.AFRINICAllURL, rpslDIAFRINICDump)
	hc, transport := rpslErrorClient()

	plugin, err := NewAFRINICPlugin(hc)
	require.NoError(t, err)

	findings, err := plugin.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"afrinic_handles": "ORG-ACME1-AF"},
	})
	require.NoError(t, err)
	require.Empty(t, transport.recorded(), "a warm cache must not trigger any download")

	v6 := rpslFindingByValue(t, findings, "2001:db8:aaaa::/48")
	assert.Equal(t, plugins.FindingCIDR, v6.Type)
	assert.Equal(t, "afrinic", v6.Source)
	assert.Equal(t, map[string]any{
		"handle":   "ORG-ACME1-AF",
		"org":      "Acme Corp",
		"registry": "afrinic",
		"netname":  "",
	}, v6.Data, "a v6 finding must carry the same Data keys as a v4 finding")

	require.Len(t, v6.Confidences, 1)
	assert.Equal(t, confRPSLHandleInetnum, v6.Confidences[0].Score)
	assert.Equal(t,
		`AFRINIC RPSL records prefix "2001:db8:aaaa::/48" under organization handle "ORG-ACME1-AF"`,
		v6.Confidences[0].Justification,
		"a v6 record has no range, so the justification names the prefix instead")
	assert.NotContains(t, v6.Confidences[0].Justification, "range",
		"claiming a range for an inet6num record would be false")

	// The v4 half of the same combined dump keeps its existing range wording.
	v4 := rpslFindingByValue(t, findings, "196.0.2.0/24")
	require.Len(t, v4.Confidences, 1)
	assert.Equal(t,
		`AFRINIC RPSL records range "196.0.2.0 - 196.0.2.255" under organization handle "ORG-ACME1-AF" with netname "ACME-AF-V4"; the range contains CIDR "196.0.2.0/24"`,
		v4.Confidences[0].Justification)
}

// TestNewAFRINICPlugin_Run_IgnoresIPv6RecordsForOtherHandles is the benign case:
// the same healthy dump contains an inet6num record owned by a different org
// handle, and the plugin must stay silent about it. Without this, the positive
// case above measures nothing about false positives.
func TestNewAFRINICPlugin_Run_IgnoresIPv6RecordsForOtherHandles(t *testing.T) {
	home := rpslTempHome(t)
	seedRPSLCacheEntry(t, home, cache.AFRINICAllURL, rpslDIAFRINICDump)
	hc, transport := rpslErrorClient()

	plugin, err := NewAFRINICPlugin(hc)
	require.NoError(t, err)

	findings, err := plugin.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"afrinic_handles": "ORG-ACME1-AF"},
	})
	require.NoError(t, err)
	require.Empty(t, transport.recorded(), "a warm cache must not trigger any download")

	values := rpslFindingValues(findings)
	assert.NotContains(t, values, "2001:db8:bbbb::/48",
		"an inet6num record owned by ORG-OTHER1-AF must never be attributed to ORG-ACME1-AF")
	for _, f := range findings {
		assert.Equal(t, "ORG-ACME1-AF", f.Data["handle"])
	}
}

// TestNewAPNICPlugin_Run_MergesSecondaryIPv6File pins requirement 6's happy
// path: the v6 file is a genuinely separate download whose records are MERGED
// with the v4 ones, not returned instead of them. Both entries are pre-warmed,
// so the merge is proven without any HTTP.
func TestNewAPNICPlugin_Run_MergesSecondaryIPv6File(t *testing.T) {
	home := rpslTempHome(t)
	seedRPSLCacheEntry(t, home, cache.APNICInetURL, rpslDIAPNICV4Only)
	seedRPSLCacheEntry(t, home, cache.APNICInet6URL, rpslDIAPNICV6Only)
	hc, transport := rpslErrorClient()

	plugin, err := NewAPNICPlugin(hc)
	require.NoError(t, err)

	findings, err := plugin.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.NoError(t, err)
	require.Empty(t, transport.recorded(), "both cache entries are warm; nothing should be downloaded")

	values := rpslFindingValues(findings)
	assert.Contains(t, values, "203.0.113.0/24", "v4 findings from the primary file must survive the merge")
	assert.Contains(t, values, "2001:db8::/32", "v6 findings from the secondary file must be merged in")

	v6 := rpslFindingByValue(t, findings, "2001:db8::/32")
	assert.Equal(t, "apnic", v6.Source)
	assert.Equal(t, "apnic", v6.Data["registry"])
	require.Len(t, v6.Confidences, 1)
	assert.Equal(t, confRPSLHandleInetnum, v6.Confidences[0].Score)
	assert.Equal(t,
		`APNIC RPSL records prefix "2001:db8::/32" under organization handle "ORG-ACME1-AP" with netname "ACME-V6"`,
		v6.Confidences[0].Justification)
}

// TestNewAPNICPlugin_Run_SecondaryIPv6FetchFailureKeepsIPv4Findings pins the
// recall-safe rule: the v6 file is best-effort. Its download fails here (cold
// entry, refusing transport) and the v4 findings must still come back.
func TestNewAPNICPlugin_Run_SecondaryIPv6FetchFailureKeepsIPv4Findings(t *testing.T) {
	home := rpslTempHome(t)
	seedRPSLCacheEntry(t, home, cache.APNICInetURL, rpslDIAPNICV4Only)
	require.NoFileExists(t, rpslCacheEntryPath(home, cache.APNICInet6URL),
		"the v6 entry must be cold so its fetch genuinely fails")
	hc, transport := rpslErrorClient()

	plugin, err := NewAPNICPlugin(hc)
	require.NoError(t, err)

	findings, err := plugin.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.NoError(t, err, "a failed v6 fetch is best-effort and must not fail the run")

	attempted := transport.recorded()
	require.NotEmpty(t, attempted, "the v6 file must actually have been attempted")
	assert.Contains(t, attempted, cache.APNICInet6URL)
	assert.NotContains(t, attempted, cache.APNICInetURL, "the warm primary entry must not be re-downloaded")

	values := rpslFindingValues(findings)
	assert.Contains(t, values, "203.0.113.0/24", "v4 findings must survive a v6 fetch failure")
	assert.NotContains(t, values, "2001:db8::/32")
}

// TestNewAPNICPlugin_Run_PrimaryFetchFailureReturnsError is the other arm of
// the same rule: the PRIMARY file is not best-effort. Losing it means the run
// found nothing, and that must surface as an error rather than an empty
// success that reads identically to "this org owns no APNIC space".
func TestNewAPNICPlugin_Run_PrimaryFetchFailureReturnsError(t *testing.T) {
	home := rpslTempHome(t)
	require.NoFileExists(t, rpslCacheEntryPath(home, cache.APNICInetURL))
	hc, transport := rpslErrorClient()

	plugin, err := NewAPNICPlugin(hc)
	require.NoError(t, err)

	findings, err := plugin.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})
	require.Error(t, err, "a failed primary download must still return an error")
	assert.Empty(t, findings)
	assert.Contains(t, transport.recorded(), cache.APNICInetURL)
}

// ─── Run: nil cache ────────────────────────────────────────────────────────

// TestRPSLPlugin_Run_NilCacheReturnsErrorInsteadOfPanicking closes the gap the
// existing Accepts()-based self-disable does not cover. Guard's Runner exposes
// only Run, so its adapter never calls Accepts: a plugin whose cache failed to
// construct reaches Run with p.cache == nil and must report that as an error,
// not dereference nil.
func TestRPSLPlugin_Run_NilCacheReturnsErrorInsteadOfPanicking(t *testing.T) {
	plugin := newRPSLPlugin(rpslConfig{
		name:     "apnic",
		cacheURL: "https://rpsl.invalid/apnic.db.inetnum.gz",
		metaKey:  "apnic_handles",
		registry: "apnic",
		mode:     plugins.ModePassive,
	}, nil)

	var findings []plugins.Finding
	var err error
	require.NotPanics(t, func() {
		findings, err = plugin.Run(context.Background(), plugins.Input{
			OrgName: "Acme Corp",
			Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
		})
	}, "Run must not nil-dereference when cache construction failed")

	require.Error(t, err, "a nil cache must be reported, not silently treated as no results")
	assert.Empty(t, findings)
}
