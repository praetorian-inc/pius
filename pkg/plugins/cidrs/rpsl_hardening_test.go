package cidrs

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── fixtures ──────────────────────────────────────────────────────────────

// rpslCanonicalV6Dump is an AFRINIC-shaped combined dump written the way a
// registry actually publishes IPv6: the first record carries a prefix with
// UPPERCASE hex and a host bit set ("2001:DB8::1/32"), which is a legal
// netip.ParsePrefix input and therefore reaches findingsFor today. The already
// canonical record, the two ParsePrefix-rejects, and the trailing v4 range are
// the controls: they prove canonicalisation is idempotent and that skipping a
// malformed prefix does not abort the rest of the file.
const rpslCanonicalV6Dump = `inet6num:       2001:DB8::1/32
netname:        ACME-UPPER-HOSTBITS
org:            ORG-ACME1-AF

inet6num:       2001:db8:cafe::/48
netname:        ACME-ALREADY-CANONICAL
org:            ORG-ACME1-AF

inet6num:       not-a-prefix
org:            ORG-ACME1-AF

inet6num:       2001:db8:beef::/999
org:            ORG-ACME1-AF

inetnum:        196.0.2.0 - 196.0.2.255
netname:        ACME-AF-V4
org:            ORG-ACME1-AF

`

// ─── Run: the zero-handle short circuit ────────────────────────────────────

// TestRPSLPlugin_Run_ZeroHandlesDownloadsNothing pins the cost guard.
//
// splitHandles returns an empty slice for a missing meta key, an empty value,
// and a value that is nothing but separators and whitespace. Zero handles can
// match zero records, so every byte of a multi-hundred-megabyte RPSL dump
// downloaded in that state is wasted. The Accepts()-based self-disable does not
// cover it: Guard's Runner interface exposes only Run, so its adapter never
// calls Accepts and reaches recordsFrom -> cache.GetOrDownload regardless.
//
// The load-bearing assertion is the request count, not the nil return. A Run
// that downloaded the whole dump and then found nothing to match would also
// return (nil, nil), so only the transport can tell the two apart. The cache is
// asserted COLD first — a warm entry would short-circuit GetOrDownload on its
// own and make the zero-request assertion vacuous — and http.DefaultTransport is
// blocked so a regression fails in-process instead of egressing to a real RIR
// mirror.
func TestRPSLPlugin_Run_ZeroHandlesDownloadsNothing(t *testing.T) {
	registries := []struct {
		name      string
		construct func(*http.Client) (*RPSLPlugin, error)
		metaKey   string
		urls      []string
	}{
		{"apnic", NewAPNICPlugin, "apnic_handles", []string{cache.APNICInetURL, cache.APNICInet6URL}},
		{"afrinic", NewAFRINICPlugin, "afrinic_handles", []string{cache.AFRINICAllURL}},
	}

	metaCases := []struct {
		name string
		meta func(metaKey string) map[string]string
	}{
		{"nil meta", func(string) map[string]string { return nil }},
		{"key absent", func(string) map[string]string {
			return map[string]string{"unrelated_handles": "ORG-SOMEONE-ELSE"}
		}},
		{"empty value", func(key string) map[string]string { return map[string]string{key: ""} }},
		{"separators and whitespace only", func(key string) map[string]string { return map[string]string{key: " , "} }},
	}

	for _, reg := range registries {
		for _, mc := range metaCases {
			t.Run(reg.name+"/"+mc.name, func(t *testing.T) {
				home := rpslTempHome(t)
				blocked := rpslBlockGlobalTransport(t)
				hc, transport := rpslErrorClient()

				for _, url := range reg.urls {
					require.NoFileExists(t, rpslCacheEntryPath(home, url),
						"the cache must be cold, or a warm entry would satisfy the zero-request assertion for the wrong reason")
				}

				plugin, err := reg.construct(hc)
				require.NoError(t, err)

				findings, err := plugin.Run(rpslShortCtx(t), plugins.Input{
					OrgName: "Acme Corp",
					Meta:    mc.meta(reg.metaKey),
				})

				assert.Empty(t, transport.recorded(),
					"zero handles match zero records: Run must short-circuit before downloading the RPSL dump")
				assert.Empty(t, blocked.recorded(),
					"a request escaped to http.DefaultTransport instead of the injected client")
				require.NoError(t, err, "having nothing to resolve is not an error")
				assert.Empty(t, findings)
			})
		}
	}
}

// ─── Run: IPv6 prefix canonicalisation ─────────────────────────────────────

// TestNewAFRINICPlugin_Run_CanonicalizesIPv6PrefixFindings pins the emitted
// Finding.Value for an inet6num record.
//
// findingsFor currently hands rec.prefix straight to newFinding, so whatever
// spelling the registry published becomes the CIDR Guard stores — and RPSL
// publishes uppercase hex and set host bits. Two spellings of one network then
// deduplicate as two distinct assets. The finding value must be the canonical
// form: parsed, Masked (host bits cleared) and lowercased.
//
// The assertion deliberately sits on Finding.Value from Run rather than on
// rpslInetnum.prefix: the parser is documented to carry the registry's original
// bytes through untouched, and TestParseRPSLInetnums_Inet6numEmitsPrefixVerbatim
// pins that. Canonicalisation belongs at the emit boundary, not in the parse.
func TestNewAFRINICPlugin_Run_CanonicalizesIPv6PrefixFindings(t *testing.T) {
	home := rpslTempHome(t)
	seedRPSLCacheEntry(t, home, cache.AFRINICAllURL, rpslCanonicalV6Dump)
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

	assert.Contains(t, values, "2001:db8::/32",
		"a prefix with uppercase hex and a host bit set must be emitted canonically: Masked and lowercased")
	assert.NotContains(t, values, "2001:DB8::1/32",
		"the registry's raw spelling must not survive into the finding value")

	assert.Contains(t, values, "2001:db8:cafe::/48",
		"canonicalisation must be identity on an already-canonical prefix")

	assert.NotContains(t, values, "not-a-prefix",
		"a prefix netip.ParsePrefix rejects must still be skipped")
	assert.NotContains(t, values, "2001:db8:beef::/999")
	assert.Contains(t, values, "196.0.2.0/24",
		"records after a malformed inet6num must still be emitted: a bad prefix is skipped, not fatal")

	assert.Len(t, findings, 3,
		"two valid inet6num prefixes plus one covering CIDR for the v4 range; the malformed prefixes contribute nothing")
}

// ─── parseRPSLInetnums: the EOF flush ──────────────────────────────────────

// TestParseRPSLInetnums_CommitsFinalRecordEndingAtEOF pins the record every
// current parse silently loses.
//
// The commit block lives entirely inside the `strings.TrimSpace(line) == ""`
// branch, and the loop is followed directly by `return results, scanner.Err()`.
// A file whose last record is not followed by a blank line therefore drops that
// record with no error and no log line — the failure mode is indistinguishable
// from "this org owns nothing here". Both record kinds are covered because the
// commit switch has two arms, and an EOF flush that handles only one of them
// would leave the other still dropping.
//
// Each fixture is preceded by a normally terminated record, so a passing
// assertion proves the FINAL record was flushed rather than merely that the
// parser works.
func TestParseRPSLInetnums_CommitsFinalRecordEndingAtEOF(t *testing.T) {
	const leading = "inetnum:        198.51.100.0 - 198.51.100.255\n" +
		"netname:        LEADING\n" +
		"org:            ORG-ACME1-AP\n" +
		"\n"

	tests := []struct {
		name  string
		final string
		want  rpslInetnum
	}{
		{
			name: "inetnum range, file ends without a newline",
			final: "inetnum:        203.0.113.0 - 203.0.113.255\n" +
				"netname:        ACME-V4\n" +
				"org:            ORG-ACME1-AP",
			want: rpslInetnum{start: "203.0.113.0", end: "203.0.113.255", netname: "ACME-V4"},
		},
		{
			name: "inetnum range, file ends with a newline but no blank line",
			final: "inetnum:        203.0.113.0 - 203.0.113.255\n" +
				"netname:        ACME-V4\n" +
				"org:            ORG-ACME1-AP\n",
			want: rpslInetnum{start: "203.0.113.0", end: "203.0.113.255", netname: "ACME-V4"},
		},
		{
			name: "inet6num prefix, file ends without a newline",
			final: "inet6num:       2001:db8::/32\n" +
				"netname:        ACME-V6\n" +
				"org:            ORG-ACME1-AP",
			want: rpslInetnum{prefix: "2001:db8::/32", netname: "ACME-V6"},
		},
		{
			name: "inet6num prefix, file ends with a newline but no blank line",
			final: "inet6num:       2001:db8::/32\n" +
				"netname:        ACME-V6\n" +
				"org:            ORG-ACME1-AP\n",
			want: rpslInetnum{prefix: "2001:db8::/32", netname: "ACME-V6"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempRPSL(t, leading+tt.final)

			results, err := parseRPSLInetnums(path, []string{"ORG-ACME1-AP"})
			require.NoError(t, err)
			require.Contains(t, results, "ORG-ACME1-AP")

			assert.Contains(t, results["ORG-ACME1-AP"],
				rpslInetnum{start: "198.51.100.0", end: "198.51.100.255", netname: "LEADING"},
				"the blank-line-terminated record must still parse")
			assert.Contains(t, results["ORG-ACME1-AP"], tt.want,
				"the last record has no blank line after it; without an EOF flush it is dropped silently")
			assert.Len(t, results["ORG-ACME1-AP"], 2)
		})
	}
}

// TestParseRPSLInetnums_TrailingBlankLineCommitsExactlyOnce is the control on
// the EOF flush above: a record the blank-line branch already committed must not
// be committed a second time when the file ends. An unguarded post-loop flush
// would duplicate every well-formed file's last record, turning one asset into
// two — a worse outcome than the dropped record it was added to fix.
func TestParseRPSLInetnums_TrailingBlankLineCommitsExactlyOnce(t *testing.T) {
	content := "inetnum:        203.0.113.0 - 203.0.113.255\n" +
		"netname:        ACME-V4\n" +
		"org:            ORG-ACME1-AP\n" +
		"\n" +
		"inet6num:       2001:db8::/32\n" +
		"netname:        ACME-V6\n" +
		"org:            ORG-ACME1-AP\n" +
		"\n"
	path := writeTempRPSL(t, content)

	results, err := parseRPSLInetnums(path, []string{"ORG-ACME1-AP"})
	require.NoError(t, err)

	assert.Equal(t, []rpslInetnum{
		{start: "203.0.113.0", end: "203.0.113.255", netname: "ACME-V4"},
		{prefix: "2001:db8::/32", netname: "ACME-V6"},
	}, results["ORG-ACME1-AP"],
		"each record must appear exactly once: the blank line commits it, the EOF flush must not re-commit it")
}

// ─── Run: the cancelled secondary fetch ────────────────────────────────────

// rpslCancelOnURLTransport answers the download of one designated URL by
// cancelling the run's context and then handing back a plain 503 response.
// Every other URL gets the same 503 without the cancel, so a test can aim the
// teardown at whichever fetch it is exercising: APNIC's secondary inet6num
// file, or a registry's primary dump.
//
// The two halves are what make the test's premise real, and BOTH are
// load-bearing:
//
//   - It cancels, synchronously, before returning. RoundTrip runs on the
//     caller's goroutine, so by the time recordsFrom returns and Run evaluates
//     its `case ctx.Err() != nil` arm, the run context is already done. No
//     sleep, no polling, no race.
//
//   - It IGNORES req.Context() entirely and returns (resp, nil) — a transport
//     error is never produced. This is condition (b): because the RoundTripper
//     returns no error, net/http constructs no *url.Error and therefore never
//     wraps context.Canceled into the chain. cache.download then rejects the
//     response on status alone with fmt.Errorf("HTTP %d", …) — an error with an
//     EMPTY chain — and GetOrDownload wraps only that: "download <url>: HTTP
//     503". The error Run receives thus provably contains no context error at
//     any depth.
//
// Cancelling the context before calling Run instead would defeat the test: the
// transport would then likely fail the request with a *url.Error wrapping
// context.Canceled, errors.Is(err, context.Canceled) would hold today purely
// because the transport put it there, and the assertion below would go green
// without Run's arm having done anything. Here it cannot: any match on
// context.Canceled must come from Run's own error construction.
type rpslCancelOnURLTransport struct {
	cancelURL string
	cancel    context.CancelFunc
	urls      []string
}

func (t *rpslCancelOnURLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.urls = append(t.urls, req.URL.String())
	if req.URL.String() == t.cancelURL {
		t.cancel()
	}
	return &http.Response{
		Status:     "503 Service Unavailable",
		StatusCode: http.StatusServiceUnavailable,
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

// TestNewAPNICPlugin_Run_CancelledSecondaryFetchWrapsContextError pins what the
// caller learns when a run is torn down mid-flight during the best-effort
// inet6num download.
//
// rpsl.go's secondary-fetch switch tests cancellation FIRST — ahead of the
// success arm — and classifies it on ctx.Err(), deliberately not on the error's
// identity, then wraps BOTH the context error and the transport error through
// abortedFetchError:
//
//	switch {
//	case ctx.Err() != nil:
//	    return nil, p.abortedFetchError("inet6num", ctx.Err(), err)
//	case err == nil:
//	    // merge the v6 records
//	default:
//	    // warn and continue with IPv4 only
//	}
//
// The arm's POSITION is load-bearing, because err == nil does not mean the
// fetch succeeded: cache.GetOrDownload falls back to a stale local file and
// returns a NIL error whenever a download fails, a download aborted by this
// run's own ctx included. Testing err == nil first therefore routed a
// torn-down run into the success arm, merged stale IPv6 records, and returned
// no error at all — a run that never finished, reported as complete, on data
// of unknown age. TestNewAPNICPlugin_Run_CancelledSecondaryStaleFallbackFailsRun
// pins that shape directly.
//
// The arm's CLASSIFIER is load-bearing for a separate reason: it keys off
// ctx.Err() rather than the error's identity because the transport error
// carries no context error in its chain when the mirror happened to fail for
// its own reasons at the same moment. A caller running
// errors.Is(err, context.Canceled) — the standard way to tell "we tore this
// run down" from "this registry mirror is broken" — would get false, and a
// cancelled run would be misreported as an APNIC outage. Retry logic and
// alerting both key off exactly that distinction.
//
// And both halves of the wrap are load-bearing. The returned error must
// satisfy BOTH assertions at once: matchable as the cancellation, and still
// carrying the transport failure's own text. Returning the bare transport
// error fails the first; returning a bare ctx.Err() would pass the first and
// throw the 503 away — the only diagnostic separating a cancelled run from a
// cancelled run that was *also* failing — failing the second.
//
// Preconditions that make the arm reachable, each asserted rather than assumed:
// APNIC is the only registry with a non-empty cacheURL6; the handle list is
// non-empty so Run does not short-circuit before any fetch; the IPv4 entry is
// seeded warm so the PRIMARY fetch succeeds off disk and the failure under test
// is unambiguously the secondary one; and the IPv6 entry is asserted absent so
// GetOrDownload's stale-cache fallback cannot rescue the download and mask it.
func TestNewAPNICPlugin_Run_CancelledSecondaryFetchWrapsContextError(t *testing.T) {
	home := rpslTempHome(t)
	blocked := rpslBlockGlobalTransport(t)

	seedRPSLCacheEntry(t, home, cache.APNICInetURL, rpslDIAPNICV4Only)
	require.NoFileExists(t, rpslCacheEntryPath(home, cache.APNICInet6URL),
		"the inet6num entry must be cold, or GetOrDownload's stale-cache fallback would swallow the failed download")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &rpslCancelOnURLTransport{cancelURL: cache.APNICInet6URL, cancel: cancel}
	plugin, err := NewAPNICPlugin(&http.Client{Transport: transport})
	require.NoError(t, err)

	findings, err := plugin.Run(ctx, plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})

	require.Equal(t, []string{cache.APNICInet6URL}, transport.urls,
		"only the secondary fetch may hit the network: a warm IPv4 entry means the primary never downloads")
	require.Empty(t, blocked.recorded(),
		"a request escaped to http.DefaultTransport instead of the injected client")
	require.Error(t, err,
		"the run context is done, so the best-effort arm must fail the run rather than degrade to IPv4-only")

	assert.ErrorIs(t, err, context.Canceled,
		"a run torn down mid-fetch must be matchable as the cancellation; the raw transport error is not, so callers read a cancelled run as an APNIC outage")
	assert.Contains(t, err.Error(), "503",
		"the transport failure's own text must survive the wrap: a bare ctx.Err() would discard the only diagnostic saying what the mirror actually did")
	assert.Empty(t, findings,
		"the run failed, so no partial IPv4 findings may be returned alongside the error")
}

// ─── Run: cancellation masked by the stale-cache fallback ──────────────────

// seedStaleRPSLCacheEntry seeds a cache entry and then backdates its mtime past
// cache.DefaultTTL, so cache.GetOrDownload treats it as stale and actually
// attempts a download.
//
// The backdating is not a detail; it is the difference between exercising the
// stale-cache fallback and proving nothing while looking green.
// seedRPSLCacheEntry writes with the CURRENT mtime, and Cache.isStale is
// time.Since(info.ModTime()) > c.ttl against a 24h DefaultTTL — so a freshly
// seeded entry is WARM, GetOrDownload returns at its `if !c.isStale(localPath)`
// early exit, download is never called, the transport is never reached, and the
// cancel hook never fires. A test built on a warm entry would assert against a
// run that was never cancelled at all.
//
// Because a warm entry fails silently that way, every caller below also asserts
// the recorded transport URLs: an actual request for this URL is the observable
// proof that the entry was stale enough to reach download.
func seedStaleRPSLCacheEntry(t *testing.T, home, url, content string) string {
	t.Helper()

	path := seedRPSLCacheEntry(t, home, url, content)
	backdated := time.Now().Add(-2 * cache.DefaultTTL)
	require.NoError(t, os.Chtimes(path, backdated, backdated))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Greater(t, time.Since(info.ModTime()), cache.DefaultTTL,
		"the seeded entry must be older than cache.DefaultTTL, or GetOrDownload short-circuits before download and the fetch under test never happens")

	return path
}

// TestNewAPNICPlugin_Run_CancelledSecondaryStaleFallbackFailsRun is the sibling
// of the cold-cache test above with its single most consequential precondition
// inverted: the inet6num entry is present but STALE rather than absent.
//
// That inversion is the whole defect. With the entry absent, a cancelled
// download surfaces to Run as an error, so even the pre-fix `case err == nil`
// ordering fell through to the cancellation arm and the run failed — loudly and
// with a badly typed error, but it failed. With the entry present and stale,
// cache.GetOrDownload catches the failed download, stats the stale file, and
// returns (path, nil). recordsFrom then hands Run a NIL error and a full set of
// stale IPv6 records, and the pre-fix switch took the success arm: it merged
// them and returned findings with no error. A run torn down mid-refresh
// reported as complete, on data of unknown age.
//
// So the assertions here are not mainly about the error's shape. `findings`
// being empty is the heart of it: pre-fix, this code path did not return a
// mis-typed error — it returned RESULTS.
func TestNewAPNICPlugin_Run_CancelledSecondaryStaleFallbackFailsRun(t *testing.T) {
	home := rpslTempHome(t)
	blocked := rpslBlockGlobalTransport(t)

	seedRPSLCacheEntry(t, home, cache.APNICInetURL, rpslDIAPNICV4Only)
	stalePath := seedStaleRPSLCacheEntry(t, home, cache.APNICInet6URL, rpslDIAPNICV6Only)
	require.FileExists(t, stalePath,
		"the fallback under test only exists because GetOrDownload finds a file to fall back to")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &rpslCancelOnURLTransport{cancelURL: cache.APNICInet6URL, cancel: cancel}
	plugin, err := NewAPNICPlugin(&http.Client{Transport: transport})
	require.NoError(t, err)

	findings, err := plugin.Run(ctx, plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})

	require.Equal(t, []string{cache.APNICInet6URL}, transport.urls,
		"exactly one request, for the inet6num file: this is the proof the seeded v6 entry was genuinely stale (a warm entry short-circuits GetOrDownload before download, so the cancel hook would never fire and the test would pass having exercised nothing) and that the warm v4 entry served the primary off disk")
	require.Empty(t, blocked.recorded(),
		"a request escaped to http.DefaultTransport instead of the injected client")

	require.Error(t, err,
		"the run context is done, so the run must fail rather than complete on stale IPv6 records")
	assert.ErrorIs(t, err, context.Canceled,
		"a run torn down mid-fetch must be matchable as the cancellation, not as a registry outage")
	assert.Empty(t, findings,
		"the defect in one assertion: the stale fallback made the aborted fetch look successful, so the pre-fix success arm merged stale records and returned them alongside a nil error")

	assert.NotContains(t, err.Error(), "transport:",
		"GetOrDownload swallowed the 503 and returned nil when it fell back to the stale file, so there is no transport error to report; a transport clause here would mean the fallback never fired and this test is not exercising the defect it names")
	assert.NotContains(t, err.Error(), "%!w",
		"abortedFetchError must not hand fmt a nil fetch error to %w, which renders as the literal %!w(<nil>)")
}

// TestNewAFRINICPlugin_Run_CancelledPrimaryStaleFallbackFailsRun moves the same
// defect onto the PRIMARY fetch, which needed its own ctx.Err() test.
//
// AFRINIC is the right registry for it: afrinicConfig has an empty cacheURL6
// because the registry ships one combined dump, so the primary fetch is the
// only fetch and nothing downstream can mask the result. Pre-fix the primary
// path had no cancellation test at all — it checked `if err != nil` and
// nothing else — so a cancelled download rescued by the stale-cache fallback
// returned a nil error, parsed the stale dump, and completed the run with
// findings. Identical failure mode to the secondary arm, one function earlier.
func TestNewAFRINICPlugin_Run_CancelledPrimaryStaleFallbackFailsRun(t *testing.T) {
	home := rpslTempHome(t)
	blocked := rpslBlockGlobalTransport(t)

	seedStaleRPSLCacheEntry(t, home, cache.AFRINICAllURL, rpslDIAFRINICDump)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &rpslCancelOnURLTransport{cancelURL: cache.AFRINICAllURL, cancel: cancel}
	plugin, err := NewAFRINICPlugin(&http.Client{Transport: transport})
	require.NoError(t, err)

	findings, err := plugin.Run(ctx, plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"afrinic_handles": "ORG-ACME1-AF"},
	})

	require.Equal(t, []string{cache.AFRINICAllURL}, transport.urls,
		"exactly one request, for the combined dump: it proves the seeded entry was genuinely stale (a warm entry never reaches download, so the cancel hook never fires) and that an empty cacheURL6 produced no second fetch")
	require.Empty(t, blocked.recorded(),
		"a request escaped to http.DefaultTransport instead of the injected client")

	require.Error(t, err,
		"the run context is done, so the primary fetch must fail the run rather than complete on a stale dump")
	assert.ErrorIs(t, err, context.Canceled,
		"a run torn down during the primary fetch must be matchable as the cancellation")
	assert.Empty(t, findings,
		"pre-fix the primary path returned the stale dump's findings with a nil error; a cancelled run must return neither")

	assert.NotContains(t, err.Error(), "transport:",
		"the stale fallback swallowed the 503 and returned nil, so there is no transport error to report; a transport clause here would mean the fallback never fired")
	assert.NotContains(t, err.Error(), "%!w",
		"abortedFetchError must not hand fmt a nil fetch error to %w")
}

// TestNewAPNICPlugin_Run_CancelledColdPrimaryFetchWrapsContextError is the
// primary fetch with NO cache entry to fall back to, which is the other half of
// the primary arm's contract.
//
// Here GetOrDownload cannot rescue anything: it stats a path that does not
// exist and returns ("", "download <url>: HTTP 503") — an error whose chain is
// empty, because the stub RoundTripper returns (resp, nil) and net/http
// therefore never builds a *url.Error around context.Canceled. Pre-fix that raw
// error was exactly what the caller got, so errors.Is(err, context.Canceled)
// was false and a torn-down run read as an APNIC outage.
//
// This test is the reason abortedFetchError takes both errors: the 503 must
// still be legible in the message, and the cancellation must still be
// matchable, from one error value.
func TestNewAPNICPlugin_Run_CancelledColdPrimaryFetchWrapsContextError(t *testing.T) {
	home := rpslTempHome(t)
	blocked := rpslBlockGlobalTransport(t)

	require.NoFileExists(t, rpslCacheEntryPath(home, cache.APNICInetURL),
		"the cold-cache half of the contract requires no entry to fall back to, or GetOrDownload would return a nil error and this would be the stale-fallback test instead")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &rpslCancelOnURLTransport{cancelURL: cache.APNICInetURL, cancel: cancel}
	plugin, err := NewAPNICPlugin(&http.Client{Transport: transport})
	require.NoError(t, err)

	findings, err := plugin.Run(ctx, plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"apnic_handles": "ORG-ACME1-AP"},
	})

	require.Equal(t, []string{cache.APNICInetURL}, transport.urls,
		"the primary fetch must fail the run outright: the best-effort inet6num download may not be attempted after the run is already lost")
	require.Empty(t, blocked.recorded(),
		"a request escaped to http.DefaultTransport instead of the injected client")

	require.Error(t, err,
		"the primary file is not best-effort; losing it must fail the run")
	assert.ErrorIs(t, err, context.Canceled,
		"pre-fix the caller got the bare \"download …: HTTP 503\", whose chain holds no context error, so a cancelled run was indistinguishable from a broken mirror")
	assert.Contains(t, err.Error(), "503",
		"a bare ctx.Err() would pass the assertion above and discard the only diagnostic saying what the mirror actually did")
	assert.Contains(t, err.Error(), "transport:",
		"both halves of abortedFetchError's wrap must be present when the fetch produced a real transport error")
	assert.Empty(t, findings,
		"the run failed before any record was parsed, so there is nothing to return alongside the error")
}
