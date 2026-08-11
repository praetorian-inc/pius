package cidrs

import (
	"context"
	"net/http"
	"testing"

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

// rpslCancelDuringV6Transport answers the secondary (inet6num) download by
// cancelling the run's context and then handing back a plain 503 response.
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
type rpslCancelDuringV6Transport struct {
	cancelURL string
	cancel    context.CancelFunc
	urls      []string
}

func (t *rpslCancelDuringV6Transport) RoundTrip(req *http.Request) (*http.Response, error) {
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
// rpsl.go's secondary-fetch switch classifies on ctx.Err(), deliberately not on
// the error's identity, and then returns the raw transport error:
//
//	case ctx.Err() != nil:
//	    return nil, err
//
// That raw error carries no context error in its chain when the mirror happened
// to fail for its own reasons at the same moment. A caller running
// errors.Is(err, context.Canceled) — the standard way to tell "we tore this
// run down" from "this registry mirror is broken" — gets false, and a cancelled
// run is misreported as an APNIC outage. Retry logic and alerting both key off
// exactly that distinction.
//
// So the returned error must satisfy BOTH assertions at once: matchable as the
// cancellation, and still carrying the transport failure's own text. Returning
// the bare transport error fails the first; returning a bare ctx.Err() would
// pass the first and throw the 503 away, failing the second.
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

	transport := &rpslCancelDuringV6Transport{cancelURL: cache.APNICInet6URL, cancel: cancel}
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
