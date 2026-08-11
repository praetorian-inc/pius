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
