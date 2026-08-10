package domains

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockCRTShServer(entries []map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
}

// deadResolver is a fakeResolver (defined in dns_brute_test.go) that never
// resolves anything. It is the default stand-in for tests that don't care
// about DNS state, keeping the suite hermetic and fast — without it, a nil
// lookup falls through to real DNS against 8.8.8.8 with a 5s timeout per name.
func deadResolver() *fakeResolver {
	return &fakeResolver{fn: func(string) []string { return nil }}
}

// cnameResolver is a fakeResolver that ALSO implements CNAMEResolver, unlike
// plain fakeResolver — which is exactly why the other tests in this file (and
// all of dns_brute_test.go) degrade to address-only semantics rather than
// exercising the CNAME path. Tests that need to drive dangling-CNAME live-DNS
// behavior construct one of these instead.
type cnameResolver struct {
	*fakeResolver
	cnameFn func(host string) string
}

func newCNAMEResolver(resolveFn func(host string) []string, cnameFn func(host string) string) *cnameResolver {
	return &cnameResolver{fakeResolver: &fakeResolver{fn: resolveFn}, cnameFn: cnameFn}
}

func (c *cnameResolver) ResolveCNAME(host string) string {
	return c.cnameFn(host)
}

func TestCRTShPlugin_ParsesDomains(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "api.example.com"},
		{"name_value": "www.example.com"},
		{"name_value": "mail.example.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "crt-sh", f.Source)

		// Every name gets the observation signal. Each subdomain here also
		// falls under example.com's own zone (the no-Meta fallback), so it
		// also earns the owned-zone signal. None resolve (deadResolver), so
		// confCRTShLiveDNS is absent. Two independent signals, two entries —
		// never one pre-summed entry.
		require.Len(t, f.Confidences, 2)
		assert.InDelta(t, confCRTShObservation, f.Confidences[0].Score, 0.001)
		assert.Contains(t, f.Confidences[0].Justification, f.Value)
		assert.Contains(t, f.Confidences[0].Justification, "example.com")
		assert.Contains(t, f.Confidences[0].Justification, srv.URL+"/?q=example.com&output=json")
		assert.InDelta(t, confCRTShOwnedZone, f.Confidences[1].Score, 0.001)
		assert.Contains(t, f.Confidences[1].Justification, "example.com")

		assert.NotContains(t, f.Data, "confidence")
		assert.NotContains(t, f.Data, "confidences")
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "api.example.com")
	assert.Contains(t, values, "www.example.com")
	assert.Contains(t, values, "mail.example.com")
}

// TestCRTShPlugin_DropsBareWildcardAndSeedWildcard was previously named
// TestCRTShPlugin_SkipsWildcards, which now describes the opposite of the
// plugin's behavior: wildcard PARENTS are recovered and kept (see
// TestCRTShPlugin_WildcardParentRecovered), not discarded. This test's two
// wildcard entries both still yield no finding, but for two different
// reasons that have nothing to do with "wildcards are skipped":
//   - "*.example.com" strips to "example.com", which is the queried seed and
//     is never re-emitted.
//   - a bare "*" has nothing left after stripping and is dropped by
//     DropWildcard itself.
func TestCRTShPlugin_DropsBareWildcardAndSeedWildcard(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "*.example.com"},
		{"name_value": "api.example.com"},
		{"name_value": "*"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	for _, f := range findings {
		assert.False(t, strings.HasPrefix(f.Value, "*"), "wildcards must be filtered: %s", f.Value)
	}
	require.Len(t, findings, 1)
	assert.Equal(t, "api.example.com", findings[0].Value)
}

// TestCRTShPlugin_WildcardParentRecovered pins the actual current behavior:
// "*.foo.example.com" is a real zone that had a certificate issued for it, and
// its parent is recovered rather than discarded.
func TestCRTShPlugin_WildcardParentRecovered(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "*.foo.example.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "foo.example.com", findings[0].Value)
}

// TestCRTShPlugin_SeedNeverEmitted is the direct regression test for the
// intentional change: the queried domain is never re-emitted as a finding,
// even though it is a completely ordinary entry in the crt.sh response.
func TestCRTShPlugin_SeedNeverEmitted(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "example.com"},
		{"name_value": "api.example.com"},
		{"name_value": "www.example.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	var values []string
	for _, f := range findings {
		values = append(values, f.Value)
	}
	assert.NotContains(t, values, "example.com", "the queried seed must never be re-emitted as a finding")
	assert.Contains(t, values, "api.example.com")
	assert.Contains(t, values, "www.example.com")
	assert.Len(t, findings, 2)
}

// TestCRTShPlugin_DeduplicatesDomains repeats a SUBDOMAIN, not the seed. Using
// the seed for this (as the previous version did) is a vacuous test now: the
// seed is skipped unconditionally, so it always yields zero occurrences
// regardless of whether dedup logic works at all.
func TestCRTShPlugin_DeduplicatesDomains(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "api.example.com\napi.example.com"},
		{"name_value": "api.example.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	count := 0
	for _, f := range findings {
		if f.Value == "api.example.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "api.example.com should appear exactly once after dedup")
}

// TestCRTShPlugin_NormalizesDomains asserts normalization on non-seed names.
// Asserting on values["example.com"] (as the previous version did) tests
// nothing now, because that key is the skipped seed and is never present.
func TestCRTShPlugin_NormalizesDomains(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "API.Example.Com."},
		{"name_value": "  MAIL.EXAMPLE.COM  "},
		{"name_value": "www.example.com."},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	values := make(map[string]bool)
	for _, f := range findings {
		values[f.Value] = true
		assert.Equal(t, strings.ToLower(strings.TrimSpace(f.Value)), f.Value,
			"value %q must be lowercase and trimmed", f.Value)
	}
	assert.True(t, values["api.example.com"], "API.Example.Com. should normalize to api.example.com")
	assert.True(t, values["mail.example.com"], "whitespace should be trimmed")
	assert.True(t, values["www.example.com"], "trailing dot should be removed")
}

func TestCRTShPlugin_MultipleDomainsInNameValue(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "api.example.com\nwww.example.com\nmail.example.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Len(t, findings, 3)
}

func TestCRTShPlugin_PrefersDomainOverOrgName(t *testing.T) {
	var receivedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	_, _ = p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Domain:  "acme.com",
	})
	assert.Equal(t, "acme.com", receivedQuery, "domain should be used over org name")
}

func TestCRTShPlugin_GracefulOnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCRTShPlugin_GracefulOnNetworkError(t *testing.T) {
	p := &CRTShPlugin{client: client.NewNoRetry(), baseURL: "http://127.0.0.1:1", lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

// TestCRTShPlugin_ConfidenceBanding drives DNS state through a stub resolver
// so the four confidence bands are deterministic, and asserts the TOTALS —
// what Guard actually routes on — rather than individual entries.
func TestCRTShPlugin_ConfidenceBanding(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "resolves.example.com"},
		{"name_value": "dead.example.com"},
		{"name_value": "resolves.other.org"},
		{"name_value": "dead.other.org"},
	})
	defer srv.Close()

	resolving := map[string]bool{
		"resolves.example.com": true,
		"resolves.other.org":   true,
	}
	fake := &fakeResolver{fn: func(host string) []string {
		if resolving[host] {
			return []string{"1.2.3.4"}
		}
		return nil
	}}

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: fake}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	require.NoError(t, err)

	totals := make(map[string]float64, len(findings))
	for _, f := range findings {
		totals[f.Value] = plugins.TotalConfidence(f)
	}

	assert.InDelta(t, 0.80, totals["resolves.example.com"], 0.001, "in-zone + resolves")
	assert.InDelta(t, 0.60, totals["dead.example.com"], 0.001, "in-zone + dead")
	assert.InDelta(t, 0.50, totals["resolves.other.org"], 0.001, "out-of-zone + resolves")
	// out-of-zone + dead totals 0.30, below ConfidenceLow (0.35), so Run drops
	// it at the noise floor rather than emitting it scored at 0.30.
	assert.NotContains(t, totals, "dead.other.org",
		"out-of-zone + dead is below the noise floor and must be dropped, not scored 0.30")
}

// TestCRTShPlugin_MetaOwnedDomainsWidensScope is the most important new
// behavior test: it is what preserves cross-brand discovery. Without
// Meta["owned_domains"], a name under an unrelated registrable zone scores
// out-of-zone. With the caller's owned-domain set widened to include that
// zone, the exact same name scores in-zone.
func TestCRTShPlugin_MetaOwnedDomainsWidensScope(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "brand.otherbrand.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "example.com",
		Meta:   map[string]string{MetaOwnedDomains: "example.com,otherbrand.com"},
	})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.InDelta(t, 0.60, plugins.TotalConfidence(findings[0]), 0.001,
		"otherbrand.com is owned via Meta, so this is in-zone + dead")
}

// TestCRTShPlugin_MetaOwnedDomainsFallbackToQueryZone is the other half of the
// widen-scope behavior: absent any Meta, scope falls back to the queried
// domain's own registrable zone, so the identical name scores out-of-zone.
//
// The name is given a live address (rather than deadResolver's no-DNS
// default) so this lands at 0.50 (out-of-zone + live), not 0.30. Pairing
// "out-of-zone" with "dead" would total 0.30, which Run now drops at the
// noise floor — that would make this test assert on an absent finding and
// conflate the floor behavior (covered elsewhere) with the scope decision
// this test exists to guard. Its sibling,
// TestCRTShPlugin_MetaOwnedDomainsWidensScope, still lands at 0.60 (in-zone +
// dead), so the two totals remain distinguishable and each isolates exactly
// one variable: Meta widening the zone, here; DNS liveness, there.
func TestCRTShPlugin_MetaOwnedDomainsFallbackToQueryZone(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "brand.otherbrand.com"},
	})
	defer srv.Close()

	fake := &fakeResolver{fn: func(string) []string { return []string{"1.2.3.4"} }}
	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: fake}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.InDelta(t, 0.50, plugins.TotalConfidence(findings[0]), 0.001,
		"without Meta, otherbrand.com is out-of-zone; a live address keeps it "+
			"above the noise floor so this isolates the scope decision")
}

// TestCRTShPlugin_EntropyJunkGating pins the conjunction dropDeadJunk depends
// on: a high-entropy label survives if it resolves, and is dropped only when
// it ALSO fails to resolve. Neither signal alone is sufficient.
func TestCRTShPlugin_EntropyJunkGating(t *testing.T) {
	junkName := "jvoind698msu93mkf5na9l2igbihsccp5d1buy.example.com"

	t.Run("resolving junk-looking name survives", func(t *testing.T) {
		srv := mockCRTShServer([]map[string]string{{"name_value": junkName}})
		defer srv.Close()

		fake := &fakeResolver{fn: func(string) []string { return []string{"1.2.3.4"} }}
		p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: fake}
		findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, junkName, findings[0].Value)
	})

	t.Run("dead junk-looking name is dropped", func(t *testing.T) {
		srv := mockCRTShServer([]map[string]string{{"name_value": junkName}})
		defer srv.Close()

		p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
		findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

// TestCRTShPlugin_OOBNamesDroppedUnconditionally proves the OOB/canary drop
// does not consult DNS state at all: the resolver reports everything as
// resolving, and the OOB name is still dropped while an ordinary name survives.
func TestCRTShPlugin_OOBNamesDroppedUnconditionally(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "abc123.interactsh.example.com"},
		{"name_value": "api.example.com"},
	})
	defer srv.Close()

	fake := &fakeResolver{fn: func(string) []string { return []string{"1.2.3.4"} }}
	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: fake}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	require.NoError(t, err)

	var values []string
	for _, f := range findings {
		values = append(values, f.Value)
	}
	assert.NotContains(t, values, "abc123.interactsh.example.com")
	assert.Contains(t, values, "api.example.com")
}

// TestCRTShPlugin_ConfidenceNeverInData guards the SDK/Guard contract: scoring
// lives exclusively in Finding.Confidences. Data is source-specific metadata
// only (org, query, not_after here).
func TestCRTShPlugin_ConfidenceNeverInData(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "api.example.com", "not_after": "2030-01-01T00:00:00"},
	})
	defer srv.Close()

	fake := &fakeResolver{fn: func(string) []string { return []string{"1.2.3.4"} }}
	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: fake}
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme", Domain: "example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.NotContains(t, findings[0].Data, "confidence")
	assert.NotContains(t, findings[0].Data, "confidences")
	assert.Contains(t, findings[0].Data, "org")
	assert.Contains(t, findings[0].Data, "query")
	assert.Contains(t, findings[0].Data, "not_after")
}

// TestCRTShPlugin_ResolveAll_RespectsContextCancellation exercises resolveAll
// directly with an already-cancelled context. The resolver must never be
// consulted once the context is done: every plugin's Run contract requires
// respecting cancellation, and this is the seam where that would be violated.
func TestCRTShPlugin_ResolveAll_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// t.Errorf, not t.Fatalf: this callback runs on a worker goroutine spawned
	// by resolveAll, and t.Fatalf calls runtime.Goexit on the calling
	// goroutine — it would kill the worker rather than fail the test, and the
	// failure is not guaranteed to be reported.
	fake := &fakeResolver{fn: func(host string) []string {
		t.Errorf("resolver must not be called once ctx is cancelled (host=%s)", host)
		return nil
	}}
	p := &CRTShPlugin{client: client.New(), lookup: fake}

	names := []string{"a.example.com", "b.example.com", "c.example.com"}
	resolved := p.resolveAll(ctx, names)

	require.Len(t, resolved, len(names))
	for _, name := range names {
		assert.False(t, resolved[name].live(), "%s must not be reported as resolved when ctx was already cancelled", name)
	}
}

// TestCRTShPlugin_DanglingCNAME_LiveDNSRegressionGuard is the regression test
// for the highest-value class of result this plugin produces: a name with no
// address but a published CNAME must score 0.80 (in-zone + live DNS), NOT
// 0.60 (in-zone + dead), and must NOT need review.
//
// This matters beyond a scoring nuance: Guard routes needs-review findings to
// Preseeds, and Guard's correlator is asset-only, so if this ever regresses
// back to 0.60, the subdomain-takeover finding silently disappears downstream
// — the name still gets reported, but the vulnerability does not.
func TestCRTShPlugin_DanglingCNAME_LiveDNSRegressionGuard(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "orphan.example.com"},
	})
	defer srv.Close()

	resolver := newCNAMEResolver(
		func(string) []string { return nil }, // never has an address
		func(host string) string {
			if host == "orphan.example.com" {
				return "deprovisioned.s3.amazonaws.com"
			}
			return ""
		},
	)

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: resolver}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	f := findings[0]

	assert.InDelta(t, 0.80, plugins.TotalConfidence(f), 0.001,
		"a dangling CNAME must score as in-zone + live DNS (0.80), NOT in-zone + dead (0.60) — "+
			"regressing this loses the subdomain-takeover finding")
	assert.False(t, plugins.NeedsReview(f),
		"0.80 clears ConfidenceHigh, so this must not be routed to needs-review")
}

// TestCRTShPlugin_DanglingCNAME_JustificationNamesTarget asserts that the
// live-DNS justification for a dangling-CNAME name differs from the address
// case and names the CNAME target — the triage-actionable detail a human (or
// downstream takeover check) needs.
func TestCRTShPlugin_DanglingCNAME_JustificationNamesTarget(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "orphan.example.com"},
		{"name_value": "addressed.example.com"},
	})
	defer srv.Close()

	resolver := newCNAMEResolver(
		func(host string) []string {
			if host == "addressed.example.com" {
				return []string{"1.2.3.4"}
			}
			return nil
		},
		func(host string) string {
			if host == "orphan.example.com" {
				return "deprovisioned.s3.amazonaws.com"
			}
			return ""
		},
	)

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: resolver}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	require.NoError(t, err)
	require.Len(t, findings, 2)

	byValue := make(map[string]plugins.Finding, len(findings))
	for _, f := range findings {
		byValue[f.Value] = f
	}

	cnameFinding, ok := byValue["orphan.example.com"]
	require.True(t, ok)
	require.NotEmpty(t, cnameFinding.Confidences)
	cnameJustification := cnameFinding.Confidences[len(cnameFinding.Confidences)-1].Justification
	assert.Contains(t, cnameJustification, "deprovisioned.s3.amazonaws.com",
		"the CNAME target is the triage-actionable detail and must appear in the justification")

	addressedFinding, ok := byValue["addressed.example.com"]
	require.True(t, ok)
	require.NotEmpty(t, addressedFinding.Confidences)
	addressedJustification := addressedFinding.Confidences[len(addressedFinding.Confidences)-1].Justification

	assert.NotEqual(t, cnameJustification, addressedJustification,
		"the CNAME and address live-DNS justifications must read differently to a human")
}

// TestCRTShPlugin_EntropyJunkGating_DanglingCNAME extends
// TestCRTShPlugin_EntropyJunkGating to the CNAME half of live(): a
// high-entropy label with a live CNAME must survive the entropy gate, and the
// identical label with neither an address nor a CNAME must still be dropped.
// The conjunction (entropy AND dead) is the whole point of the gate.
func TestCRTShPlugin_EntropyJunkGating_DanglingCNAME(t *testing.T) {
	junkName := "jvoind698msu93mkf5na9l2igbihsccp5d1buy.example.com"

	t.Run("junk-looking name with a live CNAME survives", func(t *testing.T) {
		srv := mockCRTShServer([]map[string]string{{"name_value": junkName}})
		defer srv.Close()

		resolver := newCNAMEResolver(
			func(string) []string { return nil },
			func(string) string { return "target.example.net" },
		)
		p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: resolver}
		findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, junkName, findings[0].Value)
	})

	t.Run("same junk-looking name with neither address nor CNAME is dropped", func(t *testing.T) {
		srv := mockCRTShServer([]map[string]string{{"name_value": junkName}})
		defer srv.Close()

		resolver := newCNAMEResolver(
			func(string) []string { return nil },
			func(string) string { return "" },
		)
		p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: resolver}
		findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

// TestCRTShPlugin_ResolverWithoutCNAMESupport_DegradesToAddressOnly guards the
// type assertion's fallback in resolve(): fakeResolver/deadResolver do NOT
// implement CNAMEResolver, so a name with no address must degrade to
// address-only semantics (in-zone + dead, 0.60) rather than erroring or
// somehow still earning live-DNS credit.
func TestCRTShPlugin_ResolverWithoutCNAMESupport_DegradesToAddressOnly(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "orphan.example.com"},
	})
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: deadResolver()}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.InDelta(t, 0.60, plugins.TotalConfidence(findings[0]), 0.001,
		"a resolver without CNAMEResolver must degrade to address-only semantics: in-zone + dead")
}

// TestCRTShPlugin_Run_CancelledMidResolution_ReturnsErrorNotMisscoredFindings
// guards the failure mode Run's post-resolveAll cancellation check exists to
// prevent: silently mis-scored output, not a crash. resolveAll leaves a
// zero-value dnsPresence for every name it never reached once ctx is done,
// which reads identically to "no DNS record" — so without this check, a
// cancellation mid-resolution would fall straight through dropDeadJunk and
// scoring, quietly deleting unreached high-entropy names as dead and
// dropping every surviving unreached name a confidence band, all while
// returning (nil error). The crt.sh fetch itself must succeed so the ctx
// cancellation — not a failed HTTP call — is what triggers the path: the
// fake resolver cancels ctx from inside resolveAll's worker goroutine, after
// the HTTP round-trip has already completed.
func TestCRTShPlugin_Run_CancelledMidResolution_ReturnsErrorNotMisscoredFindings(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "api.example.com"},
	})
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &fakeResolver{fn: func(string) []string {
		cancel() // simulate the RunTimeout (or caller cancellation) firing mid-resolution
		return nil
	}}

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: fake}
	findings, err := p.Run(ctx, plugins.Input{Domain: "example.com"})

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled),
		"Run must surface the cancellation itself, not swallow it")
	assert.Nil(t, findings,
		"a cancelled resolution pass must withhold ALL findings, not return partial/mis-scored results")
}

// TestCRTShPlugin_ConfidenceFloor_DropsBelowKeepsAtOrAbove is the direct
// regression guard for the floor comparison Change B added
// (TotalConfidence(finding) < ConfidenceLow): a below-floor finding must
// never reach the findings slice, and a finding at-or-above the floor must
// always survive. This is deliberately narrower than
// TestCRTShPlugin_ConfidenceBanding, which exercises all four scoring bands
// together — this test isolates the floor decision on its own so a
// regression there (e.g. widening "<" to "<=") is caught by a test whose
// only job is the boundary, not one carrying three other assertions.
//
// crt-sh's confidence entries are fixed additive constants (0.30 observation,
// +0.30 owned zone, +0.20 live DNS), so the only totals this plugin's real
// scoring can ever produce are 0.30, 0.50, 0.60, and 0.80 — there is no
// combination that lands on ConfidenceLow (0.35) exactly. 0.50 is the lowest
// total the plugin can produce above the floor, so it stands in for "at or
// just above" here; see the test-implementation report for why an exact-0.35
// case is unreachable through Run().
func TestCRTShPlugin_ConfidenceFloor_DropsBelowKeepsAtOrAbove(t *testing.T) {
	srv := mockCRTShServer([]map[string]string{
		{"name_value": "below.other.org"},
		{"name_value": "atorabove.other.org"},
	})
	defer srv.Close()

	resolving := map[string]bool{"atorabove.other.org": true}
	fake := &fakeResolver{fn: func(host string) []string {
		if resolving[host] {
			return []string{"1.2.3.4"}
		}
		return nil
	}}

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL, lookup: fake}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})
	require.NoError(t, err)

	totals := make(map[string]float64, len(findings))
	for _, f := range findings {
		totals[f.Value] = plugins.TotalConfidence(f)
	}

	assert.NotContains(t, totals, "below.other.org",
		"0.30 is below ConfidenceLow (0.35) and must be dropped")
	require.Contains(t, totals, "atorabove.other.org",
		"0.50 is above ConfidenceLow (0.35) and must be kept")
	assert.InDelta(t, 0.50, totals["atorabove.other.org"], 0.001)
}
