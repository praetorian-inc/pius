package domains

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openrdap/rdap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const (
	fullWhoisRecord = "Domain Name: EXAMPLE.COM\n" +
		"Registrar: Example Registrar, LLC\n" +
		"Registrant Organization: Acme Corp\n" +
		"Registrant Name: John Doe\n" +
		"Registrant Email: admin@acme.com\n"

	orgOnlyWhoisRecord = "Domain Name: EXAMPLE.COM\n" +
		"Registrant Organization: Acme Corp\n"

	notFoundWhoisRecord = "No match for \"EXAMPLE.COM\".\n"

	injectedWhoisRecord = "Domain Name: EXAMPLE.COM\n" +
		"Registrant Organization: Sentinel Injected Corp\n" +
		"Registrant Email: sentinel@injected.test\n"
)

type stubRDAPSource struct {
	raw   string
	err   error
	calls int
}

func (s *stubRDAPSource) rdapRecord(_ context.Context, _ string) (whoisRecord, error) {
	s.calls++
	if s.err != nil {
		return whoisRecord{}, s.err
	}
	return textWhoisRecord(whoisMethodRDAP, s.raw)
}

func failingRDAP() *stubRDAPSource {
	return &stubRDAPSource{err: errors.New("rdap: no working servers")}
}

// stubWhoisReferralChain answers the bootstrap seed with a referral and the
// referred-to server with raw, satisfying whoisQuery's post-referral invariant.
func stubWhoisReferralChain(t *testing.T, raw string, err error) *int {
	t.Helper()
	calls := 0
	stubWhoisRawFn(t, func(_ context.Context, _, server string) (string, error) {
		calls++
		if server == defaultServer {
			return "refer: whois.registry.test\n", nil
		}
		if err != nil {
			return "", err
		}
		return raw, nil
	})
	return &calls
}

func recordMethods(t *testing.T, findings []plugins.Finding) []string {
	t.Helper()
	var out []string
	for _, f := range findings {
		if f.Type != plugins.FindingWhoisRecord {
			continue
		}
		method, ok := f.Data["method"].(string)
		require.True(t, ok, "record finding must carry a string method")
		out = append(out, method)
	}
	return out
}

func preseedValues(findings []plugins.Finding) []string {
	var out []string
	for _, f := range findings {
		if f.Type == plugins.FindingPreseed {
			out = append(out, f.Value)
		}
	}
	return out
}

func TestWhoisCascade_StopsAtRDAP(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	stubWhoisRawFn(t, func(_ context.Context, _, _ string) (string, error) {
		assert.Fail(t, "TCP/43 must not be queried once RDAP satisfied the predicate")
		return "", errors.New("unexpected call")
	})

	findings, err := (&WhoisPlugin{rdap: &stubRDAPSource{raw: fullWhoisRecord}}).
		Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Equal(t, []string{whoisMethodRDAP}, recordMethods(t, findings))
	assert.Contains(t, preseedValues(findings), "admin@acme.com")
}

func TestWhoisCascade_FallsThroughToTCP43(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	stubWhoisReferralChain(t, fullWhoisRecord, nil)

	rdapStub := failingRDAP()
	findings, err := (&WhoisPlugin{rdap: rdapStub}).
		Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Equal(t, 1, rdapStub.calls)
	assert.Equal(t, []string{whoisMethodTCP43}, recordMethods(t, findings))
	assert.Contains(t, preseedValues(findings), "admin@acme.com")
}

// An organization-only record is what a registry artifact looks like, so it
// must not stop the cascade — every answering source is still emitted, in order.
func TestWhoisCascade_OrgOnlyRecordDoesNotShortCircuit(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	stubWhoisReferralChain(t, fullWhoisRecord, nil)

	findings, err := (&WhoisPlugin{rdap: &stubRDAPSource{raw: orgOnlyWhoisRecord}}).
		Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Equal(t, []string{whoisMethodRDAP, whoisMethodTCP43}, recordMethods(t, findings))
	assert.Contains(t, preseedValues(findings), "John Doe", "preseeds come from the accepted record")
}

// whoxyTestServer answers the live and history endpoints, recording hits.
func whoxyTestServer(t *testing.T, live, history string) (*whoxyWhoisClient, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		switch {
		case r.URL.Query().Get("whois") != "":
			fmt.Fprint(w, live)
		case r.URL.Query().Get("history") != "":
			fmt.Fprint(w, history)
		default:
			http.Error(w, "unknown endpoint", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return &whoxyWhoisClient{client: client.New(), baseURL: srv.URL}, &hits
}

func TestWhoisCascade_FallsThroughToWhoxyAndEmitsHistory(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "secret-key")
	stubWhoisReferralChain(t, "", errors.New("dial tcp: connection refused"))
	stubWhoisHopBackoff(t, time.Millisecond)

	whoxy, _ := whoxyTestServer(t,
		fmt.Sprintf(`{"status":1,"raw_whois":%q}`, fullWhoisRecord),
		`{"status":1,"total_records_found":2,"whois_records":[{"domain_name":"example.com"}]}`,
	)

	findings, err := (&WhoisPlugin{rdap: failingRDAP(), whoxy: whoxy}).
		Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Equal(t, []string{whoisMethodWhoxy}, recordMethods(t, findings))
	assert.Contains(t, preseedValues(findings), "admin@acme.com")

	var history []plugins.Finding
	for _, f := range findings {
		if f.Type == plugins.FindingWhoisHistory {
			history = append(history, f)
		}
	}
	require.Len(t, history, 1)
	assert.Equal(t, whoisMethodWhoxy, history[0].Data["method"])
	raw, ok := history[0].Data["history"].(string)
	require.True(t, ok, "history must be carried verbatim as a JSON string")
	assert.JSONEq(t, `[{"domain_name":"example.com"}]`, raw)
}

func TestWhoisCascade_WhoxySkippedWithoutAPIKey(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	stubWhoisReferralChain(t, orgOnlyWhoisRecord, nil)

	whoxy, hits := whoxyTestServer(t, `{"status":1,"raw_whois":"x"}`, `{"status":1}`)

	findings, err := (&WhoisPlugin{rdap: failingRDAP(), whoxy: whoxy}).
		Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Equal(t, []string{whoisMethodTCP43}, recordMethods(t, findings))
	assert.Zero(t, atomic.LoadInt32(hits), "a key-less run must not spend Whoxy credits")
}

func TestWhoisCascade_HistoryFailureDoesNotFailRun(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "secret-key")
	stubWhoisReferralChain(t, "", errors.New("dial tcp: connection refused"))
	stubWhoisHopBackoff(t, time.Millisecond)

	whoxy, _ := whoxyTestServer(t,
		fmt.Sprintf(`{"status":1,"raw_whois":%q}`, fullWhoisRecord),
		`{"status":0,"status_reason":"No historic records found"}`,
	)

	findings, err := (&WhoisPlugin{rdap: failingRDAP(), whoxy: whoxy}).
		Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Equal(t, []string{whoisMethodWhoxy}, recordMethods(t, findings))
	for _, f := range findings {
		assert.NotEqual(t, plugins.FindingWhoisHistory, f.Type)
	}
}

func TestWhoisCascade_UnregisteredVerdict(t *testing.T) {
	tests := []struct {
		name       string
		rdapErr    error
		tcp43Raw   string
		tcp43Err   error
		wantMethod string
	}{
		{
			name:       "rdap reports object does not exist",
			rdapErr:    &rdap.ClientError{Type: rdap.ObjectDoesNotExist, Text: "no such domain"},
			tcp43Err:   errors.New("dial tcp: connection refused"),
			wantMethod: whoisMethodRDAP,
		},
		{
			name:       "registry answers no match",
			rdapErr:    errors.New("rdap: no working servers"),
			tcp43Raw:   notFoundWhoisRecord,
			wantMethod: whoisMethodTCP43,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("WHOXY_API_KEY", "")
			stubWhoisReferralChain(t, tt.tcp43Raw, tt.tcp43Err)
			stubWhoisHopBackoff(t, time.Millisecond)

			findings, err := (&WhoisPlugin{rdap: &stubRDAPSource{err: tt.rdapErr}}).
				Run(context.Background(), plugins.Input{Domain: "example.com"})

			require.NoError(t, err, "an unregistered domain is a result, not a failure")
			require.Len(t, findings, 1)
			assert.Equal(t, plugins.FindingWhoisRecord, findings[0].Type)
			assert.Equal(t, tt.wantMethod, findings[0].Data["method"])
			assert.Equal(t, true, findings[0].Data["unregistered"])
			assert.NotContains(t, findings[0].Data, "raw")
		})
	}
}

func TestWhoisCascade_AllSourcesFailReturnsError(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	stubWhoisReferralChain(t, "", errors.New("dial tcp: connection refused"))
	stubWhoisHopBackoff(t, time.Millisecond)

	findings, err := (&WhoisPlugin{rdap: failingRDAP()}).
		Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.Error(t, err)
	assert.Empty(t, findings)
}

// The Whoxy API key travels in a query parameter, and Go renders a transport
// failure as `Get "<full url>": <cause>`. The consumer surfaces this error to
// tenant users, so it must never carry the key.
func TestWhoxyWhois_ErrorNeverLeaksAPIKey(t *testing.T) {
	const apiKey = "s3cr3t-whoxy-key"
	t.Setenv("WHOXY_API_KEY", apiKey)

	stubWhoisReferralChain(t, "", errors.New("dial tcp: connection refused"))
	stubWhoisHopBackoff(t, time.Millisecond)

	// An unparseable base makes http.NewRequestWithContext fail on a URL that
	// already carries the key — the shortest path to a key-bearing raw error.
	c := &whoxyWhoisClient{client: client.New(), baseURL: "://invalid"}

	_, recErr := c.record(context.Background(), "example.com")
	require.Error(t, recErr)
	assert.NotContains(t, recErr.Error(), apiKey)

	_, histErr := c.history(context.Background(), "example.com")
	require.Error(t, histErr)
	assert.NotContains(t, histErr.Error(), apiKey)

	findings, runErr := (&WhoisPlugin{rdap: failingRDAP(), whoxy: c}).
		Run(context.Background(), plugins.Input{Domain: "example.com"})
	require.Error(t, runErr)
	assert.NotContains(t, runErr.Error(), apiKey)
	assert.Empty(t, findings)
}

func TestWhoisHop_RetriesTransientFailure(t *testing.T) {
	stubWhoisHopBackoff(t, time.Millisecond)

	calls := 0
	stubWhoisRawFn(t, func(_ context.Context, _, _ string) (string, error) {
		calls++
		if calls < whoisHopAttempts {
			return "", errors.New("dial tcp: connection reset by peer")
		}
		return fullWhoisRecord, nil
	})

	raw, err := whoisHop(context.Background(), "example.com", "whois.registry.test")

	require.NoError(t, err)
	assert.Equal(t, fullWhoisRecord, raw)
	assert.Equal(t, whoisHopAttempts, calls)
}

func TestWhoisHop_BailsOnContextCancellation(t *testing.T) {
	stubWhoisHopBackoff(t, time.Hour) // a backoff the ctx must cut short

	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	stubWhoisRawFn(t, func(_ context.Context, _, _ string) (string, error) {
		calls++
		cancel()
		return "", errors.New("dial tcp: connection refused")
	})

	_, err := whoisHop(ctx, "example.com", "whois.registry.test")

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, calls, "a cancelled ctx must not fund a second attempt")
}

func TestWhoisPlugin_RecordFindingCarriesRawText(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	stubWhoisRawFn(t, func(_ context.Context, _, _ string) (string, error) {
		assert.Fail(t, "TCP/43 must not be queried")
		return "", errors.New("unexpected call")
	})

	findings, err := (&WhoisPlugin{rdap: &stubRDAPSource{raw: fullWhoisRecord}}).
		Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	require.NotEmpty(t, findings)
	raw, ok := findings[0].Data["raw"].(string)
	require.True(t, ok)
	assert.True(t, strings.Contains(raw, "Acme Corp"))
	assert.Equal(t, "example.com", findings[0].Value)
}

func findingsOfType(findings []plugins.Finding, typ plugins.FindingType) []plugins.Finding {
	var out []plugins.Finding
	for _, f := range findings {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

func assertDataSurvivesJSONRoundTrip(t *testing.T, findings []plugins.Finding) {
	t.Helper()

	blob, err := json.Marshal(findings)
	require.NoError(t, err, "the consumer memoizes the finding slice as JSON")

	var got []plugins.Finding
	require.NoError(t, json.Unmarshal(blob, &got), "the consumer reads the memo back as []plugins.Finding")
	require.Len(t, got, len(findings))

	for i, before := range findings {
		after := got[i]
		assert.Equal(t, before.Type, after.Type)
		assert.Len(t, after.Data, len(before.Data),
			"finding %d (%s): no Data key may be lost across the cache", i, before.Type)
		for key, want := range before.Data {
			require.Contains(t, after.Data, key,
				"finding %d (%s): Data[%q] was lost across the cache", i, before.Type, key)
			assert.IsType(t, want, after.Data[key],
				"finding %d (%s): Data[%q] changed Go type across the cache", i, before.Type, key)
			assert.Equal(t, want, after.Data[key],
				"finding %d (%s): Data[%q] changed value across the cache", i, before.Type, key)
		}
	}
}

func TestWhoisCascade_FindingDataSurvivesJSONRoundTrip(t *testing.T) {
	t.Run("record, preseed and history findings", func(t *testing.T) {
		t.Setenv("WHOXY_API_KEY", "secret-key")
		stubWhoisReferralChain(t, fullWhoisRecord, nil)
		stubWhoisHopBackoff(t, time.Millisecond)

		whoxy, _ := whoxyTestServer(t,
			fmt.Sprintf(`{"status":1,"raw_whois":%q}`, fullWhoisRecord),
			`{"status":1,"total_records_found":2,"whois_records":[{"domain_name":"example.com"}]}`,
		)

		findings, err := (&WhoisPlugin{rdap: &stubRDAPSource{raw: orgOnlyWhoisRecord}, whoxy: whoxy}).
			Run(context.Background(), plugins.Input{Domain: "example.com"})

		require.NoError(t, err)
		require.NotEmpty(t, findingsOfType(findings, plugins.FindingWhoisRecord),
			"the round-trip check is vacuous without a record finding")
		require.NotEmpty(t, findingsOfType(findings, plugins.FindingPreseed),
			"the round-trip check is vacuous without a preseed finding")
		require.Len(t, findingsOfType(findings, plugins.FindingWhoisHistory), 1,
			"the round-trip check is vacuous without a history finding")

		assertDataSurvivesJSONRoundTrip(t, findings)
	})

	t.Run("unregistered verdict", func(t *testing.T) {
		t.Setenv("WHOXY_API_KEY", "")
		stubWhoisReferralChain(t, notFoundWhoisRecord, nil)
		stubWhoisHopBackoff(t, time.Millisecond)

		findings, err := (&WhoisPlugin{rdap: failingRDAP()}).
			Run(context.Background(), plugins.Input{Domain: "example.com"})

		require.NoError(t, err)
		require.Len(t, findings, 1)
		require.Equal(t, true, findings[0].Data["unregistered"],
			"the round-trip check is vacuous without the unregistered verdict")

		assertDataSurvivesJSONRoundTrip(t, findings)
	})
}

func TestNewWhoisPlugin_UsesInjectedRDAPLookup(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	stubWhoisRawFn(t, func(_ context.Context, _, _ string) (string, error) {
		assert.Fail(t, "TCP/43 must not run when the injected RDAP lookup answers")
		return "", errors.New("unexpected call")
	})

	var domains []string
	p := NewWhoisPlugin(WithRDAPLookup(func(_ context.Context, domain string) (string, error) {
		domains = append(domains, domain)
		return fullWhoisRecord, nil
	}))

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Equal(t, []string{"example.com"}, domains)
	assert.Equal(t, []string{whoisMethodRDAP}, recordMethods(t, findings))
}

func TestNewWhoisPlugin_UsesInjectedWhoisRaw(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "")
	stubWhoisHopBackoff(t, time.Millisecond)
	stubWhoisRawFn(t, func(_ context.Context, _, _ string) (string, error) {
		assert.Fail(t, "the package-default transport must not be consulted when a transport is injected")
		return "", errors.New("unexpected call")
	})

	var servers []string
	p := NewWhoisPlugin(WithWhoisRaw(func(_ context.Context, _, server string) (string, error) {
		servers = append(servers, server)
		if server == defaultServer {
			return "refer: whois.registry.test\n", nil
		}
		return injectedWhoisRecord, nil
	}))
	p.rdap = failingRDAP() // force the cascade past RDAP onto TCP/43

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	assert.Equal(t, []string{defaultServer, "whois.registry.test"}, servers,
		"the injected transport must serve the referral hop too, not only the bootstrap seed")
	assert.Equal(t, []string{whoisMethodTCP43}, recordMethods(t, findings))

	records := findingsOfType(findings, plugins.FindingWhoisRecord)
	require.Len(t, records, 1)
	raw, ok := records[0].Data["raw"].(string)
	require.True(t, ok)
	assert.Contains(t, raw, "Sentinel Injected Corp", "the injected transport is what answered")
	assert.Contains(t, preseedValues(findings), "sentinel@injected.test")
}
