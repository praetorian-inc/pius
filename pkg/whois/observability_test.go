package whois

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLogs installs a JSON slog handler for the duration of the test and
// returns the records it collected. Asserting on real emitted records rather
// than on a hand-rolled interface is the point: the CloudWatch queries that
// compute per-provider success rate parse these exact field names, so a rename
// is a breaking change and belongs in a test.
func captureLogs(t *testing.T, level slog.Level, fn func()) []map[string]any {
	t.Helper()

	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	fn()

	var records []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal(line, &record))
		records = append(records, record)
	}
	return records
}

// lookupRecords keeps only the one-per-resolver completion records, so an
// unrelated debug line cannot make an assertion pass or fail by accident.
func lookupRecords(records []map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range records {
		if r["msg"] == "whois lookup complete" {
			out = append(out, r)
		}
	}
	return out
}

// TestLogLookup_ClassifiesEveryOutcome is the contract the provider success
// rate is built on. Four outcomes, not two: "the provider is broken" and "the
// registry has nothing to give anyone" must not aggregate into one number, or
// the metric cannot answer the question it exists for — which provider deserves
// to go first.
func TestLogLookup_ClassifiesEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolver *fakeResolver
		want     string
	}{
		{"a record is found", complete(ProviderWhoxy), outcomeFound},
		{"an unregistered verdict is an answer", &fakeResolver{
			name:   ProviderWhoxy,
			result: Result{Domain: "gone.example", Unregistered: true},
		}, outcomeFound},
		{"acknowledged with no record", silent(ProviderWhoxy), outcomeEmpty},
		{"a failed request", failing(ProviderWhoxy), outcomeError},
		{"no credential configured", unkeyed(ProviderWhoxy), outcomeSkipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := captureLogs(t, slog.LevelInfo, func() {
				result, err := tc.resolver.Lookup(context.Background(), "example.com")
				logLookup(tc.resolver.Name(), "example.com", time.Now(), &result, &err)
			})

			require.Len(t, lookupRecords(records), 1, "exactly one record per resolver call")
			record := lookupRecords(records)[0]

			assert.Equal(t, tc.want, record["result"])
			assert.Equal(t, ProviderWhoxy, record["resolver"])
			assert.Equal(t, "example.com", record["domain"])
			assert.Contains(t, record, "duration_ms")
		})
	}
}

// TestLogLookup_EmittedAtInfo: the metric is useless if it is filtered out in
// production, where Debug is off.
func TestLogLookup_EmittedAtInfo(t *testing.T) {
	records := captureLogs(t, slog.LevelInfo, func() {
		result := completeResult(ProviderWhoxy)
		var err error
		logLookup(ProviderWhoxy, "example.com", time.Now(), &result, &err)
	})

	require.Len(t, lookupRecords(records), 1)
	assert.Equal(t, "INFO", lookupRecords(records)[0]["level"])
}

// TestResolvers_EmitOneRecordEachThroughLookup wires the real resolvers up to
// httptest servers and walks a whole cascade, proving the instrumentation is
// actually reached on the real code path — one record per leg consulted, with
// the leg's own name on it.
func TestResolvers_EmitOneRecordEachThroughLookup(t *testing.T) {
	whoxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Answers, but holds nothing for this domain.
		_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "raw_whois": ""})
	}))
	defer whoxySrv.Close()

	freaksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer freaksSrv.Close()

	whoxy := NewWhoxyResolver(whoxySrv.Client(), "key")
	whoxy.baseURL = whoxySrv.URL
	freaks := NewWhoisFreaksResolver(freaksSrv.Client(), "key")
	freaks.baseURL = freaksSrv.URL

	t.Setenv("WHOISXML_API_KEY", "")
	unkeyedXML := NewWhoisXMLResolver(nil, "")

	records := captureLogs(t, slog.LevelInfo, func() {
		_, err := Lookup(context.Background(), "example.com", route(whoxy, freaks, unkeyedXML)...)
		require.Error(t, err, "no leg had a record")
	})

	byResolver := map[string]string{}
	for _, r := range lookupRecords(records) {
		name, _ := r["resolver"].(string)
		outcome, _ := r["result"].(string)
		byResolver[name] = outcome
	}

	assert.Equal(t, map[string]string{
		ProviderWhoxy:       outcomeEmpty,
		ProviderWhoisFreaks: outcomeError,
		ProviderWhoisXML:    outcomeSkipped,
	}, byResolver, "every consulted leg reports its own outcome exactly once")
}

// TestLogLookup_NeverLogsTheAPIKey: both Whoxy and WhoisXML authenticate with a
// query parameter, so an error rendered by net/http carries the full URL and
// the key with it. The metric records the kind of failure, never its text.
func TestLogLookup_NeverLogsTheAPIKey(t *testing.T) {
	const key = "super-secret-key"

	records := captureLogs(t, slog.LevelDebug, func() {
		var result Result
		err := errors.New(`Get "https://api.whoxy.com/?key=` + key + `&whois=example.com": dial error`)
		logLookup(ProviderWhoxy, "example.com", time.Now(), &result, &err)
	})

	require.Len(t, lookupRecords(records), 1)
	for _, record := range records {
		encoded, marshalErr := json.Marshal(record)
		require.NoError(t, marshalErr)
		assert.NotContains(t, string(encoded), key,
			"the metric must not carry the error text that embeds the credential")
	}
}
