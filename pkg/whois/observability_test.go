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
	return recordsWithMessage(records, "whois lookup complete")
}

func recordsWithMessage(records []map[string]any, message string) []map[string]any {
	var out []map[string]any
	for _, r := range records {
		if r["msg"] == message {
			out = append(out, r)
		}
	}
	return out
}

func TestPublicFieldCount_ExcludesPrivacyInvalidEmailAndProvenance(t *testing.T) {
	result := DomainResult{
		Domain: "example.com", NameServers: []string{"ns2.example.com", "ns1.example.com"},
		Status: []string{"active", "client transfer prohibited"}, Sources: []string{ProviderWhoxy},
		Registrant: Contact{Name: "Registration Private", Email: "not an email"},
		Tech:       Contact{Email: "tech@example.com"},
	}
	result.Normalize()

	assert.Equal(t, 3, publicFieldCount(result))
	assert.Equal(t, "tech@example.com", result.ContactEmail)
	assert.Equal(t, []string{"ns2.example.com", "ns1.example.com"}, result.NameServers)
}

func TestLookupContribution_CountsOnlyFieldsAddedToMergedRecord(t *testing.T) {
	whoxy := &fakeWHOISClient{name: ProviderWhoxy, result: DomainResult{
		Admin: Contact{Name: "Whoxy Admin"},
	}}
	freaks := &fakeWHOISClient{name: ProviderWhoisFreaks, result: DomainResult{
		Admin: Contact{Name: "Different Admin"},
	}}
	xml := &fakeWHOISClient{name: ProviderWhoisXML, result: DomainResult{
		Created: "2021-09-19", Expiration: "2026-09-19",
		Tech: Contact{Name: "XML Tech", Phone: "+1.2125550100", Country: "US"},
	}}

	records := captureLogs(t, slog.LevelInfo, func() {
		result, err := withCommercialLookups(whoxy, freaks, xml).LookupDomain(t.Context(), "example.com")
		require.NoError(t, err)
		assert.Equal(t, "Whoxy Admin", result.Admin.Name)
	})

	contributions := recordsWithMessage(records, "whois lookup contribution")
	require.Len(t, contributions, 5)
	for i, provider := range []string{ProviderWhoxy, ProviderWhoisFreaks, ProviderWhoisXML} {
		assert.Equal(t, provider, contributions[i+2]["resolver"])
		assert.Equal(t, "example.com", contributions[i+2]["domain"])
		assert.Len(t, contributions[i+2], 6)
	}
	assert.EqualValues(t, 1, contributions[2]["added_fields"])
	assert.EqualValues(t, 0, contributions[3]["added_fields"])
	assert.EqualValues(t, 5, contributions[4]["added_fields"])

	encoded, err := json.Marshal(records)
	require.NoError(t, err)
	for _, value := range []string{"Whoxy Admin", "Different Admin", "XML Tech", "+1.2125550100"} {
		assert.NotContains(t, string(encoded), value)
	}
}

func TestLookupContribution_DoesNotCountErrorsOrSkippedProviders(t *testing.T) {
	freaks := failing(ProviderWhoisFreaks)
	freaks.result.Admin.Name = "Must not count a failed response"
	records := captureLogs(t, slog.LevelInfo, func() {
		_, err := withCommercialLookups(unkeyed(ProviderWhoxy), freaks, answering(ProviderWhoisXML)).LookupDomain(t.Context(), "example.com")
		require.NoError(t, err)
	})
	contributions := recordsWithMessage(records, "whois lookup contribution")
	require.Len(t, contributions, 3)
	assert.Equal(t, ProviderWhoisXML, contributions[2]["resolver"])
	assert.EqualValues(t, 1, contributions[2]["added_fields"])
	outcomes := lookupRecords(records)
	assert.Equal(t, outcomeSkipped, outcomes[2]["result"])
	assert.Equal(t, outcomeError, outcomes[3]["result"])
}

func TestLookupContribution_RespectsEarlyStopAndStaysWithinOneLookup(t *testing.T) {
	whoxy, freaks, xml := answering(ProviderWhoxy), complete(ProviderWhoisFreaks), complete(ProviderWhoisXML)
	client := withCommercialLookups(whoxy, freaks, xml)
	for range 2 {
		records := captureLogs(t, slog.LevelInfo, func() {
			_, err := client.LookupDomain(t.Context(), "example.com")
			require.NoError(t, err)
		})
		contributions := recordsWithMessage(records, "whois lookup contribution")
		require.Len(t, contributions, 4)
		assert.EqualValues(t, 1, contributions[2]["added_fields"])
		assert.EqualValues(t, 4, contributions[3]["added_fields"])
	}
	assert.Zero(t, xml.calls)
}

func TestLookupContribution_RedactionToPublicAndNoOp(t *testing.T) {
	whoxy := &fakeWHOISClient{name: ProviderWhoxy, result: DomainResult{
		Admin: Contact{Name: "Registration Private"},
	}}
	freaks := &fakeWHOISClient{name: ProviderWhoisFreaks, result: DomainResult{
		Admin: Contact{Name: "Public Contact"}, Tech: Contact{Name: "Public Contact"},
	}}
	xml := &fakeWHOISClient{name: ProviderWhoisXML, result: freaks.result}
	records := captureLogs(t, slog.LevelInfo, func() {
		_, err := withCommercialLookups(whoxy, freaks, xml).LookupDomain(t.Context(), "example.com")
		require.NoError(t, err)
	})
	contributions := recordsWithMessage(records, "whois lookup contribution")
	require.Len(t, contributions, 5)
	assert.EqualValues(t, 0, contributions[2]["added_fields"])
	assert.EqualValues(t, 2, contributions[3]["added_fields"])
	assert.EqualValues(t, 0, contributions[4]["added_fields"])
}

// TestLogLookup_ClassifiesEveryOutcome is the contract the provider success
// rate is built on. Four outcomes, not two: "the provider is broken" and "the
// registry has nothing to give anyone" must not aggregate into one number, or
// the metric cannot answer the question it exists for — which provider deserves
// to go first.
func TestLogLookup_ClassifiesEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolver *fakeWHOISClient
		want     string
	}{
		{"a record is found", complete(ProviderWhoxy), outcomeFound},
		{"an unregistered verdict is an answer", &fakeWHOISClient{
			name:   ProviderWhoxy,
			result: DomainResult{Domain: "gone.example", Unregistered: true},
		}, outcomeFound},
		{"acknowledged with no record", silent(ProviderWhoxy), outcomeEmpty},
		{"a failed request", failing(ProviderWhoxy), outcomeError},
		{"no credential configured", unkeyed(ProviderWhoxy), outcomeSkipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := captureLogs(t, slog.LevelInfo, func() {
				result, err := tc.resolver.LookupDomain(context.Background(), "example.com")
				logLookup(tc.resolver.Name(), "example.com", time.Now(), result, err)
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
		logLookup(ProviderWhoxy, "example.com", time.Now(), result, nil)
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

	whoxy := NewWhoxyClient(whoxySrv.Client(), "key")
	whoxy.baseURL = whoxySrv.URL
	freaks := NewWhoisFreaksClient(freaksSrv.Client(), "key")
	freaks.baseURL = freaksSrv.URL

	t.Setenv("WHOISXML_API_KEY", "")
	unkeyedXML := NewWhoisXMLClient(nil, "")

	records := captureLogs(t, slog.LevelInfo, func() {
		_, err := withCommercialLookups(whoxy, freaks, unkeyedXML).LookupDomain(context.Background(), "example.com")
		require.Error(t, err, "no leg had a record")
	})

	byResolver := map[string]string{}
	for _, r := range lookupRecords(records) {
		name, _ := r["resolver"].(string)
		outcome, _ := r["result"].(string)
		byResolver[name] = outcome
	}

	assert.Equal(t, map[string]string{
		SourceRDAP:          outcomeEmpty,
		SourceTCP43:         outcomeEmpty,
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
		var result DomainResult
		err := errors.New(`Get "https://api.whoxy.com/?key=` + key + `&whois=example.com": dial error`)
		logLookup(ProviderWhoxy, "example.com", time.Now(), result, err)
	})

	require.Len(t, lookupRecords(records), 1)
	for _, record := range records {
		encoded, marshalErr := json.Marshal(record)
		require.NoError(t, marshalErr)
		assert.NotContains(t, string(encoded), key,
			"the metric must not carry the error text that embeds the credential")
	}
}
