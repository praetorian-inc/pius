package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real purchase response for exact company="Praetorian", searchType=current.
// nextPageSearchAfter is JSON null, and domainsList is the object form because
// includeAuditDates is always sent as true.
const whoisXMLAPIRealPurchase = `{
 "nextPageSearchAfter": null,
 "domainsCount": 2,
 "domainsList": [
  {"domainName":"praetorianlabs.dev","audit":{"createdDate":"2025-03-11T00:00:00+00:00","updatedDate":"2025-03-11T00:00:00+00:00"}},
  {"domainName":"adr-secure.org","audit":{"createdDate":"2017-09-08T00:00:00+00:00","updatedDate":"2017-09-08T00:00:00+00:00"}}
 ]
}`

func newTestWhoisXMLAPI(t *testing.T, resolver registrantResolver, handler http.HandlerFunc) *WhoisXMLAPIReverseWhoisPlugin {
	t.Helper()
	t.Setenv("WHOISXMLAPI_API_KEY", "test-token")
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &WhoisXMLAPIReverseWhoisPlugin{
		client:   client.New(),
		baseURL:  server.URL,
		resolver: resolver,
	}
}

// decodeReverseRequest reads the POSTed body so assertions can inspect what we sent.
func decodeReverseRequest(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	return body
}

func TestWhoisXMLAPIReverseWhois_Metadata(t *testing.T) {
	p, ok := plugins.Get("whoisxmlapi-reverse-whois")
	require.True(t, ok, "whoisxmlapi-reverse-whois plugin must be registered")

	assert.Equal(t, "whoisxmlapi-reverse-whois", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModePassive, p.Mode())
	assert.Contains(t, p.Description(), "WHOISXMLAPI_API_KEY")
}

func TestWhoisXMLAPIReverseWhois_Accepts(t *testing.T) {
	t.Setenv("WHOISXMLAPI_API_KEY", "test-token")
	p := &WhoisXMLAPIReverseWhoisPlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.True(t, p.Accepts(plugins.Input{Email: "admin@acme.com"}))
	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

func TestWhoisXMLAPIReverseWhois_Accepts_RejectsWithoutKey(t *testing.T) {
	t.Setenv("WHOISXMLAPI_API_KEY", "")
	p := &WhoisXMLAPIReverseWhoisPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

func TestWhoisXMLAPIReverseWhois_Run_ParsesRealPayload(t *testing.T) {
	stub := &stubResolver{byDomain: map[string]registrantResult{
		"praetorianlabs.dev": org("Praetorian"),
	}}

	var modes []string
	p := newTestWhoisXMLAPI(t, stub, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		// Header auth keeps the key out of the URL entirely.
		assert.Equal(t, "test-token", r.Header.Get("X-Authentication-Token"))

		body := decodeReverseRequest(t, r)
		modes = append(modes, body["mode"].(string))
		// The precision lever: historic would return 164 instead of 12.
		assert.Equal(t, "current", body["searchType"])
		// Always true, so domainsList has one shape rather than two.
		assert.Equal(t, true, body["includeAuditDates"])

		terms := body["advancedSearchTerms"].([]any)
		require.Len(t, terms, 1)
		term := terms[0].(map[string]any)
		assert.Equal(t, "RegistrantContact.Organization", term["field"])
		assert.Equal(t, "Praetorian", term["term"])
		assert.Equal(t, true, term["exactMatch"])

		if body["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":2}`))
			return
		}
		_, _ = w.Write([]byte(whoisXMLAPIRealPurchase))
	})

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Praetorian"})
	require.NoError(t, err)

	// Free preview precedes the paid purchase.
	assert.Equal(t, []string{"preview", "purchase"}, modes)

	require.Len(t, findings, 2)
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "whoisxmlapi-reverse-whois", f.Source)
		assert.Equal(t, "Praetorian", f.Data["org"])
	}

	// verifyCandidates ranks: the corroborated candidate outscores the one whose
	// registrant could not be resolved. Neither is dropped.
	byDomain := map[string]float64{}
	for _, f := range findings {
		byDomain[f.Value] = f.Data["confidence"].(float64)
	}
	assert.InDelta(t, confReverseWhoisCorroborated, byDomain["praetorianlabs.dev"], 0.001)
	assert.InDelta(t, confReverseWhoisUnverified, byDomain["adr-secure.org"], 0.001)
}

// preview is free, so a pivot matching nothing must not spend a credit.
func TestWhoisXMLAPIReverseWhois_Run_ZeroPreviewSkipsPurchase(t *testing.T) {
	var modes []string
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		modes = append(modes, decodeReverseRequest(t, r)["mode"].(string))
		_, _ = w.Write([]byte(`{"domainsCount":0}`))
	})

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Nothing Matches Ltd"})
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, []string{"preview"}, modes, "a zero-count preview must not be followed by a purchase")
}

// Email-mode uses the union Email field, which covers registrant, admin,
// billing and tech addresses in one query.
func TestWhoisXMLAPIReverseWhois_Run_EmailUsesUnionField(t *testing.T) {
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		term := decodeReverseRequest(t, r)["advancedSearchTerms"].([]any)[0].(map[string]any)
		assert.Equal(t, "Email", term["field"])
		assert.Equal(t, "admin@acme.com", term["term"])
		// exactMatch is unsupported for email fields and treated as true anyway,
		// so it must not be sent as an explicit false.
		assert.NotContains(t, term, "exactMatch")
		_, _ = w.Write([]byte(`{"domainsCount":0}`))
	})

	_, err := p.Run(context.Background(), plugins.Input{Email: "admin@acme.com"})
	require.NoError(t, err)
}

// Email-mode has no org to corroborate against, so verifyCandidates must
// short-circuit without any registrant lookups.
func TestWhoisXMLAPIReverseWhois_Run_EmailModeSkipsVerification(t *testing.T) {
	stub := &stubResolver{}
	p := newTestWhoisXMLAPI(t, stub, func(w http.ResponseWriter, r *http.Request) {
		if decodeReverseRequest(t, r)["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"domainsCount":1,"domainsList":[{"domainName":"acme.com","audit":{"updatedDate":"2025-03-11T00:00:00+00:00"}}]}`))
	})

	findings, err := p.Run(context.Background(), plugins.Input{Email: "admin@acme.com"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.False(t, stub.queried("acme.com"), "email-mode must not trigger registrant lookups")
	assert.InDelta(t, confReverseWhoisUnverified, findings[0].Data["confidence"].(float64), 0.001)
}

// nextPageSearchAfter is JSON null on the last page; it must decode to
// no-next-page rather than a literal "null" cursor that would loop.
func TestWhoisXMLAPIReverseWhois_Run_NullCursorTerminatesPaging(t *testing.T) {
	var purchases int
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		if decodeReverseRequest(t, r)["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":1}`))
			return
		}
		purchases++
		_, _ = w.Write([]byte(whoisXMLAPIRealPurchase))
	})

	_, err := p.Run(context.Background(), plugins.Input{OrgName: "Praetorian"})
	require.NoError(t, err)
	assert.Equal(t, 1, purchases)
}

func TestWhoisXMLAPIReverseWhois_Run_FollowsCursorAndDedupes(t *testing.T) {
	var cursors []string
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		body := decodeReverseRequest(t, r)
		if body["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":3}`))
			return
		}
		cursor, _ := body["searchAfter"].(string)
		cursors = append(cursors, cursor)
		if cursor == "" {
			_, _ = w.Write([]byte(`{"nextPageSearchAfter":"cursor-def","domainsCount":3,` +
				`"domainsList":[{"domainName":"a.com","audit":{"updatedDate":"2025-03-11T00:00:00+00:00"}}]}`))
			return
		}
		// Repeats a.com to prove dedup, and adds b.com.
		_, _ = w.Write([]byte(`{"nextPageSearchAfter":null,"domainsCount":3,` +
			`"domainsList":[{"domainName":"a.com","audit":{"updatedDate":"2025-03-11T00:00:00+00:00"}},` +
			`{"domainName":"b.com","audit":{"updatedDate":"2025-03-11T00:00:00+00:00"}}]}`))
	})

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.NoError(t, err)

	assert.Equal(t, []string{"", "cursor-def"}, cursors)
	values := []string{findings[0].Value, findings[1].Value}
	assert.ElementsMatch(t, []string{"a.com", "b.com"}, values)
	assert.Len(t, findings, 2, "a domain repeated across pages must be emitted once")
}

// A stale record must not even trigger a verification lookup.
func TestWhoisXMLAPIReverseWhois_Run_StaleRecordFilteredBeforeVerification(t *testing.T) {
	stale := time.Now().AddDate(-12, 0, 0).Format(time.RFC3339)
	stub := &stubResolver{}
	p := newTestWhoisXMLAPI(t, stub, func(w http.ResponseWriter, r *http.Request) {
		if decodeReverseRequest(t, r)["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":2}`))
			return
		}
		_, _ = w.Write([]byte(fmt.Sprintf(
			`{"domainsCount":2,"domainsList":[{"domainName":"fresh.com","audit":{"updatedDate":%q}},`+
				`{"domainName":"ancient.com","audit":{"updatedDate":%q}}]}`,
			time.Now().Format(time.RFC3339), stale)))
	})

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "fresh.com", findings[0].Value)
	assert.False(t, stub.queried("ancient.com"), "stale candidates must not trigger a lookup")
}

// Audit dates only exist because includeAuditDates is sent as true. If the
// vendor stopped returning them, treating that as stale would drop every
// candidate and read as "this pivot owns nothing".
func TestWhoisXMLAPIRecordStale(t *testing.T) {
	assert.False(t, whoisXMLAPIRecordStale(time.Now().Format(time.RFC3339)))
	assert.True(t, whoisXMLAPIRecordStale(time.Now().AddDate(-11, 0, 0).Format(time.RFC3339)))
	assert.False(t, whoisXMLAPIRecordStale(""), "absent audit date must not be treated as stale")
	assert.False(t, whoisXMLAPIRecordStale("not-a-date"), "unparseable audit date must not be treated as stale")
}

func TestDecodeWhoisXMLAPIHits_NullAndAbsentAreNotErrors(t *testing.T) {
	hits, err := decodeWhoisXMLAPIHits(nil)
	require.NoError(t, err)
	assert.Empty(t, hits)

	hits, err = decodeWhoisXMLAPIHits(json.RawMessage("null"))
	require.NoError(t, err)
	assert.Empty(t, hits)

	_, err = decodeWhoisXMLAPIHits(json.RawMessage(`{"not":"a list"}`))
	require.Error(t, err)
}

func TestWhoisXMLAPIReverseWhois_Run_PreviewFailureIsAnError(t *testing.T) {
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "preview")
}

// The request body echoes the apiKey field, so errors must not wrap the response.
func TestWhoisXMLAPIReverseWhois_Run_ErrorNeverContainsTheAPIKey(t *testing.T) {
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"apiKey":"test-token"}`))
	})

	_, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "test-token")
}

func TestWhoisXMLAPIReverseWhois_Run_HonoursContextCancellation(t *testing.T) {
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"domainsCount":1}`))
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Run(ctx, plugins.Input{OrgName: "Acme"})
	require.Error(t, err)
}
