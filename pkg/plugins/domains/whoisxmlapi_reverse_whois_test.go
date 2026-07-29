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

// verifyCandidates corroborates only the first maxReverseWhoisCandidates
// entries, so freshest-first ordering decides who gets a lookup.
func TestWhoisXMLAPIReverseWhois_Run_OrdersMostRecentFirst(t *testing.T) {
	// Relative dates: absolute ones silently cross the ten-year staleness cutoff
	// as time passes and turn this into a filtering test.
	now := time.Now()
	old := now.AddDate(-9, 0, 0).Format(time.RFC3339)
	mid := now.AddDate(-4, 0, 0).Format(time.RFC3339)
	newest := now.AddDate(0, -1, 0).Format(time.RFC3339)

	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		if decodeReverseRequest(t, r)["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":4}`))
			return
		}
		// Deliberately returned oldest-first, with one undated record.
		_, _ = fmt.Fprintf(w, `{"domainsCount":4,"domainsList":[`+
			`{"domainName":"old.com","audit":{"updatedDate":%q}},`+
			`{"domainName":"undated.com","audit":{}},`+
			`{"domainName":"newest.com","audit":{"updatedDate":%q}},`+
			`{"domainName":"mid.com","audit":{"updatedDate":%q}}]}`, old, newest, mid)
	})

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.NoError(t, err)

	got := make([]string, 0, len(findings))
	for _, f := range findings {
		got = append(got, f.Value)
	}
	// Undated sorts last rather than being dropped.
	assert.Equal(t, []string{"newest.com", "mid.com", "old.com", "undated.com"}, got)
}

// Dedup keeps the freshest observation, which only holds because dedup runs
// after the sort.
func TestWhoisXMLAPIReverseWhois_Run_DedupeKeepsFreshestObservation(t *testing.T) {
	older := time.Now().AddDate(-12, 0, 0).Format(time.RFC3339)
	fresh := time.Now().Format(time.RFC3339)

	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		body := decodeReverseRequest(t, r)
		if body["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":2}`))
			return
		}
		cursor, _ := body["searchAfter"].(string)
		if cursor == "" {
			// Older copy first, so first-wins dedupe alone would keep the wrong one.
			_, _ = fmt.Fprintf(w, `{"nextPageSearchAfter":"next","domainsCount":2,`+
				`"domainsList":[{"domainName":"dup.com","audit":{"updatedDate":%q}}]}`, older)
			return
		}
		_, _ = fmt.Fprintf(w, `{"nextPageSearchAfter":null,"domainsCount":2,`+
			`"domainsList":[{"domainName":"dup.com","audit":{"updatedDate":%q}}]}`, fresh)
	})

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "dup.com", findings[0].Value)
}

// preview proved matches exist, so a first-page purchase failure must not read
// as "this org owns no domains".
func TestWhoisXMLAPIReverseWhois_Run_FirstPurchasePageFailureIsAnError(t *testing.T) {
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		if decodeReverseRequest(t, r)["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":12}`))
			return
		}
		w.WriteHeader(http.StatusPaymentRequired)
	})

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Praetorian"})
	require.Error(t, err, "a failed paid lookup must not be reported as an empty result")
	assert.Empty(t, findings)
}

// A later-page failure keeps what was already collected: partial recall beats
// discarding a successful first page.
func TestWhoisXMLAPIReverseWhois_Run_LaterPageFailureKeepsPartialResults(t *testing.T) {
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		body := decodeReverseRequest(t, r)
		if body["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":2}`))
			return
		}
		if cursor, _ := body["searchAfter"].(string); cursor == "" {
			_, _ = w.Write([]byte(`{"nextPageSearchAfter":"next","domainsCount":2,` +
				`"domainsList":[{"domainName":"first.com","audit":{"updatedDate":"2025-03-11T00:00:00+00:00"}}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "first.com", findings[0].Value)
}

// A malformed first page is as opaque to the caller as a transport failure.
func TestWhoisXMLAPIReverseWhois_Run_UndecodableFirstPageIsAnError(t *testing.T) {
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		if decodeReverseRequest(t, r)["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":3}`))
			return
		}
		_, _ = w.Write([]byte(`{"domainsCount":3,"domainsList":{"not":"a list"}}`))
	})

	_, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "domainsList")
}

const liveReversePurchase = `{
 "nextPageSearchAfter": null,
 "domainsCount": 12,
 "domainsList": [
  {"domainName":"wherewizardsstayuplate.us","audit":{"createdDate":"2026-07-24T22:00:38+00:00","updatedDate":"2026-07-24T22:00:38+00:00"}},
  {"domainName":"praetorianlabs.dev","audit":{"createdDate":"2025-03-11T11:32:06+00:00","updatedDate":"2025-03-11T11:32:06+00:00"}},
  {"domainName":"mobilesecurityframework.org","audit":{"createdDate":"2016-07-25T20:52:30+00:00","updatedDate":"2016-07-25T20:52:30+00:00"}},
  {"domainName":"mobilesecurityframework.us","audit":{"createdDate":"2016-07-24T20:45:46+00:00","updatedDate":"2016-07-24T20:45:46+00:00"}},
  {"domainName":"praetorians.biz","audit":{"createdDate":"2016-07-10T20:47:41+00:00","updatedDate":"2016-07-10T20:47:41+00:00"}},
  {"domainName":"riskmobile.org","audit":{"createdDate":"2016-06-12T21:27:34+00:00","updatedDate":"2016-06-12T21:27:34+00:00"}}
 ]
}`

// Decade-old audit dates must survive. searchType=current already restricts the
// result set to live registrations, and the audit block is WhoisXMLAPI's crawl
// recency rather than the registration's age
func TestWhoisXMLAPIReverseWhois_Run_KeepsDomainsWithOldAuditDates(t *testing.T) {
	p := newTestWhoisXMLAPI(t, &stubResolver{}, func(w http.ResponseWriter, r *http.Request) {
		if decodeReverseRequest(t, r)["mode"] == "preview" {
			_, _ = w.Write([]byte(`{"domainsCount":12}`))
			return
		}
		_, _ = w.Write([]byte(liveReversePurchase))
	})

	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Praetorian"})
	require.NoError(t, err)

	got := make([]string, 0, len(findings))
	for _, f := range findings {
		got = append(got, f.Value)
	}
	// Freshest first, and nothing dropped for age.
	assert.Equal(t, []string{
		"wherewizardsstayuplate.us",
		"praetorianlabs.dev",
		"mobilesecurityframework.org",
		"mobilesecurityframework.us",
		"praetorians.biz",
		"riskmobile.org",
	}, got)
}

func TestWhoisXMLAPIObservedAt(t *testing.T) {
	// The live audit format carries a "+00:00" offset rather than "Z".
	got := whoisXMLAPIObservedAt("2016-07-25T20:52:30+00:00")
	require.False(t, got.IsZero(), "live audit format must parse")
	assert.Equal(t, 2016, got.Year())

	assert.True(t, whoisXMLAPIObservedAt("").IsZero(), "absent audit date must parse to zero")
	assert.True(t, whoisXMLAPIObservedAt("not-a-date").IsZero(), "unparseable audit date must parse to zero")
}

func TestWhoisXMLAPIDomainList_NullAndAbsentAreNotErrors(t *testing.T) {
	var list whoisXMLAPIDomainList
	require.NoError(t, json.Unmarshal([]byte("null"), &list))
	assert.Empty(t, list)

	var resp whoisXMLAPIReverseResponse
	require.NoError(t, json.Unmarshal([]byte(`{"domainsCount":4}`), &resp))
	assert.Empty(t, resp.DomainsList, "absent in preview mode")
}

func TestWhoisXMLAPIDomainList_DecodesObjectForm(t *testing.T) {
	var list whoisXMLAPIDomainList
	require.NoError(t, json.Unmarshal(
		[]byte(`[{"domainName":"a.com","audit":{"updatedDate":"2025-03-11T00:00:00+00:00"}}]`), &list))

	require.Len(t, list, 1)
	assert.Equal(t, "a.com", list[0].DomainName)
	assert.Equal(t, "2025-03-11T00:00:00+00:00", list[0].Audit.UpdatedDate)
}

// The bare-string form is what the vendor returns when includeAuditDates is
// false. We always send true, so this is a defensive path: accepting it costs
// audit dates rather than failing the page.
func TestWhoisXMLAPIDomainList_DecodesStringForm(t *testing.T) {
	var list whoisXMLAPIDomainList
	require.NoError(t, json.Unmarshal([]byte(`["a.com","b.com"]`), &list))

	require.Len(t, list, 2)
	assert.Equal(t, "a.com", list[0].DomainName)
	assert.Empty(t, list[0].Audit.UpdatedDate)
	assert.Equal(t, "b.com", list[1].DomainName)
}

func TestWhoisXMLAPIDomainList_RejectsNeitherShape(t *testing.T) {
	var list whoisXMLAPIDomainList
	err := json.Unmarshal([]byte(`{"not":"a list"}`), &list)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "domainsList")
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
