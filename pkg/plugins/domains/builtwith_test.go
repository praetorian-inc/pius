package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltWith_Accepts_WithKeyAndAnalyticsIDs(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")
	p := &BuiltWithPlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{Meta: map[string]string{"analytics_ids": "UA-12345"}}))
}

func TestBuiltWith_Accepts_RejectsWithoutKey(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "")
	p := &BuiltWithPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{Meta: map[string]string{"analytics_ids": "UA-12345"}}))
}

func TestBuiltWith_Accepts_RejectsWithoutAnalyticsIDs(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")
	p := &BuiltWithPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.False(t, p.Accepts(plugins.Input{Meta: map[string]string{"analytics_ids": ""}}))
}

func TestBuiltWith_Metadata(t *testing.T) {
	p, ok := plugins.Get("builtwith")
	require.True(t, ok, "builtwith plugin must be registered")

	assert.Equal(t, "builtwith", p.Name())
	assert.Equal(t, 3, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModePassive, p.Mode())
	assert.Contains(t, p.Description(), "BUILTWITH_API_KEY")
}

// mockBuiltWithResponse builds a JSON response matching the real BuiltWith tag API shape:
// a top-level array of entries, each with Value and Matches fields.
func mockBuiltWithResponse(domainsByID map[string][]string) []byte {
	type matchEntry struct {
		Domain string `json:"Domain"`
	}
	type entry struct {
		Value   string       `json:"Value"`
		Matches []matchEntry `json:"Matches"`
	}

	var entries []entry
	for id, domains := range domainsByID {
		var matches []matchEntry
		for _, d := range domains {
			matches = append(matches, matchEntry{Domain: d})
		}
		entries = append(entries, entry{Value: id, Matches: matches})
	}
	data, _ := json.Marshal(entries)
	return data
}

func TestBuiltWith_Run_EmitsFindings(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/tag1/api.json")
		assert.Contains(t, r.URL.RawQuery, "KEY=test-key")
		assert.Contains(t, r.URL.RawQuery, "LOOKUP=")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockBuiltWithResponse(map[string][]string{
			"UA-12345": {"acme.com", "acme-corp.com"},
		}))
	}))
	defer srv.Close()

	p := &BuiltWithPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"analytics_ids": "UA-12345"},
	})

	require.NoError(t, err)
	require.Len(t, findings, 2)

	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "builtwith", f.Source)
		assert.Equal(t, "Acme Corp", f.Data["org"])
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "acme.com")
	assert.Contains(t, values, "acme-corp.com")
}

func TestBuiltWith_Run_ConfidenceScore(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockBuiltWithResponse(map[string][]string{
			"UA-12345": {"acme.com"},
		}))
	}))
	defer srv.Close()

	p := &BuiltWithPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"analytics_ids": "UA-12345"},
	})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1, "one analytics ID, one evidence entry")
	assert.Equal(t, confBuiltWithSharedAnalytics, findings[0].Confidences[0].Score)
	assert.Contains(t, findings[0].Confidences[0].Justification, "UA-12345",
		"the justification names the identifier that linked the domain")
	assert.Equal(t, 60, plugins.TotalConfidence(findings[0]))
}

func TestBuiltWith_Run_MultipleAnalyticsIDs(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch callCount {
		case 1:
			_, _ = w.Write(mockBuiltWithResponse(map[string][]string{
				"id1": {"domain1.com"},
			}))
		default:
			_, _ = w.Write(mockBuiltWithResponse(map[string][]string{
				"id2": {"domain2.com"},
			}))
		}
	}))
	defer srv.Close()

	p := &BuiltWithPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"analytics_ids": "UA-111, UA-222"},
	})

	require.NoError(t, err)
	assert.Equal(t, 2, callCount, "must call API once per analytics ID")

	var values []string
	for _, f := range findings {
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "domain1.com")
	assert.Contains(t, values, "domain2.com")
}

func TestBuiltWith_Run_DeduplicatesDomains(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockBuiltWithResponse(map[string][]string{
			"id": {"duplicate.com", "duplicate.com", "unique.com"},
		}))
	}))
	defer srv.Close()

	p := &BuiltWithPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"analytics_ids": "UA-123"},
	})

	require.NoError(t, err)
	assert.Len(t, findings, 2)
}

func TestBuiltWith_Run_EmptyResponse(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockBuiltWithResponse(nil))
	}))
	defer srv.Close()

	p := &BuiltWithPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Unknown Corp",
		Meta:    map[string]string{"analytics_ids": "UA-99999"},
	})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestBuiltWith_Run_ContinuesOnError(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockBuiltWithResponse(map[string][]string{
			"id2": {"success.com"},
		}))
	}))
	defer srv.Close()

	p := &BuiltWithPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"analytics_ids": "UA-fail, UA-success"},
	})

	assert.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "success.com", findings[0].Value)
}

func TestBuiltWith_IsRegistered(t *testing.T) {
	_, ok := plugins.Get("builtwith")
	assert.True(t, ok)
}

// TestBuiltWith_Run_ListsEveryMatchingIdentifier is the point of retaining
// identifiers per domain: the justification names each one that reached the
// domain. It stays ONE entry — a second tracker on the same marketing stack is
// not independent corroboration of ownership, and scoring it separately would
// sum to 1.20 and cap at full certainty.
func TestBuiltWith_Run_ListsEveryMatchingIdentifier(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Both lookups return the SAME domain, reached via different identifiers.
		_, _ = w.Write(mockBuiltWithResponse(map[string][]string{
			"id": {"shared.com"},
		}))
	}))
	defer srv.Close()

	p := &BuiltWithPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"analytics_ids": "UA-111, UA-222"},
	})

	require.NoError(t, err)
	require.Len(t, findings, 1, "one domain, however many identifiers reached it")

	require.Len(t, findings[0].Confidences, 1, "however many identifiers matched, one entry")
	assert.Equal(t, `Domain shares analytics identifiers "UA-111", "UA-222" with the target`,
		findings[0].Confidences[0].Justification)
	assert.Equal(t, confBuiltWithSharedAnalytics, plugins.TotalConfidence(findings[0]),
		"a second tracker does not raise the score")
	assert.True(t, plugins.NeedsReview(findings[0]))
}

// TestBuiltWith_Run_RepeatedPairListedOnce keeps a domain returned twice under
// the same identifier from naming that identifier twice.
func TestBuiltWith_Run_RepeatedPairListedOnce(t *testing.T) {
	t.Setenv("BUILTWITH_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockBuiltWithResponse(map[string][]string{
			"id": {"repeat.com", "repeat.com"},
		}))
	}))
	defer srv.Close()

	p := &BuiltWithPlugin{client: client.New(), baseURL: srv.URL}
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme Corp",
		Meta:    map[string]string{"analytics_ids": "UA-111"},
	})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	assert.Equal(t, `Domain shares analytics identifier "UA-111" with the target`,
		findings[0].Confidences[0].Justification, "singular noun, and the identifier appears once")
	assert.Equal(t, confBuiltWithSharedAnalytics, plugins.TotalConfidence(findings[0]))
}
