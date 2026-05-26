package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Accepts ───────────────────────────────────────────────────────────────────

func TestGATrackingPlugin_Accepts_WithAPIKeyAndDomain(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")
	p := &GATrackingPlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{Domain: "example.com"}))
}

func TestGATrackingPlugin_Accepts_WithAPIKeyAndMetaIDs(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")
	p := &GATrackingPlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{Meta: map[string]string{"ga_tracking_ids": "UA-12345-1"}}))
}

func TestGATrackingPlugin_Accepts_RejectsWithoutAPIKey(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "")
	p := &GATrackingPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{Domain: "example.com"}))
	assert.False(t, p.Accepts(plugins.Input{Meta: map[string]string{"ga_tracking_ids": "UA-12345-1"}}))
}

func TestGATrackingPlugin_Accepts_RejectsWithoutDomainOrMeta(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")
	p := &GATrackingPlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme"}))
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGATrackingPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("ga-tracking")
	require.True(t, ok, "ga-tracking plugin must be registered")

	assert.Equal(t, "ga-tracking", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModeActive, p.Mode())
	assert.Contains(t, p.Description(), "GA Tracking")
	assert.Contains(t, p.Description(), "SPYONWEB_API_KEY")
}

// ── parseTrackingIDList ───────────────────────────────────────────────────────

func TestParseTrackingIDList_ParsesAnalyticsIDs(t *testing.T) {
	ids := parseTrackingIDList("UA-15207196-1")
	require.Len(t, ids, 1)
	assert.Equal(t, "UA-15207196-1", ids[0].value)
	assert.Equal(t, "analytics", ids[0].idType)
}

func TestParseTrackingIDList_ParsesAdsenseIDs(t *testing.T) {
	ids := parseTrackingIDList("pub-1234567890123456")
	require.Len(t, ids, 1)
	assert.Equal(t, "pub-1234567890123456", ids[0].value)
	assert.Equal(t, "adsense", ids[0].idType)
}

func TestParseTrackingIDList_ParsesMixed(t *testing.T) {
	ids := parseTrackingIDList("UA-12345-1, pub-9876543210, UA-99999-2")
	require.Len(t, ids, 3)
	assert.Equal(t, "UA-12345-1", ids[0].value)
	assert.Equal(t, "analytics", ids[0].idType)
	assert.Equal(t, "pub-9876543210", ids[1].value)
	assert.Equal(t, "adsense", ids[1].idType)
	assert.Equal(t, "UA-99999-2", ids[2].value)
	assert.Equal(t, "analytics", ids[2].idType)
}

func TestParseTrackingIDList_SkipsUnrecognized(t *testing.T) {
	ids := parseTrackingIDList("UA-12345-1, UNKNOWN-FORMAT, pub-9876543210")
	require.Len(t, ids, 2, "unrecognized format should be skipped")
}

func TestParseTrackingIDList_EmptyInput(t *testing.T) {
	ids := parseTrackingIDList("")
	assert.Empty(t, ids)
}

func TestParseTrackingIDList_ExtractsExactMatch(t *testing.T) {
	ids := parseTrackingIDList("UA-12345-1 trailing garbage")
	require.Len(t, ids, 1)
	assert.Equal(t, "UA-12345-1", ids[0].value)
}

// ── extractFromDomain ─────────────────────────────────────────────────────────

func TestGATrackingPlugin_ExtractFromDomain_ExtractsUAIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>UA-15207196-1</html>"))
	}))
	defer srv.Close()

	p := &GATrackingPlugin{client: client.New(), targetURL: srv.URL}
	ids, err := p.extractFromDomain(context.Background(), "example.com")
	require.NoError(t, err)
	require.Len(t, ids, 1)
	assert.Equal(t, "UA-15207196-1", ids[0].value)
	assert.Equal(t, "analytics", ids[0].idType)
}

func TestGATrackingPlugin_ExtractFromDomain_ExtractsPubIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>pub-1234567890123456</html>"))
	}))
	defer srv.Close()

	p := &GATrackingPlugin{client: client.New(), targetURL: srv.URL}
	ids, err := p.extractFromDomain(context.Background(), "example.com")
	require.NoError(t, err)
	require.Len(t, ids, 1)
	assert.Equal(t, "pub-1234567890123456", ids[0].value)
	assert.Equal(t, "adsense", ids[0].idType)
}

func TestGATrackingPlugin_ExtractFromDomain_ReturnsErrorOnFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	p := &GATrackingPlugin{client: client.New(), targetURL: srv.URL}
	_, err := p.extractFromDomain(context.Background(), "example.com")
	assert.Error(t, err)
}

func TestGATrackingPlugin_ExtractFromDomain_EmptyHTMLReturnsNoIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>No tracking here</body></html>"))
	}))
	defer srv.Close()

	p := &GATrackingPlugin{client: client.New(), targetURL: srv.URL}
	ids, err := p.extractFromDomain(context.Background(), "example.com")
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestGATrackingPlugin_ExtractFromDomain_CapsIDs(t *testing.T) {
	var html strings.Builder
	html.WriteString("<html>")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&html, "UA-%d-1 ", 10000+i)
	}
	html.WriteString("</html>")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(html.String()))
	}))
	defer srv.Close()

	p := &GATrackingPlugin{client: client.New(), targetURL: srv.URL}
	ids, err := p.extractFromDomain(context.Background(), "example.com")
	require.NoError(t, err)
	assert.LessOrEqual(t, len(ids), maxTrackingIDsPerDomain, "should cap extracted UA IDs")
}

// ── parseSpyOnWebResponse ─────────────────────────────────────────────────────

func TestParseSpyOnWebResponse_Found_Analytics(t *testing.T) {
	body := []byte(`{"status":"found","result":{"analytics":{"UA-15207196":{"items":{"example.com":"2024-01-15","other.com":"2024-01-10"}}}}}`)
	tid := trackingID{value: "UA-15207196-1", idType: "analytics"}
	input := plugins.Input{OrgName: "Acme", Domain: "example.com"}

	findings, err := parseSpyOnWebResponse(body, tid, input)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "ga-tracking", f.Source)
		assert.Equal(t, "UA-15207196-1", f.Data["tracking_id"])
		assert.Equal(t, "analytics", f.Data["tracking_type"])
		assert.Equal(t, 0.85, f.Data["confidence"])
		assert.Equal(t, false, f.Data["needs_review"])
	}

	domains := make([]string, 0, len(findings))
	for _, f := range findings {
		domains = append(domains, f.Value)
	}
	assert.Contains(t, domains, "example.com")
	assert.Contains(t, domains, "other.com")
}

func TestParseSpyOnWebResponse_Found_Adsense(t *testing.T) {
	body := []byte(`{"status":"found","result":{"adsense":{"pub-1234567890":{"items":{"related.com":"2024-02-01"}}}}}`)
	tid := trackingID{value: "pub-1234567890", idType: "adsense"}

	findings, err := parseSpyOnWebResponse(body, tid, plugins.Input{})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "related.com", findings[0].Value)
	assert.Equal(t, 0.70, findings[0].Data["confidence"])
	assert.Equal(t, false, findings[0].Data["needs_review"])
}

func TestParseSpyOnWebResponse_NotFound(t *testing.T) {
	body := []byte(`{"status":"not_found"}`)
	tid := trackingID{value: "UA-99999-1", idType: "analytics"}

	findings, err := parseSpyOnWebResponse(body, tid, plugins.Input{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParseSpyOnWebResponse_ErrorStatus(t *testing.T) {
	body := []byte(`{"status":"error"}`)
	findings, err := parseSpyOnWebResponse(body, trackingID{value: "UA-1234-1", idType: "analytics"}, plugins.Input{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParseSpyOnWebResponse_MalformedJSON(t *testing.T) {
	_, err := parseSpyOnWebResponse([]byte("not-json"), trackingID{value: "UA-1", idType: "analytics"}, plugins.Input{})
	assert.Error(t, err)
}

func TestParseSpyOnWebResponse_MissingCategory(t *testing.T) {
	body := []byte(`{"status":"found","result":{}}`)
	tid := trackingID{value: "UA-12345-1", idType: "analytics"}

	findings, err := parseSpyOnWebResponse(body, tid, plugins.Input{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParseSpyOnWebResponse_NormalizesDomains(t *testing.T) {
	body := []byte(`{"status":"found","result":{"analytics":{"UA-12345":{"items":{"EXAMPLE.COM.":"2024-01-01"}}}}}`)
	tid := trackingID{value: "UA-12345-1", idType: "analytics"}

	findings, err := parseSpyOnWebResponse(body, tid, plugins.Input{})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "example.com", findings[0].Value)
}

// ── confidenceForType ─────────────────────────────────────────────────────────

func TestConfidenceForType_Analytics(t *testing.T) {
	assert.Equal(t, 0.85, confidenceForType("analytics"))
}

func TestConfidenceForType_Adsense(t *testing.T) {
	assert.Equal(t, 0.70, confidenceForType("adsense"))
}

// ── deduplicateTrackingIDs ────────────────────────────────────────────────────

func TestDeduplicateTrackingIDs_RemovesDuplicates(t *testing.T) {
	ids := []trackingID{
		{value: "UA-12345-1", idType: "analytics"},
		{value: "UA-12345-1", idType: "analytics"},
		{value: "pub-9876543210", idType: "adsense"},
	}
	result := deduplicateTrackingIDs(ids)
	require.Len(t, result, 2)
}

func TestDeduplicateTrackingIDs_Empty(t *testing.T) {
	result := deduplicateTrackingIDs(nil)
	assert.Empty(t, result)
}

// ── Run integration (mock servers) ───────────────────────────────────────────

func newGATestPlugin(spyonwebSrv *httptest.Server, targetSrv *httptest.Server) *GATrackingPlugin {
	p := &GATrackingPlugin{client: client.New()}
	if spyonwebSrv != nil {
		p.spyonwebURL = spyonwebSrv.URL
	}
	if targetSrv != nil {
		p.targetURL = targetSrv.URL
	}
	return p
}

func mockSpyOnWebServer(idType, trackID string, items map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"status": "found",
			"result": map[string]any{
				idType: map[string]any{
					trackID: map[string]any{
						"items": items,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func mockTargetHTMLServer(html string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(html))
	}))
}

func TestGATrackingPlugin_Run_PlatformMode(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")

	spySrv := mockSpyOnWebServer("analytics", "UA-15207196", map[string]string{
		"related.com": "2024-01-15",
		"another.com": "2024-01-10",
	})
	defer spySrv.Close()

	p := newGATestPlugin(spySrv, nil)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Acme",
		Meta:    map[string]string{"ga_tracking_ids": "UA-15207196-1"},
	})

	require.NoError(t, err)
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "ga-tracking", f.Source)
	}
	domains := make([]string, 0, len(findings))
	for _, f := range findings {
		domains = append(domains, f.Value)
	}
	assert.Contains(t, domains, "related.com")
	assert.Contains(t, domains, "another.com")
}

func TestGATrackingPlugin_Run_StandaloneMode(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")

	targetSrv := mockTargetHTMLServer("<html>UA-15207196-1</html>")
	defer targetSrv.Close()

	spySrv := mockSpyOnWebServer("analytics", "UA-15207196", map[string]string{
		"discovered.com": "2024-01-15",
	})
	defer spySrv.Close()

	p := newGATestPlugin(spySrv, targetSrv)
	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "example.com",
	})

	require.NoError(t, err)
	require.NotEmpty(t, findings)
	assert.Equal(t, "discovered.com", findings[0].Value)
}

func TestGATrackingPlugin_Run_Deduplication(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")

	spySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"status": "found",
			"result": map[string]any{
				"analytics": map[string]any{
					"UA-12345": map[string]any{"items": map[string]string{"shared.com": "2024-01-01"}},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer spySrv.Close()

	p := newGATestPlugin(spySrv, nil)
	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"ga_tracking_ids": "UA-12345-1,UA-12345-2"},
	})

	require.NoError(t, err)
	count := 0
	for _, f := range findings {
		if f.Value == "shared.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "shared.com should appear only once after deduplication")
}

func TestGATrackingPlugin_Run_GracefulOnSpyOnWebError(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	p := newGATestPlugin(srv, nil)
	findings, err := p.Run(context.Background(), plugins.Input{
		Meta: map[string]string{"ga_tracking_ids": "UA-12345-1"},
	})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGATrackingPlugin_Run_GracefulOnTargetFetchError(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	targetSrv.Close()

	p := newGATestPlugin(nil, targetSrv)
	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "example.com",
	})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGATrackingPlugin_QuerySpyOnWeb_StripsPropertySuffix(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"not_found"}`))
	}))
	defer srv.Close()

	p := &GATrackingPlugin{client: client.New(), spyonwebURL: srv.URL}
	_, _ = p.querySpyOnWeb(context.Background(), trackingID{value: "UA-15207196-1", idType: "analytics"}, plugins.Input{})
	assert.Equal(t, "/analytics/UA-15207196", capturedPath, "should strip property suffix for analytics queries")
}

func TestGATrackingPlugin_Run_NoTrackingIDsFound(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")

	targetSrv := mockTargetHTMLServer("<html><body>No tracking IDs here</body></html>")
	defer targetSrv.Close()

	p := newGATestPlugin(nil, targetSrv)
	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "example.com",
	})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}


func TestGATrackingPlugin_Run_CombinedMode_TargetFetchFailFallsBackToMeta(t *testing.T) {
	t.Setenv("SPYONWEB_API_KEY", "test-key")

	// Target server that's already closed (will fail to connect)
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	targetSrv.Close()

	// SpyOnWeb server that returns results
	spySrv := mockSpyOnWebServer("analytics", "UA-99999", map[string]string{
		"fallback.com": "2024-01-15",
	})
	defer spySrv.Close()

	p := newGATestPlugin(spySrv, targetSrv)
	findings, err := p.Run(context.Background(), plugins.Input{
		Domain: "example.com",
		Meta:   map[string]string{"ga_tracking_ids": "UA-99999-1"},
	})

	require.NoError(t, err)
	require.NotEmpty(t, findings, "should fall back to Meta IDs when HTML fetch fails")
	assert.Equal(t, "fallback.com", findings[0].Value)
}
// ── Registry ──────────────────────────────────────────────────────────────────

func TestGATrackingPlugin_IsRegistered(t *testing.T) {
	_, ok := plugins.Get("ga-tracking")
	assert.True(t, ok)
}

func TestGATrackingPlugin_AppearsInList(t *testing.T) {
	found := false
	for _, n := range plugins.List() {
		if n == "ga-tracking" {
			found = true
			break
		}
	}
	assert.True(t, found)
}
