package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGLEIFPlugin(baseURL string) *GLEIFPlugin {
	return &GLEIFPlugin{client: client.New(), baseURL: baseURL}
}

// ── Mock helpers ──────────────────────────────────────────────────────────────

func gleifSearchResp(records ...leiRecord) []byte {
	resp := leiSearchResponse{
		Data: records,
		Meta: leiMeta{Pagination: leiPagination{CurrentPage: 1, LastPage: 1, Total: len(records)}},
	}
	b, _ := json.Marshal(resp)
	return b
}

func gleifRecordResp(r leiRecord) []byte {
	b, _ := json.Marshal(struct {
		Data leiRecord `json:"data"`
	}{Data: r})
	return b
}

func gleifRelationshipResp(parentLEI string) []byte {
	resp := leiRelationshipResponse{
		Data: leiRelationshipData{
			Attributes: leiRelationshipAttributes{
				Relationship: leiRelationshipNodes{
					StartNode: leiNode{ID: "CHILD001", Type: "LEI"},
					EndNode:   leiNode{ID: parentLEI, Type: "LEI"},
				},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func gleifChildrenResp(currentPage, lastPage int, records ...leiRecord) []byte {
	resp := leiChildrenResponse{
		Data: records,
		Meta: leiMeta{Pagination: leiPagination{CurrentPage: currentPage, LastPage: lastPage}},
	}
	b, _ := json.Marshal(resp)
	return b
}

func makeLEI(id, name, jurisdiction string, hasParentLink bool) leiRecord {
	links := map[string]string{"reporting-exception": "..."}
	if hasParentLink {
		links = map[string]string{"relationship-record": "https://api.gleif.org/..."}
	}
	return leiRecord{
		ID: id,
		Attributes: leiAttributes{
			Entity: leiEntity{
				LegalName:    leiLegalName{Name: name},
				Jurisdiction: jurisdiction,
				Status:       "ACTIVE",
			},
		},
		Relationships: leiRelationships{
			DirectParent: leiRelationshipEntry{Links: links},
		},
	}
}

// ── Interface tests ───────────────────────────────────────────────────────────

func TestGLEIFPlugin_Name(t *testing.T) {
	p := newGLEIFPlugin("")
	assert.Equal(t, "gleif", p.Name())
}

func TestGLEIFPlugin_Accepts(t *testing.T) {
	p := newGLEIFPlugin("")
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.False(t, p.Accepts(plugins.Input{OrgName: ""}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

func TestGLEIFPlugin_Category_Phase_Mode(t *testing.T) {
	p := newGLEIFPlugin("")
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

// ── Run() tests ───────────────────────────────────────────────────────────────

func TestGLEIFPlugin_Run_EmptyOrgName(t *testing.T) {
	p := newGLEIFPlugin("http://should-not-be-called")
	findings, err := p.Run(context.Background(), plugins.Input{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGLEIFPlugin_Run_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(gleifSearchResp()) // empty data array
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Unknown Corp"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGLEIFPlugin_Run_TopLevelWithSubsidiaries(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false) // top-level, no parent
	childA := makeLEI("LEI010", "Acme Subsidiary A", "US", true)
	childB := makeLEI("LEI011", "Acme Subsidiary B", "GB", true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/lei-records") && r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1, childA, childB))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	// Now emits FindingDomain + FindingPreseed for each subsidiary = 4 total
	require.Len(t, findings, 4)

	domainFindings := filterByType(findings, plugins.FindingDomain)
	preseedFindings := filterByType(findings, plugins.FindingPreseed)
	require.Len(t, domainFindings, 2)
	require.Len(t, preseedFindings, 2)

	for _, f := range domainFindings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "gleif", f.Source)
		assert.Equal(t, "subsidiary", f.Data["relationshipType"])
		assert.InDelta(t, plugins.ConfidenceHigh, plugins.TotalConfidence(f), 0.001)
		require.Len(t, f.Confidences, 1)
		assert.Contains(t, f.Confidences[0].Justification, "registered direct subsidiary")
	}
	names := []string{domainFindings[0].Value, domainFindings[1].Value}
	assert.Contains(t, names, "Acme Subsidiary A")
	assert.Contains(t, names, "Acme Subsidiary B")
}

func TestGLEIFPlugin_Run_WithDirectParent(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", true) // has parent
	parent := makeLEI("LEI_PARENT", "Acme Holdings", "US", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI001/ultimate-parent-relationship":
			// Same as direct parent → no separate ultimate finding
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI_PARENT":
			_, _ = w.Write(gleifRecordResp(parent))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1)) // no children
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	// Now emits FindingDomain + FindingPreseed for parent = 2 total
	require.Len(t, findings, 2)

	domainFindings := filterByType(findings, plugins.FindingDomain)
	require.Len(t, domainFindings, 1)
	assert.Equal(t, "Acme Holdings", domainFindings[0].Value)
	assert.Equal(t, "direct-parent", domainFindings[0].Data["relationshipType"])
	assert.Equal(t, "LEI_PARENT", domainFindings[0].Data["lei"])
}

func TestGLEIFPlugin_Run_WithUltimateParent(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", true)
	directParent := makeLEI("LEI_PARENT", "Acme Holdings", "US", false)
	ultimateParent := makeLEI("LEI_ULTIMATE", "Global Conglomerate Inc", "US", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI001/ultimate-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_ULTIMATE"))
		case r.URL.Path == "/lei-records/LEI_PARENT":
			_, _ = w.Write(gleifRecordResp(directParent))
		case r.URL.Path == "/lei-records/LEI_ULTIMATE":
			_, _ = w.Write(gleifRecordResp(ultimateParent))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	// 2 domain + 2 preseed = 4 total
	require.Len(t, findings, 4)

	relTypes := map[string]string{}
	for _, f := range findings {
		if f.Type == plugins.FindingDomain {
			relTypes[f.Data["relationshipType"].(string)] = f.Value
		}
	}
	assert.Equal(t, "Acme Holdings", relTypes["direct-parent"])
	assert.Equal(t, "Global Conglomerate Inc", relTypes["ultimate-parent"])
}

func TestGLEIFPlugin_Run_PaginatedChildren(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	page1Children := []leiRecord{
		makeLEI("LEI010", "Sub A", "US", false),
		makeLEI("LEI011", "Sub B", "US", false),
		makeLEI("LEI012", "Sub C", "US", false),
	}
	page2Children := []leiRecord{
		makeLEI("LEI013", "Sub D", "US", false),
		makeLEI("LEI014", "Sub E", "US", false),
		makeLEI("LEI015", "Sub F", "US", false),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			pageNum := r.URL.Query().Get("page[number]")
			if pageNum == "2" {
				_, _ = w.Write(gleifChildrenResp(2, 2, page2Children...))
			} else {
				_, _ = w.Write(gleifChildrenResp(1, 2, page1Children...))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	// 6 domain + 6 preseed = 12 total
	assert.Len(t, findings, 12)
	for _, f := range findings {
		if f.Type == plugins.FindingDomain {
			assert.Equal(t, "subsidiary", f.Data["relationshipType"])
		}
	}
}

func TestGLEIFPlugin_Run_MultipleNameMatches(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	match2 := makeLEI("LEI002", "Acme Corporation Ltd", "GB", false)
	match3 := makeLEI("LEI003", "Acme Corp Holdings", "DE", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary, match2, match3))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	// Name-match candidates: only domain findings, no preseeds
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "name-match", f.Data["relationshipType"])
		assert.InDelta(t, plugins.ConfidenceLow, plugins.TotalConfidence(f), 0.001)
		require.Len(t, f.Confidences, 1)
		assert.Contains(t, f.Confidences[0].Justification, "secondary GLEIF legal-name search match")
	}
}

func TestGLEIFPlugin_Run_Deduplication(t *testing.T) {
	// primary has a subsidiary with same name as a name-match candidate
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	child := makeLEI("LEI010", "Acme Corp Duplicate", "US", false)
	nameMatch := makeLEI("LEI010b", "Acme Corp Duplicate", "US", false) // same name

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary, nameMatch))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1, child))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	// "Acme Corp Duplicate" appears once as domain + once as preseed
	// The name-match domain finding is deduplicated (same type+value as subsidiary domain)
	domainCount := 0
	preseedCount := 0
	for _, f := range findings {
		if f.Value == "Acme Corp Duplicate" {
			switch f.Type {
			case plugins.FindingDomain:
				domainCount++
			case plugins.FindingPreseed:
				preseedCount++
			}
		}
	}
	assert.Equal(t, 1, domainCount, "duplicate domain names should be deduplicated")
	assert.Equal(t, 1, preseedCount, "preseed should be emitted once for the subsidiary")
}

func TestGLEIFPlugin_Run_ContextCanceled(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	page1 := []leiRecord{makeLEI("LEI010", "Sub A", "US", false)}

	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requestCount++
		if r.URL.Query().Get("filter[entity.legalName]") != "" {
			_, _ = w.Write(gleifSearchResp(primary))
			return
		}
		if r.URL.Path == "/lei-records/LEI001" {
			_, _ = w.Write(gleifRecordResp(primary))
			return
		}
		if strings.Contains(r.URL.Path, "/direct-children") {
			// First page; report 2 pages so it will try to paginate
			_, _ = w.Write(gleifChildrenResp(1, 2, page1...))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	p := newGLEIFPlugin(srv.URL)
	// Context may already be done; either returns ctx error or empty results
	_, err := p.Run(ctx, plugins.Input{OrgName: "Acme Corp"})
	// We accept either nil or context.Canceled depending on timing
	if err != nil {
		assert.ErrorIs(t, err, context.Canceled)
	}
}

// ── Preseed finding tests ──────────────────────────────────────────────────────

func TestGLEIFPlugin_Run_DirectParent_EmitsPreseed(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", true)
	parent := makeLEI("LEI_PARENT", "Acme Holdings", "US", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI001/ultimate-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT")) // same as direct
		case r.URL.Path == "/lei-records/LEI_PARENT":
			_, _ = w.Write(gleifRecordResp(parent))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	domainFindings := filterByType(findings, plugins.FindingDomain)
	preseedFindings := filterByType(findings, plugins.FindingPreseed)

	require.Len(t, domainFindings, 1, "expected one domain finding for direct parent")
	require.Len(t, preseedFindings, 1, "expected one preseed finding for direct parent")

	pf := preseedFindings[0]
	assert.Equal(t, "Acme Holdings", pf.Value)
	assert.Equal(t, "gleif", pf.Source)
	assert.Equal(t, "whois+company", pf.Data["preseed_type"])
	assert.Equal(t, "Acme Holdings", pf.Data["preseed_title"])
	assert.Equal(t, "LEI_PARENT", pf.Data["lei"])
	assert.InDelta(t, plugins.ConfidenceHigh, plugins.TotalConfidence(pf), 0.001)
	require.Len(t, pf.Confidences, 1)
	assert.Contains(t, pf.Confidences[0].Justification, "registered direct parent")
}

func TestGLEIFPlugin_Run_UltimateParent_EmitsPreseed(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", true)
	directParent := makeLEI("LEI_PARENT", "Acme Holdings", "US", false)
	ultimateParent := makeLEI("LEI_ULTIMATE", "Global Conglomerate Inc", "US", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI001/ultimate-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_ULTIMATE"))
		case r.URL.Path == "/lei-records/LEI_PARENT":
			_, _ = w.Write(gleifRecordResp(directParent))
		case r.URL.Path == "/lei-records/LEI_ULTIMATE":
			_, _ = w.Write(gleifRecordResp(ultimateParent))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	preseedValues := map[string]plugins.Finding{}
	for _, f := range findings {
		if f.Type == plugins.FindingPreseed {
			preseedValues[f.Value] = f
		}
	}

	require.Contains(t, preseedValues, "Acme Holdings", "expected preseed for direct parent")
	require.Contains(t, preseedValues, "Global Conglomerate Inc", "expected preseed for ultimate parent")

	for _, pf := range preseedValues {
		assert.Equal(t, "whois+company", pf.Data["preseed_type"])
		assert.InDelta(t, plugins.ConfidenceHigh, plugins.TotalConfidence(pf), 0.001)
		require.Len(t, pf.Confidences, 1)
		assert.Contains(t, pf.Confidences[0].Justification, "parent")
	}
}

func TestGLEIFPlugin_Run_Subsidiaries_EmitPreseeds(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	childA := makeLEI("LEI010", "Acme Subsidiary A", "US", true)
	childB := makeLEI("LEI011", "Acme Subsidiary B", "GB", true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/lei-records") && r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1, childA, childB))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	preseedValues := map[string]plugins.Finding{}
	for _, f := range findings {
		if f.Type == plugins.FindingPreseed {
			preseedValues[f.Value] = f
		}
	}

	require.Contains(t, preseedValues, "Acme Subsidiary A", "expected preseed for subsidiary A")
	require.Contains(t, preseedValues, "Acme Subsidiary B", "expected preseed for subsidiary B")

	for _, pf := range preseedValues {
		assert.Equal(t, "whois+company", pf.Data["preseed_type"])
		assert.InDelta(t, plugins.ConfidenceHigh, plugins.TotalConfidence(pf), 0.001)
		require.Len(t, pf.Confidences, 1)
		assert.Contains(t, pf.Confidences[0].Justification, "registered direct subsidiary")
		assert.Equal(t, pf.Value, pf.Data["preseed_title"])
	}
}

func TestGLEIFPlugin_Run_NameMatchCandidates_NoPreseed(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	match2 := makeLEI("LEI002", "Acme Corporation Ltd", "GB", false)
	match3 := makeLEI("LEI003", "Acme Corp Holdings", "DE", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary, match2, match3))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	// Name-match candidates should produce only FindingDomain, never FindingPreseed
	for _, f := range findings {
		if f.Type == plugins.FindingPreseed {
			t.Errorf("unexpected preseed finding for name-match candidate: %s", f.Value)
		}
	}

	// Verify we still get the domain findings for candidates
	domainCount := 0
	for _, f := range findings {
		if f.Type == plugins.FindingDomain && f.Data["relationshipType"] == "name-match" {
			domainCount++
		}
	}
	assert.Equal(t, 2, domainCount, "expected 2 domain findings for name-match candidates")
}

func TestGLEIFPlugin_Run_PreseedData_ContainsJurisdiction(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	child := makeLEI("LEI010", "Acme UK", "GB", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1, child))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	var preseed *plugins.Finding
	for i := range findings {
		if findings[i].Type == plugins.FindingPreseed && findings[i].Value == "Acme UK" {
			preseed = &findings[i]
			break
		}
	}
	require.NotNil(t, preseed, "expected preseed finding for subsidiary")
	assert.Equal(t, "GB", preseed.Data["jurisdiction"])
	assert.Equal(t, "LEI010", preseed.Data["lei"])
}

func TestGLEIFPlugin_Run_DomainAndPreseed_BothEmittedForSameName(t *testing.T) {
	// Verify that both FindingDomain and FindingPreseed are emitted for the same
	// parent/subsidiary — they are different types and should not block each other.
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	child := makeLEI("LEI010", "Acme Subsidiary A", "US", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("filter[entity.legalName]") != "":
			_, _ = w.Write(gleifSearchResp(primary))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1, child))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	hasDomain := false
	hasPreseed := false
	for _, f := range findings {
		if f.Value == "Acme Subsidiary A" {
			switch f.Type {
			case plugins.FindingDomain:
				hasDomain = true
			case plugins.FindingPreseed:
				hasPreseed = true
			}
		}
	}
	assert.True(t, hasDomain, "expected FindingDomain for subsidiary")
	assert.True(t, hasPreseed, "expected FindingPreseed for subsidiary")
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func filterByType(findings []plugins.Finding, t plugins.FindingType) []plugins.Finding {
	var result []plugins.Finding
	for _, f := range findings {
		if f.Type == t {
			result = append(result, f)
		}
	}
	return result
}
