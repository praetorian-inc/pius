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
	total := len(records)
	if lastPage > currentPage {
		total = len(records) * lastPage // approximate
	}
	resp := leiChildrenResponse{
		Data: records,
		Meta: leiMeta{Pagination: leiPagination{CurrentPage: currentPage, LastPage: lastPage, Total: total}},
	}
	b, _ := json.Marshal(resp)
	return b
}

func gleifFuzzyResp(lei string) []byte {
	resp := map[string]any{
		"data": []map[string]any{
			{
				"type":       "fuzzycompletions",
				"attributes": map[string]string{"value": "matched"},
				"relationships": map[string]any{
					"lei-records": map[string]any{
						"data": map[string]string{"type": "lei-records", "id": lei},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func gleifFuzzyEmpty() []byte {
	b, _ := json.Marshal(map[string]any{"data": []any{}})
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
		_, _ = w.Write(gleifFuzzyEmpty())
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Unknown Corp"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGLEIFPlugin_Run_TopLevelWithSubsidiaries(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	childA := makeLEI("LEI010", "Acme Subsidiary A", "US", true)
	childB := makeLEI("LEI011", "Acme Subsidiary B", "GB", true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1, childA, childB))
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	require.Len(t, findings, 2)
	for _, f := range findings {
		assert.Equal(t, plugins.FindingPreseed, f.Type)
		assert.Equal(t, "gleif", f.Source)
		assert.Equal(t, "subsidiary", f.Data["corporate_relationship"])
		assert.Equal(t, plugins.ConfidenceHigh, plugins.TotalConfidence(f))
		require.Len(t, f.Confidences, 2, "resolution and registered relationship are the independent signals")
		assert.False(t, plugins.NeedsReview(f))
	}
	names := []string{findings[0].Value, findings[1].Value}
	assert.Contains(t, names, "Acme Subsidiary A")
	assert.Contains(t, names, "Acme Subsidiary B")
}

func TestGLEIFPlugin_Run_WithDirectParent(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", true)
	parent := makeLEI("LEI_PARENT", "Acme Holdings", "US", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI001/ultimate-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI_PARENT":
			_, _ = w.Write(gleifRecordResp(parent))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1))
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, plugins.FindingPreseed, findings[0].Type)
	assert.Equal(t, "Acme Holdings", findings[0].Value)
	assert.Equal(t, "direct-parent", findings[0].Data["corporate_relationship"])
	assert.Equal(t, "LEI_PARENT", findings[0].Data["lei"])
}

func TestGLEIFPlugin_Run_WithUltimateParent(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", true)
	directParent := makeLEI("LEI_PARENT", "Acme Holdings", "US", false)
	ultimateParent := makeLEI("LEI_ULTIMATE", "Global Conglomerate Inc", "US", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
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
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	require.Len(t, findings, 2)
	relTypes := map[string]string{}
	for _, f := range findings {
		relTypes[f.Data["corporate_relationship"].(string)] = f.Value
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
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			pageNum := r.URL.Query().Get("page[number]")
			if pageNum == "2" {
				_, _ = w.Write(gleifChildrenResp(2, 2, page2Children...))
			} else {
				_, _ = w.Write(gleifChildrenResp(1, 2, page1Children...))
			}
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	assert.Len(t, findings, 6)
	for _, f := range findings {
		assert.Equal(t, plugins.FindingPreseed, f.Type)
		assert.Equal(t, "subsidiary", f.Data["corporate_relationship"])
	}
}

func TestGLEIFPlugin_Run_Deduplication(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	child := makeLEI("LEI010", "Acme Corp Duplicate", "US", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1, child, child))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	preseedCount := 0
	for _, f := range findings {
		if f.Value == "Acme Corp Duplicate" && f.Type == plugins.FindingPreseed {
			preseedCount++
		}
	}
	assert.Equal(t, 1, preseedCount, "duplicate preseeds should be deduplicated")
}

func TestGLEIFPlugin_Run_ContextCanceled(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	page1 := []leiRecord{makeLEI("LEI010", "Sub A", "US", false)}

	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requestCount++
		if r.URL.Path == "/lei-records/LEI001" {
			_, _ = w.Write(gleifRecordResp(primary))
			return
		}
		if strings.Contains(r.URL.Path, "/direct-children") {
			_, _ = w.Write(gleifChildrenResp(1, 2, page1...))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/fuzzycompletions") {
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := newGLEIFPlugin(srv.URL)
	_, err := p.Run(ctx, plugins.Input{OrgName: "Acme Corp"})
	if err != nil {
		assert.ErrorIs(t, err, context.Canceled)
	}
}

func TestGLEIFPlugin_Run_PreseedData_ContainsJurisdiction(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	child := makeLEI("LEI010", "Acme UK", "GB", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case strings.Contains(r.URL.Path, "/direct-children"):
			_, _ = w.Write(gleifChildrenResp(1, 1, child))
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
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

// ── Confidence decomposition tests ──────────────────────────────────────────

func TestGLEIFPlugin_Run_ConfidenceSignals_Parent(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", true)
	parent := makeLEI("LEI_PARENT", "Acme Holdings", "US", false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI001/ultimate-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
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
	require.Len(t, findings, 1)

	f := findings[0]
	require.Len(t, f.Confidences, 2)
	assert.Equal(t, 15, f.Confidences[0].Score)
	assert.Contains(t, f.Confidences[0].Justification, "top candidate")
	assert.Contains(t, f.Confidences[0].Justification, "Acme Corp")
	require.Len(t, f.Confidences[0].References, 2)
	assert.Contains(t, f.Confidences[0].References[0].URL, srv.URL+"/fuzzycompletions?")
	assert.Equal(t, srv.URL+"/lei-records/LEI001", f.Confidences[0].References[1].URL)
	assert.Equal(t, 50, f.Confidences[1].Score)
	assert.Contains(t, f.Confidences[1].Justification, "direct parent")
	require.Len(t, f.Confidences[1].References, 2)
	assert.Equal(t, srv.URL+"/lei-records/LEI_PARENT", f.Confidences[1].References[0].URL)
	assert.Equal(t, srv.URL+"/lei-records/LEI001/direct-parent-relationship", f.Confidences[1].References[1].URL)
	assert.Equal(t, plugins.ConfidenceHigh, plugins.TotalConfidence(f))
	assert.False(t, plugins.NeedsReview(f), "a registered parent of the top candidate should not need review")
}

func TestGLEIFPlugin_Run_ConfidenceSignals_Sibling_DifferentJurisdiction(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", true)
	parent := makeLEI("LEI_PARENT", "Acme Holdings", "GB", false)
	sibling := makeLEI("LEI010", "Acme Japan", "JP", true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI001/ultimate-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI_PARENT":
			_, _ = w.Write(gleifRecordResp(parent))
		case r.URL.Path == "/lei-records/LEI001/direct-children":
			_, _ = w.Write(gleifChildrenResp(1, 1))
		case r.URL.Path == "/lei-records/LEI_PARENT/direct-children":
			_, _ = w.Write(gleifChildrenResp(1, 1, primary, sibling))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

	// Find the sibling finding.
	var sib *plugins.Finding
	for i := range findings {
		if findings[i].Value == "Acme Japan" {
			sib = &findings[i]
		}
	}
	require.NotNil(t, sib)

	require.Len(t, sib.Confidences, 2)
	assert.Equal(t, 15, sib.Confidences[0].Score)
	assert.Equal(t, 30, sib.Confidences[1].Score)
	require.Len(t, sib.Confidences[1].References, 3)
	assert.Equal(t, srv.URL+"/lei-records/LEI010", sib.Confidences[1].References[0].URL)
	assert.Equal(t, srv.URL+"/lei-records/LEI010/direct-parent-relationship", sib.Confidences[1].References[1].URL)
	assert.Equal(t, srv.URL+"/lei-records/LEI001/direct-parent-relationship", sib.Confidences[1].References[2].URL)
	assert.Equal(t, 45, plugins.TotalConfidence(*sib))
	assert.True(t, plugins.NeedsReview(*sib), "sibling in different jurisdiction should need review")
}

// ── Sibling discovery tests ──────────────────────────────────────────────────

func TestGLEIFPlugin_Run_SiblingDiscovery(t *testing.T) {
	primary := makeLEI("LEI001", "Nielsen US LLC", "US", true)
	parent := makeLEI("LEI_PARENT", "Nielsen Holdings", "GB", false)
	siblingA := makeLEI("LEI010", "Nielsen Finance BV", "NL", true)
	siblingB := makeLEI("LEI011", "Nielsen Holdings Inc", "US", true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI001/ultimate-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_PARENT"))
		case r.URL.Path == "/lei-records/LEI_PARENT":
			_, _ = w.Write(gleifRecordResp(parent))
		case r.URL.Path == "/lei-records/LEI001/direct-children":
			_, _ = w.Write(gleifChildrenResp(1, 1))
		case r.URL.Path == "/lei-records/LEI_PARENT/direct-children":
			_, _ = w.Write(gleifChildrenResp(1, 1, primary, siblingA, siblingB))
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Nielsen US LLC"})
	require.NoError(t, err)

	preseedRelTypes := map[string]string{}
	for _, f := range findings {
		require.Equal(t, plugins.FindingPreseed, f.Type)
		preseedRelTypes[f.Value] = f.Data["corporate_relationship"].(string)
	}

	assert.Equal(t, "direct-parent", preseedRelTypes["Nielsen Holdings"])
	assert.Equal(t, "sibling", preseedRelTypes["Nielsen Finance BV"])
	assert.Equal(t, "sibling", preseedRelTypes["Nielsen Holdings Inc"])
	assert.NotContains(t, preseedRelTypes, "Nielsen US LLC", "primary should not appear as a sibling")
}

func TestGLEIFPlugin_Run_SiblingDiscovery_UltimateParent(t *testing.T) {
	primary := makeLEI("LEI001", "Acme US", "US", true)
	directParent := makeLEI("LEI_DP", "Acme Holdings", "US", true)
	ultimateParent := makeLEI("LEI_UP", "Global Corp", "US", false)
	directSibling := makeLEI("LEI010", "Acme EU", "DE", true)
	ultimateSibling := makeLEI("LEI020", "Beta Holdings", "GB", true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_DP"))
		case r.URL.Path == "/lei-records/LEI001/ultimate-parent-relationship":
			_, _ = w.Write(gleifRelationshipResp("LEI_UP"))
		case r.URL.Path == "/lei-records/LEI_DP":
			_, _ = w.Write(gleifRecordResp(directParent))
		case r.URL.Path == "/lei-records/LEI_UP":
			_, _ = w.Write(gleifRecordResp(ultimateParent))
		case r.URL.Path == "/lei-records/LEI001/direct-children":
			_, _ = w.Write(gleifChildrenResp(1, 1))
		case r.URL.Path == "/lei-records/LEI_DP/direct-children":
			_, _ = w.Write(gleifChildrenResp(1, 1, primary, directSibling))
		case r.URL.Path == "/lei-records/LEI_UP/direct-children":
			_, _ = w.Write(gleifChildrenResp(1, 1, directParent, ultimateSibling))
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp("LEI001"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme US"})
	require.NoError(t, err)

	preseedValues := map[string]bool{}
	for _, f := range findings {
		if f.Type == plugins.FindingPreseed {
			preseedValues[f.Value] = true
		}
	}

	assert.Contains(t, preseedValues, "Acme Holdings", "direct parent")
	assert.Contains(t, preseedValues, "Global Corp", "ultimate parent")
	assert.Contains(t, preseedValues, "Acme EU", "sibling via direct parent")
	assert.Contains(t, preseedValues, "Beta Holdings", "sibling via ultimate parent")
	assert.NotContains(t, preseedValues, "Acme US", "primary excluded from siblings")
}
