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
	resp := leiChildrenResponse{
		Data: records,
		Meta: leiMeta{Pagination: leiPagination{CurrentPage: currentPage, LastPage: lastPage}},
	}
	b, _ := json.Marshal(resp)
	return b
}

// gleifFuzzyResp builds a fuzzycompletions response that resolves to the given LEI.
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

// gleifFuzzyEmpty builds a fuzzycompletions response with no matches.
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
	primary := makeLEI("LEI001", "Acme Corp", "US", false) // top-level, no parent
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
		assert.Equal(t, 0.50, f.Data["confidence"])
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
	// 6 domain + 6 preseed = 12 total
	assert.Len(t, findings, 12)
	for _, f := range findings {
		if f.Type == plugins.FindingDomain {
			assert.Equal(t, "subsidiary", f.Data["relationshipType"])
		}
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
			// Return the same child twice to test dedup.
			_, _ = w.Write(gleifChildrenResp(1, 1, child, child))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newGLEIFPlugin(srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)

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
	assert.Equal(t, 0.50, pf.Data["confidence"])
}

func TestGLEIFPlugin_Run_UltimateParent_EmitsPreseed(t *testing.T) {
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
		assert.Equal(t, 0.50, pf.Data["confidence"])
	}
}

func TestGLEIFPlugin_Run_Subsidiaries_EmitPreseeds(t *testing.T) {
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
		assert.Equal(t, 0.50, pf.Data["confidence"])
		assert.Equal(t, pf.Value, pf.Data["preseed_title"])
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

func TestGLEIFPlugin_Run_DomainAndPreseed_BothEmittedForSameName(t *testing.T) {
	// Verify that both FindingDomain and FindingPreseed are emitted for the same
	// parent/subsidiary — they are different types and should not block each other.
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	child := makeLEI("LEI010", "Acme Subsidiary A", "US", false)

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

// ── Sibling discovery tests ──────────────────────────────────────────────────

func TestGLEIFPlugin_Run_SiblingDiscovery(t *testing.T) {
	// Primary has a parent; parent has other children (siblings of primary).
	// The plugin should discover those siblings.
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
			_, _ = w.Write(gleifChildrenResp(1, 1)) // primary has no children
		case r.URL.Path == "/lei-records/LEI_PARENT/direct-children":
			// Parent's children include primary + 2 siblings.
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

	// Should find: parent (domain+preseed) + 2 siblings (domain+preseed each) = 6.
	// Primary itself is excluded from siblings.
	preseedValues := map[string]bool{}
	domainRelTypes := map[string]string{}
	for _, f := range findings {
		if f.Type == plugins.FindingPreseed {
			preseedValues[f.Value] = true
		}
		if f.Type == plugins.FindingDomain {
			domainRelTypes[f.Value] = f.Data["relationshipType"].(string)
		}
	}

	assert.Contains(t, preseedValues, "Nielsen Holdings")
	assert.Contains(t, preseedValues, "Nielsen Finance BV")
	assert.Contains(t, preseedValues, "Nielsen Holdings Inc")
	assert.NotContains(t, preseedValues, "Nielsen US LLC", "primary should not appear as a sibling")

	assert.Equal(t, "direct-parent", domainRelTypes["Nielsen Holdings"])
	assert.Equal(t, "sibling", domainRelTypes["Nielsen Finance BV"])
	assert.Equal(t, "sibling", domainRelTypes["Nielsen Holdings Inc"])
}

func TestGLEIFPlugin_Run_SiblingDiscovery_UltimateParent(t *testing.T) {
	// Primary → direct parent → ultimate parent (different). Siblings of both
	// parents should be discovered.
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
