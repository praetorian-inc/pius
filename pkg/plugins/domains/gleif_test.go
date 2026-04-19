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
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "gleif", f.Source)
		assert.Equal(t, "subsidiary", f.Data["relationshipType"])
		assert.Equal(t, plugins.ConfidenceHigh, f.Data["confidence"])
	}
	names := []string{findings[0].Value, findings[1].Value}
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
	require.Len(t, findings, 1)
	assert.Equal(t, "Acme Holdings", findings[0].Value)
	assert.Equal(t, "direct-parent", findings[0].Data["relationshipType"])
	assert.Equal(t, "LEI_PARENT", findings[0].Data["lei"])
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
	require.Len(t, findings, 2)

	relTypes := map[string]string{}
	for _, f := range findings {
		relTypes[f.Data["relationshipType"].(string)] = f.Value
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
	assert.Len(t, findings, 6)
	for _, f := range findings {
		assert.Equal(t, "subsidiary", f.Data["relationshipType"])
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
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.Equal(t, "name-match", f.Data["relationshipType"])
		assert.Equal(t, plugins.ConfidenceLow, f.Data["confidence"])
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
	// "Acme Corp Duplicate" appears once — subsidiary wins over name-match (added first)
	count := 0
	for _, f := range findings {
		if f.Value == "Acme Corp Duplicate" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate names should be deduplicated")
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
