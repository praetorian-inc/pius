package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	piuscache "github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCrunchbasePlugin creates a CrunchbasePlugin with a temp-dir APICache for isolated testing.
func newTestCrunchbasePlugin(t *testing.T, baseURL string) *CrunchbasePlugin {
	t.Helper()
	c, err := piuscache.NewAPI(t.TempDir(), "crunchbase")
	require.NoError(t, err)
	return &CrunchbasePlugin{
		client:   client.New(),
		baseURL:  baseURL,
		apiCache: c,
	}
}

// ── Accepts ───────────────────────────────────────────────────────────────────

func TestCrunchbasePlugin_Accepts_RequiresOrgNameAndAPIKey(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")
	p := &CrunchbasePlugin{client: client.New()}

	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Acme Corp", Domain: "acme.com"}))
}

func TestCrunchbasePlugin_Accepts_RejectsWithoutOrgName(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")
	p := &CrunchbasePlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "acme.com"}))
}

func TestCrunchbasePlugin_Accepts_RejectsWithoutAPIKey(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "")
	p := &CrunchbasePlugin{client: client.New()}

	assert.False(t, p.Accepts(plugins.Input{OrgName: "Acme Corp"}))
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestCrunchbasePlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("crunchbase")
	require.True(t, ok, "crunchbase plugin must be registered")

	assert.Equal(t, "crunchbase", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, plugins.ModePassive, p.Mode())
	assert.Contains(t, p.Description(), "Crunchbase")
	assert.Contains(t, p.Description(), "CRUNCHBASE_API_KEY")
}

// ── Run with mock server: autocomplete → entity lookup ──────────────────────

func TestCrunchbasePlugin_Run_BasicFlow(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/autocompletes":
			// Autocomplete returns matching entities
			resp := cbAutocompleteResponse{
				Entities: []cbAutocompleteEntity{
					{
						Identifier: cbIdentifier{
							Permalink:  "acme-corp",
							EntityType: "organization",
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/acme-corp":
			// Entity lookup returns org properties + cards
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{
						Permalink:  "acme-corp",
						EntityType: "organization",
					},
					ShortDescription: strPtr("Leading enterprise software company"),
					WebsiteURL:       strPtr("https://www.acme-corp.com"),
				},
				Cards: cbCards{
					AcquireeAcquisitions: []cbAcquisitionCard{
						{
							Identifier: cbIdentifier{Permalink: "acquisition-1"},
							AcquireeName: &cbIdentifier{
								Permalink:  "widget-co",
								EntityType: "organization",
							},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/widget-co":
			// Acquired company lookup
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{
						Permalink:  "widget-co",
						EntityType: "organization",
					},
					ShortDescription: strPtr("Widget manufacturer"),
					WebsiteURL:       strPtr("https://widget.co"),
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	p := newTestCrunchbasePlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})

	require.NoError(t, err)
	require.NotEmpty(t, findings)

	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "crunchbase", f.Source)
		values = append(values, f.Value)
	}

	// Primary org domain
	assert.Contains(t, values, "www.acme-corp.com")
	// Acquired company domain
	assert.Contains(t, values, "widget.co")
}

func TestCrunchbasePlugin_Run_NoAcquisitions(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/autocompletes":
			resp := cbAutocompleteResponse{
				Entities: []cbAutocompleteEntity{
					{Identifier: cbIdentifier{Permalink: "small-co", EntityType: "organization"}},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/small-co":
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier:       cbIdentifier{Permalink: "small-co", EntityType: "organization"},
					ShortDescription: strPtr("A small company"),
					WebsiteURL:       strPtr("https://small-co.com"),
				},
				Cards: cbCards{
					AcquireeAcquisitions: nil,
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	p := newTestCrunchbasePlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Small Co"})

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "small-co.com", findings[0].Value)
}

func TestCrunchbasePlugin_Run_NoAutocompleteMatch(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := cbAutocompleteResponse{Entities: nil}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := newTestCrunchbasePlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "NonExistent Corp"})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCrunchbasePlugin_Run_GracefulOnNetworkError(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	p := newTestCrunchbasePlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCrunchbasePlugin_Run_GracefulOnBadJSON(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{bad json`))
	}))
	defer srv.Close()

	p := newTestCrunchbasePlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCrunchbasePlugin_Run_UsesCacheOnSecondCall(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/autocompletes":
			resp := cbAutocompleteResponse{
				Entities: []cbAutocompleteEntity{
					{Identifier: cbIdentifier{Permalink: "acme", EntityType: "organization"}},
				},
			}
			json.NewEncoder(w).Encode(resp)

		default:
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{Permalink: "acme", EntityType: "organization"},
					WebsiteURL: strPtr("https://acme.com"),
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	p := newTestCrunchbasePlugin(t, srv.URL)
	input := plugins.Input{OrgName: "Acme Corp"}

	f1, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	firstCallCount := callCount

	f2, err := p.Run(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, firstCallCount, callCount, "second call must use cache, not hit API")
	assert.Equal(t, len(f1), len(f2))
}

func TestCrunchbasePlugin_Run_ConfidenceScoring(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/autocompletes":
			resp := cbAutocompleteResponse{
				Entities: []cbAutocompleteEntity{
					{Identifier: cbIdentifier{Permalink: "acme", EntityType: "organization"}},
				},
			}
			json.NewEncoder(w).Encode(resp)

		default:
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{Permalink: "acme", EntityType: "organization"},
					WebsiteURL: strPtr("https://acme.com"),
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	// Without domain — lower confidence (name-based resolution)
	p := newTestCrunchbasePlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	assert.Equal(t, 0.70, plugins.Confidence(findings[0]))

	// With domain — higher confidence
	p2 := newTestCrunchbasePlugin(t, srv.URL)
	findings2, err := p2.Run(context.Background(), plugins.Input{OrgName: "Acme Corp", Domain: "acme.com"})
	require.NoError(t, err)
	require.NotEmpty(t, findings2)
	assert.Equal(t, 0.85, plugins.Confidence(findings2[0]))
}

func TestCrunchbasePlugin_Run_DeduplicatesDomains(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/autocompletes":
			resp := cbAutocompleteResponse{
				Entities: []cbAutocompleteEntity{
					{Identifier: cbIdentifier{Permalink: "acme", EntityType: "organization"}},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/acme":
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{Permalink: "acme", EntityType: "organization"},
					WebsiteURL: strPtr("https://acme.com"),
				},
				Cards: cbCards{
					AcquireeAcquisitions: []cbAcquisitionCard{
						{
							Identifier:   cbIdentifier{Permalink: "acq-1"},
							AcquireeName: &cbIdentifier{Permalink: "sub-co", EntityType: "organization"},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/sub-co":
			// Acquired company has same domain as parent
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{Permalink: "sub-co", EntityType: "organization"},
					WebsiteURL: strPtr("https://acme.com"),
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	p := newTestCrunchbasePlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})

	require.NoError(t, err)

	count := 0
	for _, f := range findings {
		if f.Value == "acme.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "acme.com should appear exactly once")
}

func TestCrunchbasePlugin_Run_MultipleAcquisitions(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/autocompletes":
			resp := cbAutocompleteResponse{
				Entities: []cbAutocompleteEntity{
					{Identifier: cbIdentifier{Permalink: "bigcorp", EntityType: "organization"}},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/bigcorp":
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{Permalink: "bigcorp", EntityType: "organization"},
					WebsiteURL: strPtr("https://bigcorp.com"),
				},
				Cards: cbCards{
					AcquireeAcquisitions: []cbAcquisitionCard{
						{
							Identifier:   cbIdentifier{Permalink: "acq-1"},
							AcquireeName: &cbIdentifier{Permalink: "startup-a", EntityType: "organization"},
						},
						{
							Identifier:   cbIdentifier{Permalink: "acq-2"},
							AcquireeName: &cbIdentifier{Permalink: "startup-b", EntityType: "organization"},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/startup-a":
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{Permalink: "startup-a", EntityType: "organization"},
					WebsiteURL: strPtr("https://startup-a.io"),
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/startup-b":
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{Permalink: "startup-b", EntityType: "organization"},
					WebsiteURL: strPtr("https://startup-b.com"),
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	p := newTestCrunchbasePlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "BigCorp"})

	require.NoError(t, err)

	var values []string
	for _, f := range findings {
		values = append(values, f.Value)
	}

	assert.Contains(t, values, "bigcorp.com")
	assert.Contains(t, values, "startup-a.io")
	assert.Contains(t, values, "startup-b.com")
}

func TestCrunchbasePlugin_Run_AcquiredCompanyLookupFails(t *testing.T) {
	t.Setenv("CRUNCHBASE_API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/autocompletes":
			resp := cbAutocompleteResponse{
				Entities: []cbAutocompleteEntity{
					{Identifier: cbIdentifier{Permalink: "corp", EntityType: "organization"}},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/corp":
			resp := cbEntityResponse{
				Properties: cbOrgProperties{
					Identifier: cbIdentifier{Permalink: "corp", EntityType: "organization"},
					WebsiteURL: strPtr("https://corp.com"),
				},
				Cards: cbCards{
					AcquireeAcquisitions: []cbAcquisitionCard{
						{
							Identifier:   cbIdentifier{Permalink: "acq-1"},
							AcquireeName: &cbIdentifier{Permalink: "gone-co", EntityType: "organization"},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/entities/organizations/gone-co":
			// Simulate 404 for acquired company
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"not found"}`))
		}
	}))
	defer srv.Close()

	p := newTestCrunchbasePlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Corp"})

	// Should still return the primary org domain even if acquisition lookup fails
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "corp.com", findings[0].Value)
}

// ── extractFindings ──────────────────────────────────────────────────────────

func TestCrunchbasePlugin_ExtractFindings_WithWebsite(t *testing.T) {
	p := &CrunchbasePlugin{}
	website := "https://acme.com"
	data := &cbEntityResponse{
		Properties: cbOrgProperties{
			Identifier: cbIdentifier{Permalink: "acme", EntityType: "organization"},
			WebsiteURL: &website,
		},
	}
	findings := p.extractFindings("Acme", data)
	require.Len(t, findings, 1)
	assert.Equal(t, "acme.com", findings[0].Value)
	assert.Equal(t, "crunchbase", findings[0].Source)
	assert.Equal(t, "Acme", findings[0].Data["org"])
	assert.Equal(t, "acme", findings[0].Data["permalink"])
}

func TestCrunchbasePlugin_ExtractFindings_NoWebsite(t *testing.T) {
	p := &CrunchbasePlugin{}
	data := &cbEntityResponse{
		Properties: cbOrgProperties{
			Identifier: cbIdentifier{Permalink: "acme", EntityType: "organization"},
		},
	}
	assert.Empty(t, p.extractFindings("Acme", data))
}

func TestCrunchbasePlugin_ExtractFindings_EmptyWebsite(t *testing.T) {
	p := &CrunchbasePlugin{}
	empty := ""
	data := &cbEntityResponse{
		Properties: cbOrgProperties{
			Identifier: cbIdentifier{Permalink: "acme", EntityType: "organization"},
			WebsiteURL: &empty,
		},
	}
	assert.Empty(t, p.extractFindings("Acme", data))
}

// ── deduplicate ─────────────────────────────────────────────────────────────

func TestCrunchbasePlugin_Deduplicate(t *testing.T) {
	p := &CrunchbasePlugin{}
	findings := []plugins.Finding{
		{Type: plugins.FindingDomain, Value: "acme.com", Source: "crunchbase"},
		{Type: plugins.FindingDomain, Value: "widget.co", Source: "crunchbase"},
		{Type: plugins.FindingDomain, Value: "acme.com", Source: "crunchbase"},
	}
	deduped := p.deduplicate(findings)
	require.Len(t, deduped, 2)
	assert.Equal(t, "acme.com", deduped[0].Value)
	assert.Equal(t, "widget.co", deduped[1].Value)
}

func TestCrunchbasePlugin_Deduplicate_Empty(t *testing.T) {
	p := &CrunchbasePlugin{}
	assert.Empty(t, p.deduplicate(nil))
}

// ── Registry ──────────────────────────────────────────────────────────────────

func TestCrunchbasePlugin_IsRegistered(t *testing.T) {
	_, ok := plugins.Get("crunchbase")
	assert.True(t, ok)
}

func TestCrunchbasePlugin_AppearsInList(t *testing.T) {
	found := false
	for _, n := range plugins.List() {
		if n == "crunchbase" {
			found = true
			break
		}
	}
	assert.True(t, found)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func strPtr(s string) *string {
	return &s
}
