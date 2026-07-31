package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	piuscache "github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newGitHubTestPlugin creates a GitHubOrgPlugin with injected baseURL and temp cache.
func newGitHubTestPlugin(t *testing.T, baseURL string) *GitHubOrgPlugin {
	t.Helper()
	c, err := piuscache.NewAPI(t.TempDir(), "github-org")
	require.NoError(t, err)
	return &GitHubOrgPlugin{
		client:   client.New(),
		baseURL:  baseURL,
		apiCache: c,
	}
}

// mockGitHubServer creates an httptest server that handles GitHub search + org endpoints.
func mockGitHubServer(t *testing.T, orgs []githubOrg) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/search/users" {
			items := make([]map[string]any, len(orgs))
			for i, org := range orgs {
				items[i] = map[string]any{
					"login": org.Login,
					"score": 1.0,
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_count": len(orgs),
				"items":       items,
			})
			return
		}

		// /orgs/{login}
		for _, org := range orgs {
			if r.URL.Path == fmt.Sprintf("/orgs/%s", org.Login) {
				_ = json.NewEncoder(w).Encode(org)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{}`))
	}))
}

// ── Accepts ───────────────────────────────────────────────────────────────────

func TestGitHubOrgPlugin_Accepts_RequiresOrgName(t *testing.T) {
	p := &GitHubOrgPlugin{client: client.New()}
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Praetorian"}))
	assert.True(t, p.Accepts(plugins.Input{OrgName: "Praetorian", Domain: "praetorian.com"}))
	assert.False(t, p.Accepts(plugins.Input{}))
	assert.False(t, p.Accepts(plugins.Input{Domain: "praetorian.com"}))
}

// ── Metadata ──────────────────────────────────────────────────────────────────

func TestGitHubOrgPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("github-org")
	require.True(t, ok, "github-org plugin must be registered")

	assert.Equal(t, "github-org", p.Name())
	assert.Equal(t, 0, p.Phase())
	assert.Equal(t, "domain", p.Category())
	assert.Contains(t, p.Description(), "GitHub")
}

// ── domainContains ────────────────────────────────────────────────────────────

func TestDomainContains(t *testing.T) {
	tests := []struct {
		rawURL string
		domain string
		want   bool
	}{
		{"https://www.praetorian.com", "praetorian.com", true},
		{"https://praetorian.com", "praetorian.com", true},
		{"https://praetorian.com/blog", "praetorian.com", true},
		{"https://blog.praetorian.com", "praetorian.com", true},
		{"https://praetorian-group.io", "praetorian.com", false},
		{"https://notpraetorian.com", "praetorian.com", false},
		{"", "praetorian.com", false},
		{"https://praetorian.com", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.rawURL+"|"+tt.domain, func(t *testing.T) {
			assert.Equal(t, tt.want, domainContains(tt.rawURL, tt.domain))
		})
	}
}

// ── tokenSimilarity ───────────────────────────────────────────────────────────

func TestTokenSimilarity(t *testing.T) {
	tests := []struct {
		a, b string
		min  float64
	}{
		{"Praetorian", "Praetorian", 1.0},
		{"Praetorian", "Praetorian Security", 1.0},  // shorter (1 token) fully matches
		{"Praetorian Security", "Praetorian Inc", 0.49},  // 1/2 = 0.50
		{"Acme Corp", "Acme Corporation", 0.49}, // "acme" matches, "corp" != "corporation" = 1/2 = 0.50
		{"Google", "Apple", 0.0},
		{"", "Google", 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := tokenSimilarity(tt.a, tt.b)
			assert.GreaterOrEqual(t, got, tt.min, "similarity %q vs %q", tt.a, tt.b)
		})
	}
}

// ── score ─────────────────────────────────────────────────────────────────────

func TestGitHubOrgPlugin_Score_HighConfidenceWithDomain(t *testing.T) {
	p := &GitHubOrgPlugin{}
	org := &githubOrg{
		Login:       "praetorian-inc",
		Name:        "Praetorian",
		Blog:        "https://www.praetorian.com",
		PublicRepos: 86,
	}
	score := p.score(org, plugins.Input{OrgName: "Praetorian Security", Domain: "praetorian.com"})
	assert.GreaterOrEqual(t, score, githubEmitThreshold, "domain match should push above emit threshold")
}

func TestGitHubOrgPlugin_Score_BelowThresholdWithoutDomain(t *testing.T) {
	p := &GitHubOrgPlugin{}
	org := &githubOrg{
		Login:       "praetorian-landscaping",
		Name:        "Praetorian Landscaping LLC",
		Blog:        "https://praetorian-landscaping.com",
		PublicRepos: 2,
	}
	// No domain hint — relies on name similarity only
	score := p.score(org, plugins.Input{OrgName: "Praetorian Security"})
	assert.Less(t, score, githubEmitThreshold, "landscaping org without domain should be below emit threshold")
}

func TestGitHubOrgPlugin_Score_NoDomainInputReliesOnName(t *testing.T) {
	p := &GitHubOrgPlugin{}
	org := &githubOrg{
		Login:       "praetorian-inc",
		Name:        "Praetorian",
		Blog:        "https://www.praetorian.com",
		PublicRepos: 86,
	}
	// No domain provided — domain signal is 0
	score := p.score(org, plugins.Input{OrgName: "Praetorian"})
	// Should still be above review threshold via name + handle + activity
	assert.GreaterOrEqual(t, score, githubReviewThreshold)
}

// ── Run with mock server ──────────────────────────────────────────────────────

func TestGitHubOrgPlugin_Run_EmitsHighConfidenceMatch(t *testing.T) {
	orgs := []githubOrg{
		{Login: "praetorian-inc", Name: "Praetorian", Blog: "https://www.praetorian.com", PublicRepos: 86, HTMLURL: "https://github.com/praetorian-inc"},
	}
	srv := mockGitHubServer(t, orgs)
	defer srv.Close()

	p := newGitHubTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Praetorian Security",
		Domain:  "praetorian.com",
	})

	require.NoError(t, err)
	require.NotEmpty(t, findings)

	// Should include github.com/praetorian-inc
	var values []string
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "github-org", f.Source)
		values = append(values, f.Value)
	}
	assert.Contains(t, values, "github.com/praetorian-inc")

	// High confidence should not need review
	for _, f := range findings {
		if f.Value == "github.com/praetorian-inc" {
			assert.False(t, f.Data["needs_review"].(bool), "high-confidence match should not need review")
			assert.GreaterOrEqual(t, f.Data["confidence"].(float64), githubEmitThreshold)
		}
	}
}

func TestGitHubOrgPlugin_Run_EmitsBlogDomainWhenDifferent(t *testing.T) {
	orgs := []githubOrg{
		{Login: "example-inc", Name: "Example Corp", Blog: "https://example-corp.io", PublicRepos: 10, HTMLURL: "https://github.com/example-inc"},
	}
	srv := mockGitHubServer(t, orgs)
	defer srv.Close()

	p := newGitHubTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Example Corp",
		Domain:  "example.com", // different from blog domain
	})

	require.NoError(t, err)
	var values []string
	for _, f := range findings {
		values = append(values, f.Value)
	}
	// Blog domain should be emitted as a new domain finding
	assert.Contains(t, values, "example-corp.io")
}

func TestGitHubOrgPlugin_Run_DoesNotEmitBlogWhenMatchesInputDomain(t *testing.T) {
	orgs := []githubOrg{
		{Login: "praetorian-inc", Name: "Praetorian", Blog: "https://www.praetorian.com", PublicRepos: 86, HTMLURL: "https://github.com/praetorian-inc"},
	}
	srv := mockGitHubServer(t, orgs)
	defer srv.Close()

	p := newGitHubTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Praetorian Security",
		Domain:  "praetorian.com", // same as blog domain
	})

	require.NoError(t, err)
	for _, f := range findings {
		// Blog domain should NOT be emitted since it equals the input domain
		assert.NotEqual(t, "praetorian.com", f.Value, "should not re-emit input domain")
		assert.NotEqual(t, "www.praetorian.com", f.Value)
	}
}

func TestGitHubOrgPlugin_Run_DiscardsLowConfidenceMatch(t *testing.T) {
	orgs := []githubOrg{
		// Totally unrelated org — same first word but different industry, no domain match
		{Login: "praetorian-landscaping", Name: "Praetorian Landscaping Services", Blog: "https://landscaping.local", PublicRepos: 1, HTMLURL: "https://github.com/praetorian-landscaping"},
	}
	srv := mockGitHubServer(t, orgs)
	defer srv.Close()

	p := newGitHubTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Praetorian Security",
		Domain:  "praetorian.com",
	})

	require.NoError(t, err)
	assert.Empty(t, findings, "low-confidence org with no domain match should be discarded")
}

func TestGitHubOrgPlugin_Run_MarksReviewForBorderline(t *testing.T) {
	orgs := []githubOrg{
		// Partial name match, no domain, some repos — borderline
		{Login: "praetorian-sec", Name: "Praetorian Security Group", Blog: "", PublicRepos: 8, HTMLURL: "https://github.com/praetorian-sec"},
	}
	srv := mockGitHubServer(t, orgs)
	defer srv.Close()

	p := newGitHubTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{
		OrgName: "Praetorian Security",
		// No domain — so only name+handle+activity signals
	})

	require.NoError(t, err)
	// May or may not emit depending on exact score, but if it does emit, needs_review should be set
	for _, f := range findings {
		conf := f.Data["confidence"].(float64)
		if conf < githubEmitThreshold {
			assert.True(t, f.Data["needs_review"].(bool), "borderline match must have needs_review:true")
		}
	}
}

func TestGitHubOrgPlugin_Run_UsesCacheOnSecondCall(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/search/users" {
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 0, "items": []any{}})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := newGitHubTestPlugin(t, srv.URL)
	input := plugins.Input{OrgName: "Acme Corp", Domain: "acme.com"}

	_, _ = p.Run(context.Background(), input)
	calls1 := callCount

	_, _ = p.Run(context.Background(), input)
	assert.Equal(t, calls1, callCount, "second call should use cache, not hit API")
}

func TestGitHubOrgPlugin_Run_GracefulOnNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	p := newGitHubTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

// ── Auth headers ──────────────────────────────────────────────────────────────

func TestGitHubOrgPlugin_AuthHeaders_WithToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_testtoken")
	p := &GitHubOrgPlugin{}
	headers := p.authHeaders()
	assert.Equal(t, "Bearer ghp_testtoken", headers["Authorization"])
	assert.Equal(t, "application/vnd.github+json", headers["Accept"])
}

func TestGitHubOrgPlugin_AuthHeaders_WithoutToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	p := &GitHubOrgPlugin{}
	headers := p.authHeaders()
	_, hasAuth := headers["Authorization"]
	assert.False(t, hasAuth, "no auth header without GITHUB_TOKEN")
}

// ── Registry ──────────────────────────────────────────────────────────────────

func TestGitHubOrgPlugin_IsRegistered(t *testing.T) {
	_, ok := plugins.Get("github-org")
	assert.True(t, ok)
}
