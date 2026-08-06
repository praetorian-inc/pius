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

// TestTokenSimilarity_DuplicateTokens pins tokenSimilarity's treatment of a
// token that repeats on one side. Similarity is a comparison of token *sets*:
// "Acme" said twice is the same claim said twice, not two pieces of evidence.
//
// These cases assert an EXACT value rather than a floor, because the defect
// this pins INFLATES the score — a floor assertion (as used by TestTokenSimilarity
// above, which encodes deliberate containment behavior for the github-org caller)
// passes happily on an inflated result and can never detect it.
func TestTokenSimilarity_DuplicateTokens(t *testing.T) {
	tests := []struct {
		a, b string
		want float64
	}{
		// Duplicate on the shorter side inflates the numerator: the distinct
		// tokens of a are {acme, widgets} and only "acme" is shared, so the
		// honest score is 1/2 = 0.50. Counting "acme" once per occurrence
		// scores it twice over a 3-token denominator instead.
		{"Acme Acme Widgets", "Acme Global Systems", 0.50},
		// Duplicates also distort which side is treated as "shorter": a says
		// one distinct thing, {acme}, and it is wholly contained in
		// {acme, global}, so containment is 1/1 = 1.00. Selecting the shorter
		// side by raw token count makes the 3-copy string the longer one and
		// measures the wrong direction.
		{"Acme Acme Acme", "Acme Global", 1.00},
		// Regression pin, not a defect case: after duplicates collapse, {acme}
		// is still wholly contained in {acme, global, systems}, so pure
		// containment must remain 1.00 and not be deflated by the fix.
		{"acme acme", "acme global systems", 1.00},
		// Real-world shape of the same input: a repeated org token beside a
		// distinguishing one. {praetorian, security} vs {praetorian, inc}
		// shares exactly one of two tokens → 0.50, and the repeat must not
		// move it.
		{"Praetorian Praetorian Security", "Praetorian Inc", 0.50},
		// The two cases below are the argument-order mirrors of the two defect
		// cases above, because nothing makes a caller put the repeat in a
		// rather than b: github_org.go passes the user-supplied input.OrgName
		// as b, and reverse_whois_verify.go passes normalizeOrg output on both
		// sides — and normalizeOrg, which drops legal-suffix tokens, can turn
		// a distinct name into a repeat by itself. Collapsing only a would
		// satisfy every case above (each of their b values is already
		// duplicate-free), so these are what pin the collapse to both sides.
		//
		// Mirror of the first case. a has 3 distinct tokens and b's raw form
		// is also 3 long, so leaving b uncollapsed ties the two and measures a
		// instead: only "acme" is shared, 1/3 = 0.33. Collapsing b as well
		// makes {acme, widgets} the shorter side, restoring the honest
		// 1/2 = 0.50.
		{"Acme Global Systems", "Acme Acme Widgets", 0.50},
		// Mirror of the selection flip, driven from b. b says one distinct
		// thing, {acme}, wholly contained in {acme, global}, so containment is
		// 1/1 = 1.00. Sizing b by its three raw copies makes it the longer
		// side and measures a's two tokens instead, deflating to 1/2 = 0.50.
		{"Acme Global", "Acme Acme Acme", 1.00},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := tokenSimilarity(tt.a, tt.b)
			assert.InDelta(t, tt.want, got, 0.001, "similarity %q vs %q", tt.a, tt.b)
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
	var f plugins.Finding
	p.score(&f, org, plugins.Input{OrgName: "Praetorian Security", Domain: "praetorian.com"})

	assert.GreaterOrEqual(t, plugins.TotalConfidence(f), githubEmitThreshold,
		"domain match should push above emit threshold")
	// All four signals fire for this org: blog domain, name similarity, login
	// token, and repo activity.
	require.Len(t, f.Confidences, 4)
	assert.InDelta(t, 0.60, f.Confidences[0].Score, 0.001)
	assert.Contains(t, f.Confidences[0].Justification, "praetorian.com")
	for _, c := range f.Confidences {
		assert.NotEmpty(t, c.Justification, "every entry needs a justification")
	}
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
	var f plugins.Finding
	p.score(&f, org, plugins.Input{OrgName: "Praetorian Security"})

	assert.Less(t, plugins.TotalConfidence(f), githubEmitThreshold,
		"landscaping org without domain should be below emit threshold")
	// No domain hint, so the blog-domain entry must be absent entirely.
	for _, c := range f.Confidences {
		assert.NotContains(t, c.Justification, "blog URL")
	}
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
	var f plugins.Finding
	p.score(&f, org, plugins.Input{OrgName: "Praetorian"})

	// Should still be above review threshold via name + handle + activity
	assert.GreaterOrEqual(t, plugins.TotalConfidence(f), githubReviewThreshold)
	require.Len(t, f.Confidences, 3, "name, login token and activity — but not the blog domain")
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
			assert.False(t, plugins.NeedsReview(f), "high-confidence match should not need review")
			assert.GreaterOrEqual(t, plugins.TotalConfidence(f), githubEmitThreshold)
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
	// May or may not emit depending on exact score, but if it does emit it must
	// carry evidence and be flagged for review.
	for _, f := range findings {
		require.NotEmpty(t, f.Confidences, "an emitted github-org finding is always scored")
		if plugins.TotalConfidence(f) < githubEmitThreshold {
			assert.True(t, plugins.NeedsReview(f), "borderline match must need review")
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

func TestGitHubOrgPlugin_Run_GracefulOnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	p := newGitHubTestPlugin(t, srv.URL)
	findings, err := p.Run(context.Background(), plugins.Input{OrgName: "Acme"})
	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestGitHubOrgPlugin_Run_GracefulOnNetworkError(t *testing.T) {
	c, err := piuscache.NewAPI(t.TempDir(), "github-org")
	require.NoError(t, err)
	p := &GitHubOrgPlugin{client: client.NewNoRetry(), baseURL: "http://127.0.0.1:1", apiCache: c}
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
