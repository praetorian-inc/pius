package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	piuscache "github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("github-org", func() plugins.Plugin {
		return &GitHubOrgPlugin{client: client.New()}
	})
}

// GitHubOrgPlugin discovers GitHub organizations matching an org name.
//
// Strategy:
//   1. Search GitHub for orgs matching the name (top 5 results)
//   2. Fetch full org details for each candidate
//   3. Score each candidate (domain cross-reference + name similarity + activity)
//   4. Emit high-confidence matches (≥0.65) as FindingDomain for blog URL
//   5. Emit borderline matches (0.35–0.64) with needs_review:true for future agent review
//
// Scoring:
//   - 0.60: blog URL contains input domain (strongest signal)
//   - 0.25: name token similarity with input OrgName
//   - 0.10: org login contains first word of OrgName
//   - 0.05: org has >5 public repos (active, not squatter)
//
// Phase 0 (independent): requires only OrgName.
// GITHUB_TOKEN env var is optional — improves rate limit from 60 to 5000 req/hr.
type GitHubOrgPlugin struct {
	client   *client.Client
	baseURL  string // override for testing
	apiCache *piuscache.APICache
}

const (
	githubEmitThreshold   = 0.65 // emit FindingDomain
	githubReviewThreshold = 0.35 // emit with needs_review:true
	githubMaxCandidates   = 5    // max orgs to fetch full details for
)

func (p *GitHubOrgPlugin) Name() string { return "github-org" }
func (p *GitHubOrgPlugin) Description() string {
	return "GitHub: discovers org handle and blog domain via GitHub org search (GITHUB_TOKEN optional)"
}
func (p *GitHubOrgPlugin) Category() string { return "domain" }
func (p *GitHubOrgPlugin) Phase() int       { return 0 }
func (p *GitHubOrgPlugin) Mode() string     { return plugins.ModePassive }

func (p *GitHubOrgPlugin) Accepts(input plugins.Input) bool {
	return input.OrgName != ""
}

func (p *GitHubOrgPlugin) githubBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.github.com"
}

func (p *GitHubOrgPlugin) getCache() *piuscache.APICache {
	if p.apiCache != nil {
		return p.apiCache
	}
	c, err := piuscache.NewAPI("", "github-org")
	if err != nil {
		log.Printf("[github-org] cache init failed: %v", err)
		return nil
	}
	p.apiCache = c
	return c
}

// ── API types ─────────────────────────────────────────────────────────────────

type githubSearchResult struct {
	Items []struct {
		Login string `json:"login"`
		Score float64 `json:"score"`
	} `json:"items"`
}

type githubOrg struct {
	Login       string `json:"login"`
	Name        string `json:"name"`
	Blog        string `json:"blog"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
	PublicRepos int    `json:"public_repos"`
	Email       string `json:"email"`
}

// ── Run ───────────────────────────────────────────────────────────────────────

func (p *GitHubOrgPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	cacheKey := strings.ToLower("github-org|" + input.OrgName + "|" + input.Domain)
	c := p.getCache()
	if c != nil {
		var cached []plugins.Finding
		if c.Get(cacheKey, &cached) {
			return cached, nil
		}
	}

	headers := p.authHeaders()

	// Step 1: Search for matching GitHub orgs
	searchURL := fmt.Sprintf("%s/search/users?q=%s+type:org&per_page=%d",
		p.githubBase(), url.QueryEscape(input.OrgName), githubMaxCandidates)

	body, err := p.client.GetWithHeaders(ctx, searchURL, headers)
	if err != nil {
		log.Printf("[github-org] search failed for %q: %v", input.OrgName, err)
		return nil, nil
	}

	var result githubSearchResult
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[github-org] parse search response: %v", err)
		return nil, nil
	}

	// Step 2: Fetch full org details and score each candidate
	var findings []plugins.Finding
	for _, item := range result.Items {
		select {
		case <-ctx.Done():
			break
		default:
		}

		org, err := p.fetchOrg(ctx, item.Login, headers)
		if err != nil || org == nil {
			continue
		}

		confidence := p.score(org, input)
		if confidence < plugins.ConfidenceLow {
			continue // below noise floor — discard
		}

		findings = append(findings, p.buildFindings(org, confidence, input)...)
	}

	if c != nil {
		c.Set(cacheKey, findings)
	}
	return findings, nil
}

func (p *GitHubOrgPlugin) fetchOrg(ctx context.Context, login string, headers map[string]string) (*githubOrg, error) {
	orgURL := fmt.Sprintf("%s/orgs/%s", p.githubBase(), url.PathEscape(login))
	body, err := p.client.GetWithHeaders(ctx, orgURL, headers)
	if err != nil {
		return nil, err
	}
	var org githubOrg
	if err := json.Unmarshal(body, &org); err != nil {
		return nil, err
	}
	return &org, nil
}

// score computes a confidence score [0.0, 1.0] for an org matching the input.
func (p *GitHubOrgPlugin) score(org *githubOrg, input plugins.Input) float64 {
	score := 0.0

	// Domain cross-reference: blog URL contains the known domain (strongest signal)
	if input.Domain != "" && domainContains(org.Blog, input.Domain) {
		score += 0.60
	}

	// Name similarity: token overlap between org display name and OrgName
	score += 0.25 * tokenSimilarity(org.Name, input.OrgName)

	// Handle contains first word of OrgName (e.g. "praetorian" in "praetorian-inc")
	if len(input.OrgName) > 0 {
		firstWord := strings.ToLower(strings.Fields(input.OrgName)[0])
		if strings.Contains(strings.ToLower(org.Login), firstWord) {
			score += 0.10
		}
	}

	// Activity signal: active org (not a squatter or placeholder)
	if org.PublicRepos > 5 {
		score += 0.05
	}

	return score
}

// buildFindings emits findings for a scored org.
func (p *GitHubOrgPlugin) buildFindings(org *githubOrg, confidence float64, input plugins.Input) []plugins.Finding {
	commonData := map[string]any{
		"org":          input.OrgName,
		"github_login": org.Login,
		"github_url":   org.HTMLURL,
		"github_name":  org.Name,
	}

	var findings []plugins.Finding

	// Emit blog domain if it's a new domain (not already the input domain)
	blogDomain := stripScheme(org.Blog)
	if blogDomain != "" && !domainContains(org.Blog, input.Domain) {
		data := make(map[string]any, len(commonData)+1)
		for k, v := range commonData {
			data[k] = v
		}
		data["field"] = "blog"
		f := plugins.Finding{Type: plugins.FindingDomain, Value: blogDomain, Source: "github-org", Data: data}
		plugins.SetConfidence(&f, confidence)
		findings = append(findings, f)
	}

	// Always emit the GitHub org as a domain finding (github.com/{login})
	orgFinding := plugins.Finding{
		Type:   plugins.FindingDomain,
		Value:  fmt.Sprintf("github.com/%s", org.Login),
		Source: "github-org",
		Data:   commonData,
	}
	plugins.SetConfidence(&orgFinding, confidence)
	findings = append(findings, orgFinding)

	return findings
}

// authHeaders returns GitHub API auth headers.
// GITHUB_TOKEN is optional but raises rate limit from 60 to 5000 req/hr.
func (p *GitHubOrgPlugin) authHeaders() map[string]string {
	h := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		h["Authorization"] = "Bearer " + token
	}
	return h
}

// ── Scoring helpers ───────────────────────────────────────────────────────────

// domainContains reports whether rawURL contains the target domain as a hostname.
// "https://www.praetorian.com/foo", "praetorian.com" → true
// "https://praetorian-group.io", "praetorian.com" → false
func domainContains(rawURL, domain string) bool {
	if rawURL == "" || domain == "" {
		return false
	}
	host := strings.ToLower(stripScheme(rawURL))
	domain = strings.ToLower(strings.TrimPrefix(domain, "www."))
	host = strings.TrimPrefix(host, "www.")
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// tokenSimilarity computes the ratio of shared tokens between two strings.
// Uses the shorter string as the denominator so partial matches score well.
// "Praetorian" vs "Praetorian Security" → 1/1 = 1.0 (shorter has 1 token, matches)
// "Praetorian Security" vs "Praetorian Landscaping" → 1/2 = 0.5
func tokenSimilarity(a, b string) float64 {
	aT := tokenize(a)
	bT := tokenize(b)
	if len(aT) == 0 || len(bT) == 0 {
		return 0
	}
	shorter, longer := aT, bT
	if len(aT) > len(bT) {
		shorter, longer = bT, aT
	}
	inLonger := make(map[string]bool, len(longer))
	for _, t := range longer {
		inLonger[t] = true
	}
	matches := 0
	for _, t := range shorter {
		if inLonger[t] {
			matches++
		}
	}
	return float64(matches) / float64(len(shorter))
}

// tokenize lowercases s and splits on non-alphanumeric characters.
func tokenize(s string) []string {
	s = strings.ToLower(s)
	var buf strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			buf.WriteRune(c)
		} else {
			buf.WriteByte(' ')
		}
	}
	return strings.Fields(buf.String())
}
