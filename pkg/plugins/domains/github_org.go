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
//  1. Search GitHub for orgs matching the name (top 5 results)
//  2. Fetch full org details for each candidate
//  3. Score each candidate (domain cross-reference + name similarity + activity)
//  4. Emit high-confidence matches (≥0.65) as FindingDomain for blog URL
//  5. Emit borderline matches (0.35–0.64), which NeedsReview flags for future agent review
//
// Scoring — each signal is a separate, separately justified evidence entry:
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
	apiKey   string // set by NewGitHubOrgPlugin; falls back to GITHUB_TOKEN
	noCache  bool   // set by NewGitHubOrgPlugin; skips the on-disk cache entirely
}

// NewGitHubOrgPlugin builds the plugin around a caller-supplied client and token.
// The token is optional — it only raises the rate limit from 60 to 5000 req/hr —
// so an empty token is not an error. The on-disk cache is disabled: embedders run
// in ephemeral containers where it never warms, and a stale entry would silently
// bypass the caller's transport.
func NewGitHubOrgPlugin(c *client.Client, token string) *GitHubOrgPlugin {
	return &GitHubOrgPlugin{client: c, apiKey: token, noCache: true}
}

// key prefers an injected token so embedders never depend on process environment.
func (p *GitHubOrgPlugin) key() string {
	if p.apiKey != "" {
		return p.apiKey
	}
	return os.Getenv("GITHUB_TOKEN")
}

const (
	githubEmitThreshold   = 0.65 // emit FindingDomain
	githubReviewThreshold = 0.35 // emit, flagged by plugins.NeedsReview
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
	if p.noCache {
		return nil
	}
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
		Login string  `json:"login"`
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
		if ctx.Err() != nil {
			break
		}

		org, err := p.fetchOrg(ctx, item.Login, headers)
		if err != nil || org == nil {
			continue
		}

		// Score each candidate finding independently: score() appends to the
		// finding's own (nil) evidence slice, so the two findings built from one
		// org never share a backing array.
		for _, f := range p.buildFindings(org, input) {
			p.score(&f, org, input)
			if plugins.TotalConfidence(f) < plugins.ConfidenceLow {
				continue // below noise floor — discard
			}
			findings = append(findings, f)
		}
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

// score appends one evidence entry per independently observed signal that this
// org matches the input. Each signal is scored and justified separately so a
// reviewer sees which of the four actually fired, not just their sum.
func (p *GitHubOrgPlugin) score(finding *plugins.Finding, org *githubOrg, input plugins.Input) {
	// Domain cross-reference: blog URL contains the known domain (strongest signal)
	if input.Domain != "" && domainContains(org.Blog, input.Domain) {
		plugins.AddConfidence(finding, 0.60,
			fmt.Sprintf("GitHub organization blog URL matches the known domain %q", input.Domain))
	}

	// Name similarity: token overlap between org display name and OrgName
	if similarity := tokenSimilarity(org.Name, input.OrgName); similarity > 0 {
		plugins.AddConfidence(finding, 0.25*similarity,
			fmt.Sprintf("GitHub organization name %q matches the target organization %q with %.0f%% token similarity",
				org.Name, input.OrgName, similarity*100))
	}

	// Handle contains first word of OrgName (e.g. "praetorian" in "praetorian-inc")
	if fields := strings.Fields(input.OrgName); len(fields) > 0 {
		firstWord := strings.ToLower(fields[0])
		if strings.Contains(strings.ToLower(org.Login), firstWord) {
			plugins.AddConfidence(finding, 0.10,
				fmt.Sprintf("GitHub organization login %q contains target organization token %q",
					org.Login, firstWord))
		}
	}

	// Activity signal: active org (not a squatter or placeholder)
	if org.PublicRepos > 5 {
		plugins.AddConfidence(finding, 0.05,
			fmt.Sprintf("GitHub organization has %d public repositories, indicating an active organization",
				org.PublicRepos))
	}
}

// buildFindings emits the unscored candidate findings for an org. Callers run
// score on each one before deciding whether to keep it.
func (p *GitHubOrgPlugin) buildFindings(org *githubOrg, input plugins.Input) []plugins.Finding {
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
		findings = append(findings, plugins.Finding{
			Type: plugins.FindingDomain, Value: blogDomain, Source: "github-org", Data: data,
		})
	}

	// Always emit the GitHub org as a domain finding (github.com/{login})
	findings = append(findings, plugins.Finding{
		Type:   plugins.FindingDomain,
		Value:  fmt.Sprintf("github.com/%s", org.Login),
		Source: "github-org",
		Data:   commonData,
	})

	return findings
}

// authHeaders returns GitHub API auth headers.
// GITHUB_TOKEN is optional but raises rate limit from 60 to 5000 req/hr.
func (p *GitHubOrgPlugin) authHeaders() map[string]string {
	h := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if token := p.key(); token != "" {
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

// tokenJaccard computes the Jaccard similarity between two strings' token sets:
// |A ∩ B| / |A ∪ B|, over DISTINCT tokens. Unlike tokenSimilarity, which divides
// by the SHORTER set (containment), Jaccard counts tokens present on ONLY one side
// against the score, so a short string merely CONTAINED in a longer one no longer
// scores 1.0.
//
// This is the metric the reverse-whois verifier needs (ENG-5172). A single-token
// query org such as "Acme" against a registrant "Acme Enterprises LLC"
// (normalized {acme} vs {acme, enterprises}) scores 1/2 = 0.5 under Jaccard,
// not the 1/1 = 1.0 containment gave — so it lands in the unverified band and needs
// review instead of spuriously corroborating. github_org's name-similarity signal
// deliberately KEEPS containment (tokenSimilarity): there a partial name overlap is
// a weak, 0.25-weighted hint, not a corroboration gate.
func tokenJaccard(a, b string) float64 {
	aT := tokenize(a)
	bT := tokenize(b)
	if len(aT) == 0 || len(bT) == 0 {
		return 0
	}
	inA := make(map[string]bool, len(aT))
	for _, t := range aT {
		inA[t] = true
	}
	inB := make(map[string]bool, len(bT))
	for _, t := range bT {
		inB[t] = true
	}
	intersection := 0
	for t := range inA {
		if inB[t] {
			intersection++
		}
	}
	union := len(inA) + len(inB) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
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
