package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	confWikidataCurrent    = 0.50
	confWikidataUnverified = 0.30
	confWikidataEnded      = 0.00
)

type wikidataConfidenceScenario struct {
	score         float64
	justification func(subsidiary, website, relation string) string
}

const (
	wikidataRelationshipCurrent    = "current"
	wikidataRelationshipEnded      = "ended_or_deprecated"
	wikidataRelationshipUnverified = "unverified"
)

var wikidataConfidenceScenarios = map[string]wikidataConfidenceScenario{
	wikidataRelationshipCurrent: {
		score: confWikidataCurrent,
		justification: func(subsidiary, website, relation string) string {
			return fmt.Sprintf("Wikidata currently identifies %q as related to the target (%s) and lists %q as its official website", subsidiary, relation, website)
		},
	},
	wikidataRelationshipEnded: {
		score: confWikidataEnded,
		justification: func(subsidiary, website, relation string) string {
			return fmt.Sprintf("Wikidata lists %q as the official website of %q, but says its relationship to the target (%s) is ended or deprecated", website, subsidiary, relation)
		},
	},
	wikidataRelationshipUnverified: {
		score: confWikidataUnverified,
		justification: func(subsidiary, website, relation string) string {
			return fmt.Sprintf("Wikidata identifies %q as related to the target (%s) and lists %q as its official website, but relationship qualifiers were not verified", subsidiary, relation, website)
		},
	},
}

func init() {
	plugins.Register("wikidata", func() plugins.Plugin {
		return &WikidataPlugin{
			httpClient: &http.Client{Timeout: 30 * time.Second},
			baseURL:    "",
		}
	})
}

// WikidataPlugin discovers subsidiary websites via Wikidata's SPARQL endpoint.
// It queries for:
//   - P749 (parent organization): finds entities with target as parent
//   - P355 (subsidiary): finds entities listed as subsidiaries of target
//   - P856 (official website): extracts domains directly when available
//
// Phase 0 (independent): requires only OrgName.
// Free public endpoint — no API key required.
// Results are cached in ~/.pius/cache/ with a 24-hour TTL.
type WikidataPlugin struct {
	httpClient httpDoer        // for testing
	baseURL    string          // override for testing; default "https://query.wikidata.org/sparql"
	apiCache   *cache.APICache // injected in tests; nil = lazy init on first Run
	noCache    bool            // set by NewWikidataPlugin; skips the on-disk cache entirely
}

func NewWikidataPlugin(hc *http.Client) *WikidataPlugin {
	return &WikidataPlugin{httpClient: hc, noCache: true}
}

// httpDoer allows mocking HTTP requests in tests.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

func (p *WikidataPlugin) Name() string { return "wikidata" }
func (p *WikidataPlugin) Description() string {
	return "Wikidata SPARQL: discovers subsidiary websites via structured corporate data (free, no API key)"
}
func (p *WikidataPlugin) Category() string { return "domain" }
func (p *WikidataPlugin) Phase() int       { return 0 }
func (p *WikidataPlugin) Mode() string     { return plugins.ModePassive }

func (p *WikidataPlugin) Accepts(input plugins.Input) bool {
	return input.OrgName != ""
}

func (p *WikidataPlugin) sparqlEndpoint() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://query.wikidata.org/sparql"
}

// getCache returns the APICache, initializing it lazily on first use.
// Returns nil if the cache directory cannot be created (non-fatal).
func (p *WikidataPlugin) getCache() *cache.APICache {
	if p.noCache {
		return nil
	}
	if p.apiCache != nil {
		return p.apiCache
	}
	c, err := cache.NewAPI("", "wikidata")
	if err != nil {
		slog.Debug("wikidata: cache init failed", "error", err)
		return nil
	}
	p.apiCache = c
	return c
}

// sparqlResponse represents the JSON response from Wikidata SPARQL endpoint.
type sparqlResponse struct {
	Results struct {
		Bindings []sparqlBinding `json:"bindings"`
	} `json:"results"`
}

type sparqlBinding struct {
	Entity      sparqlValue `json:"entity"`
	EntityLabel sparqlValue `json:"entityLabel"`
	Website     sparqlValue `json:"website"`
	Relation    sparqlValue `json:"relation"`
	Rank        sparqlValue `json:"rank"`
	EndTime     sparqlValue `json:"endTime"`
}

type sparqlValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (p *WikidataPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	if input.OrgName == "" {
		return nil, nil
	}

	cacheKey := strings.ToLower(input.OrgName)
	c := p.getCache()
	if cached, ok := cachedWikidataFindings(c, cacheKey); ok {
		slog.Debug("wikidata: cache hit", "org", input.OrgName)
		return cached, nil
	}

	companyID, err := p.findCompanyEntity(ctx, input.OrgName)
	if err != nil {
		slog.Debug("wikidata: company lookup failed", "org", input.OrgName, "error", err)
		return nil, nil
	}
	if companyID == "" {
		slog.Debug("wikidata: no entity found", "org", input.OrgName)
		return nil, nil
	}

	results, err := p.querySubsidiaries(ctx, companyID)
	if err != nil {
		slog.Warn("wikidata: subsidiary query failed", "org", input.OrgName, "error", err)
		return nil, nil
	}

	statuses, err := p.queryRelationshipStatuses(ctx, companyID, results)
	if err != nil {
		slog.Debug("wikidata: relationship qualifier query failed", "org", input.OrgName, "error", err)
	}

	findings := p.websiteFindings(input.OrgName, results, statuses)
	if c != nil {
		c.Set(cacheKey, findings)
	}

	return findings, nil
}

func cachedWikidataFindings(c *cache.APICache, cacheKey string) ([]plugins.Finding, bool) {
	if c == nil {
		return nil, false
	}
	var cached []plugins.Finding
	return cached, c.Get(cacheKey, &cached)
}

func (p *WikidataPlugin) websiteFindings(orgName string, results []sparqlBinding, statuses map[string]string) []plugins.Finding {
	fs := plugins.NewFindingSet()
	for _, r := range results {
		status := statuses[extractEntityID(r.Entity.Value)]
		if f := p.websiteFinding(orgName, r, status); f.Value != "" {
			fs.Add(f)
		}
	}
	return fs.Findings
}

func (p *WikidataPlugin) websiteFinding(orgName string, r sparqlBinding, status string) plugins.Finding {
	domain := extractDomainFromURL(r.Website.Value)
	if domain == "" {
		return plugins.Finding{}
	}

	f := plugins.Finding{
		Type:   plugins.FindingDomain,
		Value:  domain,
		Source: p.Name(),
		Data: map[string]any{
			"org":                 orgName,
			"subsidiary":          r.EntityLabel.Value,
			"wikidata_id":         extractEntityID(r.Entity.Value),
			"website":             r.Website.Value,
			"relationship":        r.Relation.Value,
			"relationship_status": relationshipStatusString(status),
			"method":              "wikidata-sparql",
		},
	}
	plugins.AddConfidence(&f, wikidataConfidence(status), wikidataConfidenceJustification(r, status))
	return f
}

// findCompanyEntity searches for a Wikidata entity matching the organization name.
// Returns the entity ID (e.g., "Q312") or empty string if not found.
func (p *WikidataPlugin) findCompanyEntity(ctx context.Context, orgName string) (string, error) {
	variants := companyNameVariants(orgName)
	for _, includeAliases := range []bool{false, true} {
		for _, variant := range variants {
			companyID, err := p.findCompanyEntityByLabel(ctx, variant, includeAliases)
			if err != nil || companyID != "" {
				return companyID, err
			}
		}
	}
	return "", nil
}

func wikidataConfidence(status string) float64 {
	return wikidataScenario(status).score
}

func wikidataConfidenceJustification(r sparqlBinding, status string) string {
	return wikidataScenario(status).justification(r.EntityLabel.Value, r.Website.Value, r.Relation.Value)
}

func wikidataScenario(status string) wikidataConfidenceScenario {
	if scenario, ok := wikidataConfidenceScenarios[status]; ok {
		return scenario
	}
	return wikidataConfidenceScenarios[wikidataRelationshipUnverified]
}

func relationshipStatusString(status string) string {
	if status == "" {
		return wikidataRelationshipUnverified
	}
	return status
}

func (p *WikidataPlugin) findCompanyEntityByLabel(ctx context.Context, orgName string, includeAliases bool) (string, error) {
	body, err := p.executeSPARQL(ctx, companyEntityQuery(orgName, includeAliases))
	if err != nil {
		return "", err
	}

	var resp sparqlResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if len(resp.Results.Bindings) == 0 {
		return "", nil
	}
	return extractEntityID(resp.Results.Bindings[0].Entity.Value), nil
}

func companyNameVariants(orgName string) []string {
	variants := []string{orgName}
	normalized := titleCaseUppercase(orgName)
	if normalized != "" && normalized != orgName {
		variants = append(variants, normalized)
	}
	return variants
}

func titleCaseUppercase(s string) string {
	if s != strings.ToUpper(s) || s == strings.ToLower(s) {
		return s
	}
	return cases.Title(language.English).String(strings.ToLower(s))
}

func companyEntityQuery(orgName string, includeAliases bool) string {
	labelMatch := fmt.Sprintf(`?entity rdfs:label "%s"@en .`, escapeSPARQL(orgName))
	if includeAliases {
		labelMatch = fmt.Sprintf(`
  {
    ?entity rdfs:label "%s"@en .
  }
  UNION
  {
    ?entity skos:altLabel "%s"@en .
  }`, escapeSPARQL(orgName), escapeSPARQL(orgName))
	}

	return fmt.Sprintf(`
SELECT ?entity WHERE {
  %s
  {
    { ?entity wdt:P31/wdt:P279* wd:Q783794 }  # instance of company
    UNION
    { ?entity wdt:P31/wdt:P279* wd:Q4830453 } # instance of business
    UNION
    { ?entity wdt:P31/wdt:P279* wd:Q43229 }   # instance of organization
  }
}
LIMIT 1
`, labelMatch)
}

// querySubsidiaries finds entities related to the company via P749 or P355.
func (p *WikidataPlugin) querySubsidiaries(ctx context.Context, companyID string) ([]sparqlBinding, error) {
	// SPARQL query for subsidiaries and their websites.
	// P749 = parent organization (inverse: entity has companyID as parent)
	// P355 = subsidiary (companyID lists entity as subsidiary)
	// P856 = official website
	query := fmt.Sprintf(`
SELECT DISTINCT ?entity ?entityLabel ?website ?relation WHERE {
  {
    SELECT DISTINCT ?entity ?relation WHERE {
      {
        ?entity wdt:P749 wd:%s .
        BIND("subsidiary (P749)" AS ?relation)
      }
      UNION
      {
        wd:%s wdt:P355 ?entity .
        BIND("subsidiary (P355)" AS ?relation)
      }
    }
    LIMIT 500
  }
  OPTIONAL { ?entity wdt:P856 ?website }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en" }
}
`, companyID, companyID)

	body, err := p.executeSPARQL(ctx, query)
	if err != nil {
		return nil, err
	}

	var resp sparqlResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return resp.Results.Bindings, nil
}

func (p *WikidataPlugin) queryRelationshipStatuses(ctx context.Context, companyID string, results []sparqlBinding) (map[string]string, error) {
	entityIDs := wikidataEntityIDs(results)
	if len(entityIDs) == 0 {
		return nil, nil
	}

	statuses := make(map[string]string)
	if err := p.enrichRelationshipStatuses(ctx, statuses, companyID, entityIDs, "P749"); err != nil {
		return statuses, err
	}
	if err := p.enrichRelationshipStatuses(ctx, statuses, companyID, entityIDs, "P355"); err != nil {
		return statuses, err
	}
	return statuses, nil
}

func wikidataEntityIDs(results []sparqlBinding) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, result := range results {
		id := extractEntityID(result.Entity.Value)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids
}

func (p *WikidataPlugin) enrichRelationshipStatuses(ctx context.Context, statuses map[string]string, companyID string, entityIDs []string, property string) error {
	body, err := p.executeSPARQL(ctx, relationshipStatusQuery(companyID, entityIDs, property))
	if err != nil {
		return err
	}

	var resp sparqlResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	for _, binding := range resp.Results.Bindings {
		id := extractEntityID(binding.Entity.Value)
		if id == "" || binding.Rank.Value == "" {
			continue
		}
		mergeRelationshipStatus(statuses, id, binding)
	}
	return nil
}

func relationshipStatusQuery(companyID string, entityIDs []string, property string) string {
	values := make([]string, 0, len(entityIDs))
	for _, id := range entityIDs {
		values = append(values, "wd:"+id)
	}

	if property == "P355" {
		return fmt.Sprintf(`
SELECT ?entity ?rank ?endTime WHERE {
  VALUES ?entity { %s }
  wd:%s p:P355 ?statement .
  ?statement ps:P355 ?entity .
  ?statement wikibase:rank ?rank .
  OPTIONAL { ?statement pq:P582 ?endTime }
}
`, strings.Join(values, " "), companyID)
	}

	return fmt.Sprintf(`
SELECT ?entity ?rank ?endTime WHERE {
  VALUES ?entity { %s }
  ?entity p:P749 ?statement .
  ?statement ps:P749 wd:%s .
  ?statement wikibase:rank ?rank .
  OPTIONAL { ?statement pq:P582 ?endTime }
}
`, strings.Join(values, " "), companyID)
}

func mergeRelationshipStatus(statuses map[string]string, id string, binding sparqlBinding) {
	if binding.EndTime.Value != "" || strings.HasSuffix(binding.Rank.Value, "DeprecatedRank") {
		statuses[id] = wikidataRelationshipEnded
		return
	}
	if statuses[id] == "" {
		statuses[id] = wikidataRelationshipCurrent
	}
}

// executeSPARQL sends a SPARQL query to the Wikidata endpoint.
func (p *WikidataPlugin) executeSPARQL(ctx context.Context, query string) ([]byte, error) {
	reqURL := p.sparqlEndpoint() + "?query=" + url.QueryEscape(query) + "&format=json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/sparql-results+json")
	req.Header.Set("User-Agent", "Pius/1.0 (https://github.com/praetorian-inc/pius)")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	const maxResponseSize = 10 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("response too large (>10MB)")
	}
	return body, nil
}

// extractEntityID extracts the Wikidata entity ID from a full URI.
// e.g., "http://www.wikidata.org/entity/Q312" -> "Q312"
func extractEntityID(uri string) string {
	if idx := strings.LastIndex(uri, "/"); idx >= 0 {
		return uri[idx+1:]
	}
	return uri
}

// extractDomainFromURL extracts the domain from a URL.
// e.g., "https://www.example.com/path" -> "example.com"
func extractDomainFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	if parsed.RawQuery != "" {
		return ""
	}

	host := parsed.Hostname()
	if host == "" {
		return ""
	}

	// Normalize to lowercase first
	host = strings.ToLower(host)

	// Remove www. prefix
	host = strings.TrimPrefix(host, "www.")

	// Basic validation
	if !strings.Contains(host, ".") {
		return ""
	}

	return host
}

// escapeSPARQL escapes special characters in SPARQL string literals.
func escapeSPARQL(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}
