package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("wikidata", func() plugins.Plugin {
		return &WikidataPlugin{
			httpClient: &http.Client{Timeout: 30 * time.Second},
			baseURL:    "",
		}
	})
}

// WikidataPlugin discovers subsidiary entities and corporate acquisitions via
// Wikidata's SPARQL endpoint. It queries for:
//   - P749 (parent organization): finds entities with target as parent
//   - P355 (subsidiary): finds entities listed as subsidiaries of target
//   - P127 (owned by): finds entities owned by target
//   - P856 (official website): extracts domains directly when available
//
// Phase 0 (independent): requires only OrgName.
// Free public endpoint — no API key required.
// Results are cached in ~/.pius/cache/ with a 24-hour TTL.
type WikidataPlugin struct {
	httpClient httpDoer         // for testing
	baseURL    string           // override for testing; default "https://query.wikidata.org/sparql"
	apiCache   *cache.APICache  // injected in tests; nil = lazy init on first Run
}

// httpDoer allows mocking HTTP requests in tests.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

func (p *WikidataPlugin) Name() string { return "wikidata" }
func (p *WikidataPlugin) Description() string {
	return "Wikidata SPARQL: discovers subsidiaries and acquisitions via structured corporate data (free, no API key)"
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
}

type sparqlValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (p *WikidataPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	if input.OrgName == "" {
		return nil, nil
	}

	// Check cache first — reduce load on Wikidata public endpoint
	cacheKey := strings.ToLower(input.OrgName)
	c := p.getCache()
	if c != nil {
		var cached []plugins.Finding
		if c.Get(cacheKey, &cached) {
			slog.Debug("wikidata: cache hit", "org", input.OrgName)
			return cached, nil
		}
	}

	// First, find the Wikidata entity ID for the organization
	companyID, err := p.findCompanyEntity(ctx, input.OrgName)
	if err != nil {
		slog.Debug("wikidata: company lookup failed", "org", input.OrgName, "error", err)
		return nil, nil
	}
	if companyID == "" {
		slog.Debug("wikidata: no entity found", "org", input.OrgName)
		return nil, nil
	}

	// Query for subsidiaries and owned entities
	results, err := p.querySubsidiaries(ctx, companyID)
	if err != nil {
		slog.Warn("wikidata: subsidiary query failed", "org", input.OrgName, "error", err)
		return nil, nil
	}

	seen := make(map[string]bool)
	var findings []plugins.Finding

	for _, r := range results {
		// Extract domain from website URL if available
		if r.Website.Value != "" {
			domain := extractDomainFromURL(r.Website.Value)
			if domain != "" && !seen[domain] {
				seen[domain] = true
				f := plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  domain,
					Source: p.Name(),
					Data: map[string]any{
						"org":           input.OrgName,
						"subsidiary":    r.EntityLabel.Value,
						"wikidata_id":   extractEntityID(r.Entity.Value),
						"website":       r.Website.Value,
						"relationship":  r.Relation.Value,
						"method":        "wikidata-sparql",
					},
				}
				// Direct website from Wikidata is high confidence
				plugins.SetConfidence(&f, plugins.ConfidenceHigh)
				findings = append(findings, f)
			}
		}

		// Also emit the subsidiary name for further enrichment
		// (other plugins like reverse-whois can resolve to domains)
		entityName := r.EntityLabel.Value
		if entityName != "" && !seen[entityName] && entityName != input.OrgName {
			seen[entityName] = true
			f := plugins.Finding{
				Type:   plugins.FindingCIDRHandle, // Internal finding for subsidiary names
				Value:  entityName,
				Source: p.Name(),
				Data: map[string]any{
					"org":          input.OrgName,
					"wikidata_id":  extractEntityID(r.Entity.Value),
					"relationship": r.Relation.Value,
					"method":       "wikidata-sparql",
				},
			}
			// Subsidiary names need verification
			plugins.SetConfidence(&f, 0.55)
			findings = append(findings, f)
		}
	}

	// Cache results for 24 hours
	if c != nil {
		c.Set(cacheKey, findings)
	}

	return findings, nil
}

// findCompanyEntity searches for a Wikidata entity matching the organization name.
// Returns the entity ID (e.g., "Q312") or empty string if not found.
func (p *WikidataPlugin) findCompanyEntity(ctx context.Context, orgName string) (string, error) {
	// SPARQL query to find company entity by label
	// Filters for instances of company (Q783794), business (Q4830453), or organization (Q43229)
	query := fmt.Sprintf(`
SELECT ?company WHERE {
  ?company rdfs:label "%s"@en .
  { ?company wdt:P31/wdt:P279* wd:Q783794 }  # instance of company
  UNION
  { ?company wdt:P31/wdt:P279* wd:Q4830453 } # instance of business
  UNION
  { ?company wdt:P31/wdt:P279* wd:Q43229 }   # instance of organization
}
LIMIT 1
`, escapeSPARQL(orgName))

	body, err := p.executeSPARQL(ctx, query)
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

// querySubsidiaries finds all entities related to the company via P749, P355, or P127.
func (p *WikidataPlugin) querySubsidiaries(ctx context.Context, companyID string) ([]sparqlBinding, error) {
	// SPARQL query for subsidiaries, owned entities, and their websites
	// P749 = parent organization (inverse: entity has companyID as parent)
	// P355 = subsidiary (companyID lists entity as subsidiary)
	// P127 = owned by (inverse: entity is owned by companyID)
	// P856 = official website
	query := fmt.Sprintf(`
SELECT DISTINCT ?entity ?entityLabel ?website ?relation WHERE {
  {
    ?entity wdt:P749 wd:%s .
    BIND("subsidiary (P749)" AS ?relation)
  }
  UNION
  {
    wd:%s wdt:P355 ?entity .
    BIND("subsidiary (P355)" AS ?relation)
  }
  UNION
  {
    ?entity wdt:P127 wd:%s .
    BIND("owned-by (P127)" AS ?relation)
  }
  OPTIONAL { ?entity wdt:P856 ?website }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en" }
}
LIMIT 500
`, companyID, companyID, companyID)

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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Read response body with size limit
	const maxResponseSize = 10 * 1024 * 1024 // 10MB
	body := make([]byte, 0, 64*1024)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
			if len(body) > maxResponseSize {
				return nil, fmt.Errorf("response too large (>10MB)")
			}
		}
		if err != nil {
			break
		}
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
