package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("crunchbase", func() plugins.Plugin {
		return &CrunchbasePlugin{client: client.New()}
	})
}

// CrunchbasePlugin discovers domains associated with an organization via the
// Crunchbase API. It resolves the org name to a Crunchbase permalink, then
// fetches the organization's website URL and acquiree_acquisitions to discover
// domains from acquired companies.
//
// Phase 0 (independent): runs concurrently, requires only OrgName.
// Requires CRUNCHBASE_API_KEY environment variable.
// Results are cached in ~/.pius/cache/ with a 24-hour TTL to conserve API credits.
type CrunchbasePlugin struct {
	client   *client.Client
	baseURL  string            // override for testing; empty means use real Crunchbase API
	apiCache *cache.APICache   // injected in tests; nil = lazy init on first Run
}

func (p *CrunchbasePlugin) crunchbaseBaseURL() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.crunchbase.com/api/v4"
}

// getCache returns the APICache, initializing it lazily on first use.
// Returns nil if the cache directory cannot be created (non-fatal).
func (p *CrunchbasePlugin) getCache() *cache.APICache {
	if p.apiCache != nil {
		return p.apiCache
	}
	c, err := cache.NewAPI("", "crunchbase")
	if err != nil {
		log.Printf("[crunchbase] cache init failed: %v", err)
		return nil
	}
	p.apiCache = c
	return c
}

func (p *CrunchbasePlugin) Name() string { return "crunchbase" }
func (p *CrunchbasePlugin) Description() string {
	return "Crunchbase: discovers org domains via organization API (requires CRUNCHBASE_API_KEY)"
}
func (p *CrunchbasePlugin) Category() string { return "domain" }
func (p *CrunchbasePlugin) Phase() int       { return 0 }
func (p *CrunchbasePlugin) Mode() string     { return plugins.ModePassive }

func (p *CrunchbasePlugin) Accepts(input plugins.Input) bool {
	return input.OrgName != "" && os.Getenv("CRUNCHBASE_API_KEY") != ""
}

// cbIdentifier represents Crunchbase entity identifiers
type cbIdentifier struct {
	Permalink  string `json:"permalink"`
	EntityType string `json:"entity_def_id"`
}

// cbAutocompleteResponse mirrors the Crunchbase /autocompletes response
type cbAutocompleteResponse struct {
	Entities []cbAutocompleteEntity `json:"entities"`
}

type cbAutocompleteEntity struct {
	Identifier cbIdentifier `json:"identifier"`
}

// cbEntityResponse mirrors the Crunchbase /entities/organizations/{permalink} response
type cbEntityResponse struct {
	Properties cbOrgProperties `json:"properties"`
	Cards      cbCards         `json:"cards,omitempty"`
}

type cbOrgProperties struct {
	Identifier       cbIdentifier `json:"identifier"`
	ShortDescription *string      `json:"short_description,omitempty"`
	WebsiteURL       *string      `json:"website_url,omitempty"`
}

type cbCards struct {
	AcquireeAcquisitions []cbAcquisitionCard `json:"acquiree_acquisitions,omitempty"`
}

type cbAcquisitionCard struct {
	Identifier   cbIdentifier  `json:"identifier"`
	AcquireeName *cbIdentifier `json:"acquiree_identifier,omitempty"`
}

func (p *CrunchbasePlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("CRUNCHBASE_API_KEY")
	cacheKey := strings.ToLower(input.OrgName + "|" + input.Domain)

	// Check cache first — Crunchbase charges per request
	c := p.getCache()
	if c != nil {
		var cached []plugins.Finding
		if c.Get(cacheKey, &cached) {
			return cached, nil
		}
	}

	// Step 1: Resolve org name to permalink via autocomplete
	permalink, err := p.autocomplete(ctx, input.OrgName, apiKey)
	if err != nil {
		log.Printf("[crunchbase] autocomplete failed for %q: %v", input.OrgName, err)
		return nil, nil // graceful degradation
	}
	if permalink == "" {
		log.Printf("[crunchbase] no autocomplete match for %q", input.OrgName)
		return nil, nil
	}

	// Step 2: Fetch org entity (website + acquisitions)
	orgData, err := p.fetchEntity(ctx, permalink, apiKey)
	if err != nil {
		log.Printf("[crunchbase] entity fetch failed for %q: %v", permalink, err)
		return nil, nil
	}

	findings := p.extractFindings(input.OrgName, orgData)

	// Step 3: Fetch acquired companies
	for _, acq := range orgData.Cards.AcquireeAcquisitions {
		if ctx.Err() != nil {
			break
		}

		if acq.AcquireeName == nil || acq.AcquireeName.Permalink == "" {
			continue
		}

		acquireeData, err := p.fetchEntity(ctx, acq.AcquireeName.Permalink, apiKey)
		if err != nil {
			log.Printf("[crunchbase] acquiree fetch failed for %q: %v", acq.AcquireeName.Permalink, err)
			continue // skip failed acquisitions
		}

		acquireeFindings := p.extractFindings(input.OrgName, acquireeData)
		findings = append(findings, acquireeFindings...)
	}

	// Deduplicate domains
	findings = p.deduplicate(findings)

	// Score confidence: domain-based queries are precise; org-name queries
	// may return data for a similarly-named company.
	confidence := 0.85 // ?domain= query
	if input.Domain == "" {
		confidence = 0.70 // ?organization_name= query — org name is ambiguous
	}
	for i := range findings {
		plugins.SetConfidence(&findings[i], confidence)
	}

	if c != nil {
		c.Set(cacheKey, findings)
	}

	return findings, nil
}

func (p *CrunchbasePlugin) autocomplete(ctx context.Context, orgName, apiKey string) (string, error) {
	base := p.crunchbaseBaseURL()
	apiURL := fmt.Sprintf("%s/autocompletes?query=%s&collection_ids=organizations&limit=1&user_key=%s",
		base, url.QueryEscape(orgName), url.QueryEscape(apiKey))

	body, err := p.client.Get(ctx, apiURL)
	if err != nil {
		return "", err
	}

	var resp cbAutocompleteResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parse autocomplete response: %w", err)
	}

	if len(resp.Entities) == 0 {
		return "", nil
	}

	return resp.Entities[0].Identifier.Permalink, nil
}

func (p *CrunchbasePlugin) fetchEntity(ctx context.Context, permalink, apiKey string) (*cbEntityResponse, error) {
	base := p.crunchbaseBaseURL()
	apiURL := fmt.Sprintf("%s/entities/organizations/%s?field_ids=short_description,website_url&card_ids=acquiree_acquisitions&user_key=%s",
		base, url.PathEscape(permalink), url.QueryEscape(apiKey))

	body, err := p.client.Get(ctx, apiURL)
	if err != nil {
		return nil, err
	}

	var resp cbEntityResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse entity response: %w", err)
	}

	return &resp, nil
}

func (p *CrunchbasePlugin) extractFindings(orgName string, data *cbEntityResponse) []plugins.Finding {
	var findings []plugins.Finding

	if data.Properties.WebsiteURL != nil && *data.Properties.WebsiteURL != "" {
		domain := stripScheme(*data.Properties.WebsiteURL)
		if domain != "" {
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  domain,
				Source: "crunchbase",
				Data: map[string]any{
					"org":       orgName,
					"permalink": data.Properties.Identifier.Permalink,
				},
			})
		}
	}

	return findings
}

func (p *CrunchbasePlugin) deduplicate(findings []plugins.Finding) []plugins.Finding {
	seen := make(map[string]bool)
	var deduped []plugins.Finding

	for _, f := range findings {
		if !seen[f.Value] {
			seen[f.Value] = true
			deduped = append(deduped, f)
		}
	}

	return deduped
}
