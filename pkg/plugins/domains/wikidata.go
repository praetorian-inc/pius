package domains

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("wikidata", func() plugins.Plugin {
		return &WikidataPlugin{
			httpClient: &http.Client{Timeout: 30 * time.Second},
			now:        time.Now,
		}
	})
}

const (
	wikidataEndpoint        = "https://query.wikidata.org/sparql"
	wikidataEntityEndpoint  = "https://www.wikidata.org/w/api.php"
	wikidataBatchSize       = 50
	wikidataMaxCandidates   = 500
	wikidataMaxResponse     = 10 * 1024 * 1024
	wikidataMaxAttempts     = 3
	wikidataOtherOwnerScore = 0
	wikidataEndedScore      = 10
	wikidataBaseScore       = 40
	wikidataMaxScore        = 60
	wikidataReferenceScore  = 5
	wikidataReciprocalScore = 10
)

const (
	wikidataMatchLabel        = "label"
	wikidataMatchOfficialName = "official name"
	wikidataMatchAlias        = "alias"
)

const (
	wdPropertyStatedIn        = "P248"
	wdPropertyOwner           = "P127"
	wdPropertyOfficialName    = "P1448"
	wdPropertyStartTime       = "P580"
	wdPropertyEndTime         = "P582"
	wdPropertyReferenceURL    = "P854"
	wdPropertyOfficialWebsite = "P856"
	wdPropertySubsidiary      = "P355"
	wdPropertyParent          = "P749"
)

type WikidataPlugin struct {
	httpClient httpDoer
	baseURL    string
	entityURL  string
	apiCache   *cache.APICache
	noCache    bool
	now        func() time.Time
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewWikidataPlugin(httpClient *http.Client) *WikidataPlugin {
	return &WikidataPlugin{
		httpClient: httpClient,
		noCache:    true,
		now:        time.Now,
	}
}

func (p *WikidataPlugin) Name() string { return "wikidata" }

func (p *WikidataPlugin) Description() string {
	return "Wikidata: discovers reviewable subsidiary websites from dated corporate relationship claims"
}

func (p *WikidataPlugin) Category() string { return "domain" }
func (p *WikidataPlugin) Phase() int       { return 0 }
func (p *WikidataPlugin) Mode() string     { return plugins.ModePassive }

func (p *WikidataPlugin) Accepts(input plugins.Input) bool {
	return strings.TrimSpace(input.OrgName) != ""
}

// Run resolves the target, discovers related entities, and then evaluates each
// candidate from its complete Wikidata statements. One failed discovery path
// may reduce recall, but incomplete evidence never produces a finding.
func (p *WikidataPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	orgName := strings.TrimSpace(input.OrgName)
	if orgName == "" {
		return nil, nil
	}

	cacheKey := wikidataCacheKey(orgName, input.Domain)
	apiCache := p.getCache()
	if findings, ok := cachedWikidataFindings(apiCache, cacheKey); ok {
		return findings, nil
	}

	target, err := p.resolveCompany(ctx, orgName, input.Domain)
	if err != nil {
		slog.Debug("wikidata: company lookup failed", "org", orgName, "error", err)
		return nil, nil
	}
	if target.id == "" {
		slog.Debug("wikidata: no unambiguous company found", "org", orgName)
		return nil, nil
	}

	evidence, err := p.collectEvidence(ctx, target.id)
	if err != nil {
		slog.Warn("wikidata: evidence collection failed", "org", orgName, "error", err)
		return nil, nil
	}

	findings := p.buildFindings(orgName, target, evidence)
	if apiCache != nil {
		apiCache.Set(cacheKey, findings)
	}
	return findings, nil
}

func (p *WikidataPlugin) resolveCompany(
	ctx context.Context,
	orgName string,
	knownDomain string,
) (companyResolution, error) {
	variants := companyNameVariants(orgName)
	candidateIDs, err := p.searchEntityIDs(ctx, variants)
	if err != nil || len(candidateIDs) == 0 {
		return companyResolution{}, err
	}

	documents, err := p.fetchEntities(ctx, candidateIDs, "labels|aliases|claims")
	if err != nil {
		return companyResolution{}, err
	}
	return selectCompany(documents, variants, knownDomain), nil
}

func (p *WikidataPlugin) collectEvidence(
	ctx context.Context,
	targetID string,
) ([]entityEvidence, error) {
	entityIDs, err := p.discoverEntityIDs(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if len(entityIDs) == 0 {
		return []entityEvidence{}, nil
	}

	documentIDs := append([]string{targetID}, entityIDs...)
	documents, err := p.fetchEntities(ctx, strutil.Unique(documentIDs), "labels|claims")
	if err != nil {
		return nil, err
	}

	relatedIDs := relatedEntityIDs(documents, entityIDs, targetID)
	missingIDs := missingEntityIDs(documents, relatedIDs)
	if len(missingIDs) > 0 {
		labels, err := p.fetchEntities(ctx, missingIDs, "labels")
		if err != nil {
			return nil, err
		}
		for entityID, document := range labels {
			documents[entityID] = document
		}
	}
	return buildEntityEvidence(targetID, entityIDs, documents), nil
}

func (p *WikidataPlugin) buildFindings(
	orgName string,
	target companyResolution,
	entities []entityEvidence,
) []plugins.Finding {
	bestByDomain := make(map[string]plugins.Finding)
	for _, entity := range entities {
		assessment := assessRelationship(entity, target.id, p.currentTime())
		if !assessment.hasRelationship {
			continue
		}

		for _, website := range bestWebsitesByDomain(entity.websites, p.currentTime()) {
			finding := p.newFinding(orgName, target, entity, assessment, website)
			current, exists := bestByDomain[finding.Value]
			if !exists || betterWikidataFinding(finding, current) {
				bestByDomain[finding.Value] = finding
			}
		}
	}

	domains := make([]string, 0, len(bestByDomain))
	for domain := range bestByDomain {
		domains = append(domains, domain)
	}
	slices.Sort(domains)

	findings := make([]plugins.Finding, 0, len(domains))
	for _, domain := range domains {
		findings = append(findings, bestByDomain[domain])
	}
	return findings
}

func (p *WikidataPlugin) newFinding(
	orgName string,
	target companyResolution,
	entity entityEvidence,
	assessment relationshipAssessment,
	website websiteClaim,
) plugins.Finding {
	finding := plugins.Finding{
		Type:   plugins.FindingDomain,
		Value:  website.domain,
		Source: p.Name(),
		Data: map[string]any{
			"method":                  "wikidata",
			"org":                     orgName,
			"target_wikidata_id":      target.id,
			"target_match":            target.matchKind,
			"subsidiary":              entity.name,
			"wikidata_id":             entity.id,
			"website":                 website.url,
			"relationship_properties": assessment.details,
			"relationship_status":     assessment.status,
		},
	}

	score := assessment.score
	if assessment.status == "active" || assessment.status == "open_ended" {
		score = min(score+websiteReferenceScore(website), wikidataMaxScore)
	}
	plugins.AddConfidence(
		&finding,
		score,
		wikidataJustification(orgName, target.id, entity, assessment, website),
		plugins.Reference{Label: "Target Wikidata item", URL: "https://www.wikidata.org/wiki/" + target.id},
		plugins.Reference{Label: "Subsidiary Wikidata item", URL: "https://www.wikidata.org/wiki/" + entity.id},
	)
	return finding
}

func (p *WikidataPlugin) currentTime() time.Time {
	if p.now != nil {
		return p.now().UTC()
	}
	return time.Now().UTC()
}

func (p *WikidataPlugin) sparqlEndpoint() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return wikidataEndpoint
}

func (p *WikidataPlugin) getCache() *cache.APICache {
	if p.noCache {
		return nil
	}
	if p.apiCache != nil {
		return p.apiCache
	}

	apiCache, err := cache.NewAPI("", "wikidata")
	if err != nil {
		slog.Debug("wikidata: cache init failed", "error", err)
		return nil
	}
	p.apiCache = apiCache
	return apiCache
}

func wikidataCacheKey(orgName, domain string) string {
	return strings.ToLower(strings.TrimSpace(orgName)) + "|" + normalizeKnownDomain(domain)
}

func cachedWikidataFindings(apiCache *cache.APICache, cacheKey string) ([]plugins.Finding, bool) {
	if apiCache == nil {
		return nil, false
	}
	findings := []plugins.Finding{}
	if !apiCache.Get(cacheKey, &findings) {
		return nil, false
	}
	return findings, true
}

type sparqlValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type sparqlResponse[T any] struct {
	Results struct {
		Bindings []T `json:"bindings"`
	} `json:"results"`
}

type entitySearchResponse struct {
	Search []entitySearchResult `json:"search"`
}

type entitySearchResult struct {
	ID string `json:"id"`
}

type companyCandidate struct {
	id         string
	matchKind  string
	matchScore int
}

type companyResolution struct {
	id        string
	matchKind string
}

type discoveryBinding struct {
	Entity sparqlValue `json:"entity"`
}

type entityResponse struct {
	Entities map[string]entityDocument `json:"entities"`
}

type entityDocument struct {
	ID      string                       `json:"id"`
	Labels  map[string]entityLabel       `json:"labels"`
	Aliases map[string][]entityLabel     `json:"aliases"`
	Claims  map[string][]entityStatement `json:"claims"`
}

type entityLabel struct {
	Value string `json:"value"`
}

type entityStatement struct {
	ID         string                  `json:"id"`
	Rank       string                  `json:"rank"`
	MainSnak   entitySnak              `json:"mainsnak"`
	Qualifiers map[string][]entitySnak `json:"qualifiers"`
	References []entityReference       `json:"references"`
}

type entityReference struct {
	Snaks map[string][]entitySnak `json:"snaks"`
}

type entitySnak struct {
	DataValue entityDataValue `json:"datavalue"`
}

type entityDataValue struct {
	Value json.RawMessage `json:"value"`
}

type entityIDValue struct {
	ID string `json:"id"`
}

type entityTimeValue struct {
	Time string `json:"time"`
}

type datedClaim struct {
	statement  string
	rank       string
	start      time.Time
	end        time.Time
	referenced bool
}

type relationshipClaim struct {
	datedClaim
	property string
}

type affiliationClaim struct {
	datedClaim
	property string
	entityID string
	name     string
}

type websiteClaim struct {
	datedClaim
	url    string
	domain string
}

type entityEvidence struct {
	id            string
	name          string
	relationships []relationshipClaim
	affiliations  []affiliationClaim
	websites      []websiteClaim
}

type relationshipAssessment struct {
	score           int
	status          string
	details         []string
	note            string
	referenced      bool
	reciprocal      bool
	hasRelationship bool
}
