package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("gleif", func() plugins.Plugin { return NewGLEIFPlugin(client.New()) })
}

func NewGLEIFPlugin(c *client.Client) *GLEIFPlugin {
	return &GLEIFPlugin{client: c}
}

// GLEIFPlugin discovers corporate parents, subsidiaries, and siblings via the
// GLEIF LEI registry.
//
// Strategy:
//  1. Resolve OrgName to an LEI via fuzzycompletions (fallback: name search + Jaro-Winkler)
//  2. Fetch direct and ultimate parent entities
//  3. Fetch all direct subsidiaries (paginated)
//  4. Fetch siblings — children of each parent that aren't the primary entity
//
// All enrichment steps are best-effort: HTTP errors log a warning and continue.
// Phase 0 (independent): requires only OrgName.
type GLEIFPlugin struct {
	client  *client.Client
	baseURL string // override for testing; default "https://api.gleif.org/api/v1"
}

var gleifHeaders = map[string]string{
	"Accept": "application/json",
}

func (p *GLEIFPlugin) Name() string { return "gleif" }
func (p *GLEIFPlugin) Description() string {
	return "GLEIF: discovers corporate parents and subsidiaries via LEI corporate hierarchy"
}
func (p *GLEIFPlugin) Category() string { return "domain" }
func (p *GLEIFPlugin) Phase() int       { return 0 }
func (p *GLEIFPlugin) Mode() string     { return plugins.ModePassive }

func (p *GLEIFPlugin) Accepts(input plugins.Input) bool {
	return input.OrgName != ""
}

func (p *GLEIFPlugin) gleifBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.gleif.org/api/v1"
}

// ── Run ───────────────────────────────────────────────────────────────────────

func (p *GLEIFPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	if input.OrgName == "" {
		return nil, nil
	}

	primary, err := p.resolveEntity(ctx, input.OrgName)
	if err != nil {
		log.Printf("[gleif] resolve failed for %q: %v", input.OrgName, err)
		return nil, nil
	}
	if primary == nil {
		return nil, nil
	}

	primaryName := primary.Attributes.Entity.LegalName.Name
	fs := plugins.NewFindingSet()

	parentLEIs := p.enrichParents(ctx, primary, primaryName, fs)

	if err := p.enrichChildren(ctx, primary.ID, "", primaryName, "subsidiary", fs); err != nil {
		return fs.Findings, err
	}
	for _, parentLEI := range parentLEIs {
		if err := p.enrichChildren(ctx, parentLEI, primary.ID, primaryName, "sibling", fs); err != nil {
			return fs.Findings, err
		}
	}

	return fs.Findings, nil
}

// enrichParents fetches direct and ultimate parent entities, emits findings for
// each, and returns their LEIs for sibling discovery. Best-effort: errors log
// and continue.
func (p *GLEIFPlugin) enrichParents(ctx context.Context, primary *leiRecord, primaryName string, fs *plugins.FindingSet) []string {
	fullRecord, err := p.getRecord(ctx, primary.ID)
	if err != nil {
		log.Printf("[gleif] get record failed for LEI %s: %v", primary.ID, err)
		fullRecord = primary
	}
	if !hasParent(fullRecord) {
		return nil
	}

	directLEI, err := p.getDirectParent(ctx, primary.ID)
	if err != nil {
		log.Printf("[gleif] direct parent failed for %s: %v", primary.ID, err)
		return nil
	}
	if directLEI == "" {
		return nil
	}

	parentLEIs := []string{directLEI}
	p.emitRelated(ctx, directLEI, "direct-parent", primaryName, fs)

	ultimateLEI, err := p.getUltimateParent(ctx, primary.ID)
	if err != nil {
		log.Printf("[gleif] ultimate parent failed for %s: %v", primary.ID, err)
	} else if ultimateLEI != "" && ultimateLEI != directLEI {
		parentLEIs = append(parentLEIs, ultimateLEI)
		p.emitRelated(ctx, ultimateLEI, "ultimate-parent", primaryName, fs)
	}

	return parentLEIs
}

// emitRelated fetches a single LEI record and emits domain + preseed findings.
func (p *GLEIFPlugin) emitRelated(ctx context.Context, lei, relation, primaryName string, fs *plugins.FindingSet) {
	record, err := p.getRecord(ctx, lei)
	if err != nil {
		log.Printf("[gleif] %s record failed for %s: %v", relation, lei, err)
		return
	}
	fs.Add(recordToFinding(*record, relation, plugins.ConfidenceHigh))
	fs.Add(recordToPreseed(*record, relation, primaryName, plugins.ConfidenceHigh))
}

// enrichChildren fetches children of lei, emits findings for each (skipping
// excludeLEI), and returns a context error if the context is cancelled.
func (p *GLEIFPlugin) enrichChildren(ctx context.Context, lei, excludeLEI, primaryName, relation string, fs *plugins.FindingSet) error {
	children, err := p.getChildren(ctx, lei)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		log.Printf("[gleif] %s fetch from %s failed: %v", relation, lei, err)
		return nil
	}
	for _, child := range children {
		if child.ID == excludeLEI || child.Attributes.Entity.LegalName.Name == "" {
			continue
		}
		fs.Add(recordToFinding(child, relation, plugins.ConfidenceHigh))
		fs.Add(recordToPreseed(child, relation, primaryName, plugins.ConfidenceHigh))
	}
	return nil
}

// resolveEntity resolves a company name to a GLEIF entity via fuzzycompletions.
// Returns nil when GLEIF has no match.
func (p *GLEIFPlugin) resolveEntity(ctx context.Context, name string) (*leiRecord, error) {
	lei, err := p.fuzzyResolve(ctx, name)
	if err != nil {
		return nil, err
	}
	if lei == "" {
		return nil, nil
	}
	return p.getRecord(ctx, lei)
}

// ── API methods ───────────────────────────────────────────────────────────────

// fuzzyResolve uses GLEIF's fuzzycompletions endpoint to resolve a company name
// to an LEI. Returns the best match's LEI, or "" if no match.
func (p *GLEIFPlugin) fuzzyResolve(ctx context.Context, name string) (string, error) {
	u := fmt.Sprintf("%s/fuzzycompletions?field=entity.legalName&q=%s",
		p.gleifBase(), url.QueryEscape(name))
	body, err := p.client.GetWithHeaders(ctx, u, gleifHeaders)
	if err != nil {
		return "", fmt.Errorf("gleif: fuzzy resolve: %w", err)
	}
	var resp fuzzyCompletionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("gleif: fuzzy resolve parse: %w", err)
	}
	if len(resp.Data) == 0 {
		return "", nil
	}
	return resp.Data[0].Relationships.LEIRecords.Data.ID, nil
}

func (p *GLEIFPlugin) getRecord(ctx context.Context, lei string) (*leiRecord, error) {
	u := fmt.Sprintf("%s/lei-records/%s", p.gleifBase(), url.PathEscape(lei))
	body, err := p.client.GetWithHeaders(ctx, u, gleifHeaders)
	if err != nil {
		return nil, fmt.Errorf("gleif: get record %s: %w", lei, err)
	}
	var resp struct {
		Data leiRecord `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("gleif: get record parse: %w", err)
	}
	return &resp.Data, nil
}

func (p *GLEIFPlugin) getDirectParent(ctx context.Context, lei string) (string, error) {
	u := fmt.Sprintf("%s/lei-records/%s/direct-parent-relationship", p.gleifBase(), url.PathEscape(lei))
	body, err := p.client.GetWithHeaders(ctx, u, gleifHeaders)
	if err != nil {
		return "", fmt.Errorf("gleif: direct parent of %s: %w", lei, err)
	}
	var resp leiRelationshipResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("gleif: direct parent parse: %w", err)
	}
	return resp.Data.Attributes.Relationship.EndNode.ID, nil
}

func (p *GLEIFPlugin) getUltimateParent(ctx context.Context, lei string) (string, error) {
	u := fmt.Sprintf("%s/lei-records/%s/ultimate-parent-relationship", p.gleifBase(), url.PathEscape(lei))
	body, err := p.client.GetWithHeaders(ctx, u, gleifHeaders)
	if err != nil {
		return "", fmt.Errorf("gleif: ultimate parent of %s: %w", lei, err)
	}
	var resp leiRelationshipResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("gleif: ultimate parent parse: %w", err)
	}
	return resp.Data.Attributes.Relationship.EndNode.ID, nil
}

func (p *GLEIFPlugin) getChildren(ctx context.Context, lei string) ([]leiRecord, error) {
	var all []leiRecord
	for page := 1; ; page++ {
		u := fmt.Sprintf("%s/lei-records/%s/direct-children?page[size]=200&page[number]=%d",
			p.gleifBase(), url.PathEscape(lei), page)
		body, err := p.client.GetWithHeaders(ctx, u, gleifHeaders)
		if err != nil {
			return all, fmt.Errorf("gleif: children page %d of %s: %w", page, lei, err)
		}
		var resp leiChildrenResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return all, fmt.Errorf("gleif: children parse: %w", err)
		}
		all = append(all, resp.Data...)
		if resp.Meta.Pagination.CurrentPage >= resp.Meta.Pagination.LastPage {
			break
		}
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
	}
	return all, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// hasParent reports whether the record has a registered direct parent LEI.
func hasParent(record *leiRecord) bool {
	_, ok := record.Relationships.DirectParent.Links["relationship-record"]
	return ok
}

// recordToFinding converts a GLEIF LEI record to a Pius Finding.
func recordToFinding(record leiRecord, relationshipType string, confidence float64) plugins.Finding {
	f := plugins.Finding{
		Type:   plugins.FindingDomain,
		Value:  record.Attributes.Entity.LegalName.Name,
		Source: "gleif",
		Data: map[string]any{
			"lei":              record.ID,
			"legalName":        record.Attributes.Entity.LegalName.Name,
			"jurisdiction":     record.Attributes.Entity.Jurisdiction,
			"relationshipType": relationshipType,
		},
	}
	plugins.SetConfidence(&f, confidence)
	return f
}

// recordToPreseed converts a GLEIF LEI record to a FindingPreseed.
// relationshipType is the corporate relationship (subsidiary, sibling,
// direct-parent, ultimate-parent). corporateParent is the legal name of the
// entity this record was discovered through (empty for parent findings).
func recordToPreseed(record leiRecord, relationshipType, corporateParent string, confidence float64) plugins.Finding {
	f := plugins.Finding{
		Type:   plugins.FindingPreseed,
		Value:  record.Attributes.Entity.LegalName.Name,
		Source: "gleif",
		Data: map[string]any{
			"preseed_type":           "whois+company",
			"preseed_title":          record.Attributes.Entity.LegalName.Name,
			"lei":                    record.ID,
			"jurisdiction":           record.Attributes.Entity.Jurisdiction,
			"corporate_relationship": relationshipType,
			"corporate_parent":       corporateParent,
		},
	}
	plugins.SetConfidence(&f, confidence)
	return f
}

// ── API response types ─────────────────────────────────────────────────────────

type leiRecord struct {
	ID            string           `json:"id"`
	Attributes    leiAttributes    `json:"attributes"`
	Relationships leiRelationships `json:"relationships"`
}

type leiAttributes struct {
	Entity leiEntity `json:"entity"`
}

type leiEntity struct {
	LegalName    leiLegalName `json:"legalName"`
	Jurisdiction string       `json:"jurisdiction"`
	Status       string       `json:"status"`
}

type leiLegalName struct {
	Name string `json:"name"`
}

type leiRelationships struct {
	DirectParent leiRelationshipEntry `json:"direct-parent"`
}

type leiRelationshipEntry struct {
	Links map[string]string `json:"links"`
}

type leiMeta struct {
	Pagination leiPagination `json:"pagination"`
}

type leiPagination struct {
	CurrentPage int `json:"currentPage"`
	PerPage     int `json:"perPage"`
	From        int `json:"from"`
	To          int `json:"to"`
	Total       int `json:"total"`
	LastPage    int `json:"lastPage"`
}

type leiRelationshipResponse struct {
	Data leiRelationshipData `json:"data"`
}

type leiRelationshipData struct {
	Attributes leiRelationshipAttributes `json:"attributes"`
}

type leiRelationshipAttributes struct {
	Relationship leiRelationshipNodes `json:"relationship"`
}

type leiRelationshipNodes struct {
	StartNode leiNode `json:"startNode"`
	EndNode   leiNode `json:"endNode"`
}

type leiNode struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type leiChildrenResponse struct {
	Data []leiRecord `json:"data"`
	Meta leiMeta     `json:"meta"`
}

type fuzzyCompletionResponse struct {
	Data []struct {
		Relationships struct {
			LEIRecords struct {
				Data struct {
					ID string `json:"id"`
				} `json:"data"`
			} `json:"lei-records"`
		} `json:"relationships"`
	} `json:"data"`
}
