package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/lib/strutil"
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
//  1. Resolve OrgName to an LEI via fuzzycompletions
//  2. Fetch direct and ultimate parent entities
//  3. Fetch all direct subsidiaries (paginated)
//  4. Fetch siblings — children of each parent that aren't the primary entity
//
// All enrichment steps are best-effort: HTTP errors log a warning and continue.
// Phase 0 (independent): requires only OrgName.
type GLEIFPlugin struct {
	client  *client.Client
	baseURL string // override for testing; default "https://api.gleif.org/api/v1"

	// Per-run enrichment state, set in Run().
	orgName       string
	primaryName   string
	primaryLEI    string
	candidateRank int
}

var gleifHeaders = map[string]string{
	"Accept": "application/json",
}

type gleifParent struct {
	lei          string
	relationship string
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

	primary, candidateRank, err := p.resolveEntity(ctx, input.OrgName)
	if err != nil {
		log.Printf("[gleif] resolve failed for %q: %v", input.OrgName, err)
		return nil, nil
	}
	if primary == nil {
		return nil, nil
	}

	p.orgName = input.OrgName
	p.primaryName = primary.Attributes.Entity.LegalName.Name
	p.primaryLEI = primary.ID
	p.candidateRank = candidateRank

	var findings []plugins.Finding

	parentLEIs := p.enrichParents(ctx, primary, &findings)

	if err := p.enrichChildren(ctx, primary.ID, "", "subsidiary", "direct-parent", &findings); err != nil {
		return uniqueFindings(findings), err
	}
	for _, parent := range parentLEIs {
		if err := p.enrichChildren(ctx, parent.lei, primary.ID, "sibling", parent.relationship, &findings); err != nil {
			return uniqueFindings(findings), err
		}
	}

	return uniqueFindings(findings), nil
}

// enrichParents fetches direct and ultimate parent entities, emits findings for
// each, and returns their LEIs for sibling discovery. Best-effort: errors log
// and continue.
func (p *GLEIFPlugin) enrichParents(ctx context.Context, primary *leiRecord, findings *[]plugins.Finding) []gleifParent {
	if !hasParent(primary) {
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

	parents := []gleifParent{{lei: directLEI, relationship: "direct-parent"}}
	p.emitRelated(ctx, directLEI, "direct-parent", findings)

	ultimateLEI, err := p.getUltimateParent(ctx, primary.ID)
	if err != nil {
		log.Printf("[gleif] ultimate parent failed for %s: %v", primary.ID, err)
	} else if ultimateLEI != "" && ultimateLEI != directLEI {
		parents = append(parents, gleifParent{lei: ultimateLEI, relationship: "ultimate-parent"})
		p.emitRelated(ctx, ultimateLEI, "ultimate-parent", findings)
	}

	return parents
}

// emitRelated fetches a single LEI record and emits a preseed finding.
func (p *GLEIFPlugin) emitRelated(ctx context.Context, lei, relation string, findings *[]plugins.Finding) {
	record, err := p.getRecord(ctx, lei)
	if err != nil {
		log.Printf("[gleif] %s record failed for %s: %v", relation, lei, err)
		return
	}
	finding := p.recordToPreseed(*record, relation, relation)
	if finding.Value != "" {
		*findings = append(*findings, finding)
	}
}

// enrichChildren fetches children of lei, emits findings for each (skipping
// excludeLEI), and returns a context error if the context is cancelled.
func (p *GLEIFPlugin) enrichChildren(ctx context.Context, lei, excludeLEI, relation, primaryRelationship string, findings *[]plugins.Finding) error {
	children, err := p.getChildren(ctx, lei)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	for _, child := range children {
		if child.ID == excludeLEI || child.Attributes.Entity.LegalName.Name == "" {
			continue
		}
		*findings = append(*findings, p.recordToPreseed(child, relation, primaryRelationship))
	}
	return nil
}

func uniqueFindings(findings []plugins.Finding) []plugins.Finding {
	return strutil.UniqueFunc(findings, func(f plugins.Finding) [2]string {
		return [2]string{string(f.Type), f.Value}
	})
}

// resolveEntity resolves a company name to a GLEIF entity with corporate
// hierarchy. Fuzzycompletions may return a leaf entity first (e.g. a regional
// subsidiary with no children), so we try candidates until we find one that
// has a parent or children — those are the ones worth traversing.
// Returns the record and the 0-based candidate index (for confidence scoring).
func (p *GLEIFPlugin) resolveEntity(ctx context.Context, name string) (*leiRecord, int, error) {
	leis, err := p.fuzzyResolve(ctx, name)
	if err != nil {
		return nil, 0, err
	}

	for i, lei := range leis {
		record, err := p.getRecord(ctx, lei)
		if err != nil {
			log.Printf("[gleif] candidate %s failed: %v", lei, err)
			continue
		}
		if record.Attributes.Entity.Status != "ACTIVE" {
			continue
		}
		if hasParent(record) || p.hasChildren(ctx, lei) {
			return record, i, nil
		}
	}
	return nil, 0, nil
}

// ── API methods ───────────────────────────────────────────────────────────────

// hasChildren reports whether the entity has any direct children in GLEIF.
func (p *GLEIFPlugin) hasChildren(ctx context.Context, lei string) bool {
	u := fmt.Sprintf("%s/lei-records/%s/direct-children?page[size]=1",
		p.gleifBase(), url.PathEscape(lei))
	body, err := p.client.GetWithHeaders(ctx, u, gleifHeaders)
	if err != nil {
		return false
	}
	var resp leiChildrenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return false
	}
	return resp.Meta.Pagination.Total > 0
}

// fuzzyResolve uses GLEIF's fuzzycompletions endpoint to resolve a company name
// to candidate LEIs, ordered by match quality.
func (p *GLEIFPlugin) fuzzyResolve(ctx context.Context, name string) ([]string, error) {
	u := fmt.Sprintf("%s/fuzzycompletions?field=entity.legalName&q=%s",
		p.gleifBase(), url.QueryEscape(name))
	body, err := p.client.GetWithHeaders(ctx, u, gleifHeaders)
	if err != nil {
		return nil, fmt.Errorf("gleif: fuzzy resolve: %w", err)
	}
	var resp fuzzyCompletionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("gleif: fuzzy resolve parse: %w", err)
	}
	var leis []string
	for _, d := range resp.Data {
		if lei := d.Relationships.LEIRecords.Data.ID; lei != "" {
			leis = append(leis, lei)
		}
	}
	return strutil.Unique(leis), nil
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

// recordToPreseed converts a GLEIF LEI record to a FindingPreseed with
// decomposed confidence signals. Reads enrichment state from p.
func (p *GLEIFPlugin) recordToPreseed(record leiRecord, relation, primaryRelationship string) plugins.Finding {
	name := record.Attributes.Entity.LegalName.Name
	f := plugins.Finding{
		Type:   plugins.FindingPreseed,
		Value:  name,
		Source: "gleif",
		Data: map[string]any{
			"preseed_type":           "whois+company",
			"preseed_title":          name,
			"lei":                    record.ID,
			"jurisdiction":           record.Attributes.Entity.Jurisdiction,
			"corporate_relationship": relation,
			"corporate_parent":       p.primaryName,
		},
	}

	// Signal 1: Name resolution quality — how well fuzzycompletions matched.
	resolutionURL := fmt.Sprintf("%s/fuzzycompletions?field=entity.legalName&q=%s",
		p.gleifBase(), url.QueryEscape(p.orgName))
	resolutionReferences := []plugins.LabeledURLReferenceData{{Label: "GLEIF resolution request", URL: resolutionURL}}
	if recordURL := p.gleifRecordURL(p.primaryLEI); recordURL != "" {
		resolutionReferences = append(resolutionReferences, plugins.LabeledURLReferenceData{Label: "Resolved GLEIF entity", URL: recordURL})
	}
	if p.candidateRank == 0 {
		plugins.AddConfidence(&f, 15,
			fmt.Sprintf("Resolved %q to GLEIF entity %q (top candidate)", p.orgName, p.primaryName),
			plugins.URLCollectionReference("GLEIF resolution records", resolutionReferences))
	} else {
		plugins.AddConfidence(&f, 10,
			fmt.Sprintf("Resolved %q to GLEIF entity %q (candidate #%d, skipped %d leaf entities)",
				p.orgName, p.primaryName, p.candidateRank+1, p.candidateRank),
			plugins.URLCollectionReference("GLEIF resolution records", resolutionReferences))
	}

	// Signal 2: Relationship provenance. A top-ranked resolution plus a
	// registered direct relationship reaches the high-confidence threshold;
	// indirect siblings and later resolution candidates remain reviewable.
	references := p.relationshipReferences(record.ID, relation, primaryRelationship)
	switch relation {
	case "direct-parent":
		plugins.AddConfidence(&f, 50,
			fmt.Sprintf("GLEIF lists %q as direct parent of %q", name, p.primaryName),
			plugins.URLCollectionReference("GLEIF relationship records", references))
	case "ultimate-parent":
		plugins.AddConfidence(&f, 50,
			fmt.Sprintf("GLEIF lists %q as ultimate parent of %q", name, p.primaryName),
			plugins.URLCollectionReference("GLEIF relationship records", references))
	case "subsidiary":
		plugins.AddConfidence(&f, 50,
			fmt.Sprintf("GLEIF lists %q as direct subsidiary of %q", name, p.primaryName),
			plugins.URLCollectionReference("GLEIF relationship records", references))
	case "sibling":
		plugins.AddConfidence(&f, 30,
			fmt.Sprintf("GLEIF entity %q shares a corporate parent with %q", name, p.primaryName),
			plugins.URLCollectionReference("GLEIF relationship records", references))
	}

	return f
}

func (p *GLEIFPlugin) relationshipReferences(relatedLEI, relation, primaryRelationship string) []plugins.LabeledURLReferenceData {
	references := []plugins.LabeledURLReferenceData{{Label: "Related GLEIF entity", URL: p.gleifRecordURL(relatedLEI)}}

	var relationshipLEI, relationship string
	switch relation {
	case "direct-parent", "ultimate-parent":
		relationshipLEI = p.primaryLEI
		relationship = relation
	case "subsidiary", "sibling":
		relationshipLEI = relatedLEI
		relationship = "direct-parent"
	}
	if relationshipLEI != "" {
		references = append(references, plugins.LabeledURLReferenceData{
			Label: "GLEIF relationship record", URL: p.gleifRelationshipURL(relationshipLEI, relationship)})
	}
	if relation == "sibling" {
		references = append(references, plugins.LabeledURLReferenceData{
			Label: "Target GLEIF relationship record", URL: p.gleifRelationshipURL(p.primaryLEI, primaryRelationship)})
	}
	return references
}

func (p *GLEIFPlugin) gleifRecordURL(lei string) string {
	if lei == "" {
		return ""
	}
	return fmt.Sprintf("%s/lei-records/%s", p.gleifBase(), url.PathEscape(lei))
}

func (p *GLEIFPlugin) gleifRelationshipURL(lei, relationship string) string {
	return fmt.Sprintf("%s/lei-records/%s/%s-relationship",
		p.gleifBase(), url.PathEscape(lei), relationship)
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
