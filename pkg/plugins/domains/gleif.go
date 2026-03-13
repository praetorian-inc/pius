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
	plugins.Register("gleif", func() plugins.Plugin {
		return &GLEIFPlugin{
			client:  client.New(),
			baseURL: "",
		}
	})
}

// GLEIFPlugin discovers corporate parents and subsidiaries via the GLEIF LEI registry.
//
// Strategy:
//  1. Search GLEIF for entities matching the OrgName
//  2. For the primary match, check if it has a registered direct parent
//  3. If so, fetch the direct parent and ultimate parent (if different)
//  4. Fetch all direct subsidiaries (paginated)
//  5. Emit additional name-match candidates at low confidence
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

// ── API response types ─────────────────────────────────────────────────────────

type leiSearchResponse struct {
	Data []leiRecord `json:"data"`
	Meta leiMeta     `json:"meta"`
}

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

// ── Run ───────────────────────────────────────────────────────────────────────

func (p *GLEIFPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	if input.OrgName == "" {
		return nil, nil
	}

	candidates, err := p.searchByName(ctx, input.OrgName)
	if err != nil {
		log.Printf("[gleif] search failed for %q: %v", input.OrgName, err)
		return nil, nil
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var findings []plugins.Finding

	addFinding := func(f plugins.Finding) {
		if f.Value != "" && !seen[f.Value] {
			seen[f.Value] = true
			findings = append(findings, f)
		}
	}

	primary := candidates[0]

	// Fetch full record to inspect parent relationship links.
	fullRecord, err := p.getRecord(ctx, primary.ID)
	if err != nil {
		log.Printf("[gleif] get record failed for LEI %s: %v", primary.ID, err)
		fullRecord = &primary
	}

	if hasParent(fullRecord) {
		directParentLEI, err := p.getDirectParent(ctx, primary.ID)
		if err != nil {
			log.Printf("[gleif] direct parent failed for %s: %v", primary.ID, err)
		} else if directParentLEI != "" {
			if parentRecord, err := p.getRecord(ctx, directParentLEI); err != nil {
				log.Printf("[gleif] parent record failed for %s: %v", directParentLEI, err)
			} else {
				addFinding(recordToFinding(*parentRecord, "direct-parent", plugins.ConfidenceHigh))
			}

			// Ultimate parent — only emit if different from direct parent.
			ultimateParentLEI, err := p.getUltimateParent(ctx, primary.ID)
			if err != nil {
				log.Printf("[gleif] ultimate parent failed for %s: %v", primary.ID, err)
			} else if ultimateParentLEI != "" && ultimateParentLEI != directParentLEI {
				if ultimateRecord, err := p.getRecord(ctx, ultimateParentLEI); err != nil {
					log.Printf("[gleif] ultimate parent record failed for %s: %v", ultimateParentLEI, err)
				} else {
					addFinding(recordToFinding(*ultimateRecord, "ultimate-parent", plugins.ConfidenceHigh))
				}
			}
		}
	}

	// Subsidiaries (paginated).
	children, err := p.getChildren(ctx, primary.ID)
	if err != nil && ctx.Err() != nil {
		return findings, ctx.Err()
	}
	if err != nil {
		log.Printf("[gleif] children failed for %s: %v", primary.ID, err)
	}
	for _, child := range children {
		if child.Attributes.Entity.LegalName.Name != "" {
			addFinding(recordToFinding(child, "subsidiary", plugins.ConfidenceHigh))
		}
	}

	// Additional name-match candidates at low confidence.
	for _, c := range candidates[1:] {
		if c.Attributes.Entity.LegalName.Name != "" {
			addFinding(recordToFinding(c, "name-match", plugins.ConfidenceLow))
		}
	}

	return findings, nil
}

// ── API methods ───────────────────────────────────────────────────────────────

func (p *GLEIFPlugin) searchByName(ctx context.Context, name string) ([]leiRecord, error) {
	u := fmt.Sprintf("%s/lei-records?filter[entity.legalName]=%s&filter[entity.status]=ACTIVE&page[size]=10",
		p.gleifBase(), url.QueryEscape(name))
	body, err := p.client.GetWithHeaders(ctx, u, gleifHeaders)
	if err != nil {
		return nil, fmt.Errorf("gleif: search: %w", err)
	}
	var resp leiSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("gleif: search parse: %w", err)
	}
	return resp.Data, nil
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
