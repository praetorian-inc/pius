package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// One WhoisXMLAPI response holds up to 10,000 records, so realistic reverse
// queries complete in a single page. The bound only stops a runaway cursor.
const maxWhoisXMLAPIPages = 10

// whoisXMLAPIStaleAfter mirrors whoxyRecordStale's ten-year window: a record
// last observed longer ago than this is not evidence of current ownership.
const whoisXMLAPIStaleAfter = -10

func init() {
	plugins.Register("whoisxmlapi-reverse-whois", func() plugins.Plugin {
		return &WhoisXMLAPIReverseWhoisPlugin{client: client.New()}
	})
}

// WhoisXMLAPIReverseWhoisPlugin discovers related domains by reverse-WHOIS
// query against WhoisXMLAPI, the paid sibling of WhoxyReverseWhoisPlugin.
//
// Two properties make it worth running alongside Whoxy rather than instead of
// it: searchType=current restricts matches to live registrations (verified
// live, exact company="Praetorian" returns 12 under `current` against 164 under
// `historic`), and the free preview mode yields a match count without spending
// a credit.
type WhoisXMLAPIReverseWhoisPlugin struct {
	client   *client.Client
	baseURL  string             // overridable for tests
	resolver registrantResolver // overridable for tests; defaults to rdapWhoisResolver
}

func (p *WhoisXMLAPIReverseWhoisPlugin) Name() string { return "whoisxmlapi-reverse-whois" }
func (p *WhoisXMLAPIReverseWhoisPlugin) Description() string {
	return "Reverse WHOIS via WhoisXMLAPI — discovers related domains by registrant organization name or email, current registrations only (paid, requires WHOISXMLAPI_API_KEY)"
}
func (p *WhoisXMLAPIReverseWhoisPlugin) Category() string { return "domain" }
func (p *WhoisXMLAPIReverseWhoisPlugin) Phase() int       { return 0 }
func (p *WhoisXMLAPIReverseWhoisPlugin) Mode() string     { return plugins.ModePassive }

func (p *WhoisXMLAPIReverseWhoisPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("WHOISXMLAPI_API_KEY") != "" && (input.OrgName != "" || input.Email != "")
}

func (p *WhoisXMLAPIReverseWhoisPlugin) apiBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://reverse-whois.whoisxmlapi.com/api/v2"
}

// advancedSearchTerm is one field/term predicate. Up to 4 per request, ANDed.
type advancedSearchTerm struct {
	Field      string `json:"field"`
	Term       string `json:"term"`
	ExactMatch bool   `json:"exactMatch,omitempty"`
}

type whoisXMLAPIReverseRequest struct {
	APIKey              string               `json:"apiKey"`
	SearchType          string               `json:"searchType"`
	Mode                string               `json:"mode"`
	IncludeAuditDates   bool                 `json:"includeAuditDates"`
	SearchAfter         string               `json:"searchAfter,omitempty"`
	AdvancedSearchTerms []advancedSearchTerm `json:"advancedSearchTerms"`
}

// whoisXMLAPIReverseResponse mirrors the documented output. domainsList is
// polymorphic — []string when includeAuditDates is false, []object when true —
// so it is held raw and decoded here, which always requests the object form.
type whoisXMLAPIReverseResponse struct {
	NextPageSearchAfter string          `json:"nextPageSearchAfter"`
	DomainsCount        int             `json:"domainsCount"`
	DomainsList         json.RawMessage `json:"domainsList"`
}

// whoisXMLAPIReverseHit is one match. Audit dates are when WhoisXMLAPI first
// and last observed the record, not registration dates — the same "when was
// this seen" semantic as Whoxy's query_time, which is what staleness needs.
type whoisXMLAPIReverseHit struct {
	DomainName string `json:"domainName"`
	Audit      struct {
		UpdatedDate string `json:"updatedDate"`
	} `json:"audit"`
}

func (p *WhoisXMLAPIReverseWhoisPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	// Active seed: org name by default, registrant email when only Email is set.
	query, byEmail := input.OrgName, false
	if input.OrgName == "" && input.Email != "" {
		query, byEmail = input.Email, true
	}

	// preview is free, so a pivot that matches nothing costs no credit.
	count, err := p.reverse(ctx, query, byEmail, "preview", "")
	if err != nil {
		return nil, err
	}
	if count.DomainsCount == 0 {
		return nil, nil
	}

	// Accumulate an ordered, deduped candidate list. Staleness filtering happens
	// here, BEFORE verification, so stale records never trigger a lookup. Each
	// match is only a lead; corroboration against the candidate's own registrant
	// happens in verifyCandidates (ENG-5123).
	var cands []candidate
	seen := make(map[string]struct{})
	cursor := ""

	for page := 1; page <= maxWhoisXMLAPIPages; page++ {
		body, err := p.reverse(ctx, query, byEmail, "purchase", cursor)
		if err != nil {
			slog.Warn("whoisxmlapi-reverse-whois: stopping pagination", "page", page, "error", err)
			break
		}

		hits, err := decodeWhoisXMLAPIHits(body.DomainsList)
		if err != nil {
			slog.Warn("whoisxmlapi-reverse-whois: stopping pagination", "page", page, "error", err)
			break
		}

		for _, hit := range hits {
			if whoisXMLAPIRecordStale(hit.Audit.UpdatedDate) {
				continue
			}
			domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hit.DomainName), "."))
			if domain == "" {
				continue
			}
			if _, ok := seen[domain]; ok {
				continue
			}
			seen[domain] = struct{}{}
			cands = append(cands, candidate{
				domain: domain,
				finding: plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  domain,
					Source: p.Name(),
					Data: map[string]any{
						"org": query,
					},
				},
			})
		}

		cursor = body.NextPageSearchAfter
		if cursor == "" {
			break
		}
	}

	// Resolve into a local rather than mutating p.resolver: writing shared plugin
	// state inside Run() would be a data race if an instance were ever reused.
	resolver := p.resolver
	if resolver == nil {
		resolver = &rdapWhoisResolver{}
	}
	// input.OrgName drives corroboration; email-mode (OrgName == "") short-
	// circuits inside verifyCandidates. Data["org"] provenance stays the query.
	return verifyCandidates(ctx, resolver, input.OrgName, cands)
}

// reverse issues one authenticated request. Auth is the X-Authentication-Token
// header, so unlike Whoxy and WhoisFreaks the key never reaches the URL.
func (p *WhoisXMLAPIReverseWhoisPlugin) reverse(ctx context.Context, query string, byEmail bool, mode, cursor string) (whoisXMLAPIReverseResponse, error) {
	var zero whoisXMLAPIReverseResponse

	apiKey := os.Getenv("WHOISXMLAPI_API_KEY")

	// "Email" is the union field, covering registrant, admin, billing and tech
	// addresses in one query. exactMatch is only honoured for a documented
	// subset of fields — for every email field it is ignored and treated as true
	// anyway, so it is omitted rather than sent as an explicit false.
	term := advancedSearchTerm{Field: "Email", Term: query}
	if !byEmail {
		term = advancedSearchTerm{Field: "RegistrantContact.Organization", Term: query, ExactMatch: true}
	}

	// searchType=current is the precision lever: historic includes long-dead
	// registrations, which is not what current ownership means.
	request := whoisXMLAPIReverseRequest{
		APIKey:              apiKey,
		SearchType:          "current",
		Mode:                mode,
		IncludeAuditDates:   true,
		SearchAfter:         cursor,
		AdvancedSearchTerms: []advancedSearchTerm{term},
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return zero, fmt.Errorf("whoisxmlapi: build %s request: %w", mode, err)
	}

	raw, err := p.client.PostWithHeaders(ctx, p.apiBase(), payload, map[string]string{
		"Accept":                 "application/json",
		"Content-Type":           "application/json",
		"X-Authentication-Token": apiKey,
	})
	if err != nil {
		// The body echoes the apiKey field back, so this is not wrapped.
		return zero, fmt.Errorf("whoisxmlapi: reverse %s request failed", mode)
	}

	var body whoisXMLAPIReverseResponse
	if err := json.Unmarshal(raw, &body); err != nil {
		return zero, fmt.Errorf("whoisxmlapi: parse %s response: %w", mode, err)
	}
	return body, nil
}

// decodeWhoisXMLAPIHits decodes the object form of domainsList. The field is
// absent in preview mode and null when nothing matched, neither of which is an
// error.
func decodeWhoisXMLAPIHits(list json.RawMessage) ([]whoisXMLAPIReverseHit, error) {
	if len(list) == 0 || string(list) == "null" {
		return nil, nil
	}
	var hits []whoisXMLAPIReverseHit
	if err := json.Unmarshal(list, &hits); err != nil {
		return nil, fmt.Errorf("decode domainsList: %w", err)
	}
	return hits, nil
}

// whoisXMLAPIRecordStale reports whether the record was last observed outside
// the ten-year window.
//
// Unlike whoxyRecordStale, an unparseable or absent timestamp is treated as
// NOT stale. Audit dates are only present because includeAuditDates is sent as
// true, so a vendor-side format or field change would otherwise drop every
// candidate and read as "this pivot owns nothing". Keeping them costs a
// verification lookup, which is the cheaper failure.
func whoisXMLAPIRecordStale(updated string) bool {
	t, err := time.Parse(time.RFC3339, updated)
	if err != nil {
		return false
	}
	return t.Before(time.Now().AddDate(whoisXMLAPIStaleAfter, 0, 0))
}
