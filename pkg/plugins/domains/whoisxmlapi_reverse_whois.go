package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// One WhoisXMLAPI response holds up to 10,000 records, so realistic reverse
// queries complete in a single page. The bound only stops a runaway cursor.
const maxWhoisXMLAPIPages = 10

func init() {
	plugins.Register("whoisxmlapi-reverse-whois", func() plugins.Plugin {
		return &WhoisXMLAPIReverseWhoisPlugin{client: client.New()}
	})
}

// WhoisXMLAPIReverseWhoisPlugin discovers related domains by reverse-WHOIS
// query against WhoisXMLAPI, the paid sibling of WhoxyReverseWhoisPlugin.
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

	var dated []datedCandidate
	cursor := ""

	for page := 1; page <= maxWhoisXMLAPIPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		body, err := p.reverse(ctx, query, byEmail, "purchase", cursor)
		if err == nil {
			dated = append(dated, p.candidatesFrom(body.DomainsList, query)...)
		}
		if err != nil {
			// preview already proved matches exist, so a failure before any page
			// succeeded would otherwise return an empty result set — making an
			// auth, credit or outage failure indistinguishable from "this org owns
			// no domains". Later pages degrade to partial recall instead.
			if page == 1 {
				return nil, err
			}
			slog.Warn("whoisxmlapi-reverse-whois: stopping pagination early",
				"page", page, "collected", len(dated), "error", err)
			break
		}

		cursor = body.NextPageSearchAfter
		if cursor == "" {
			break
		}
		if page == maxWhoisXMLAPIPages {
			slog.Warn("whoisxmlapi-reverse-whois: page cap reached with more results available",
				"cap", maxWhoisXMLAPIPages, "collected", len(dated))
		}
	}

	sort.SliceStable(dated, func(i, j int) bool {
		return dated[i].observed.After(dated[j].observed)
	})
	cands := make([]candidate, 0, len(dated))
	for _, d := range plugins.UniqueBy(dated, func(d datedCandidate) string { return d.domain }) {
		cands = append(cands, d.candidate)
	}

	resolver := p.resolver
	if resolver == nil {
		resolver = &rdapWhoisResolver{}
	}
	return verifyCandidates(ctx, resolver, input.OrgName, cands)
}

// reverse issues one authenticated request. Auth is the X-Authentication-Token
// header, so unlike Whoxy and WhoisFreaks the key never reaches the URL.
func (p *WhoisXMLAPIReverseWhoisPlugin) reverse(ctx context.Context, query string, byEmail bool, mode, cursor string) (whoisXMLAPIReverseResponse, error) {
	var zero whoisXMLAPIReverseResponse

	apiKey := os.Getenv("WHOISXMLAPI_API_KEY")

	term := advancedSearchTerm{Field: "Email", Term: query}
	if !byEmail {
		term = advancedSearchTerm{Field: "RegistrantContact.Organization", Term: query, ExactMatch: true}
	}

	// searchType=current is the precision lever: historic includes long-dead
	request := whoisXMLAPIReverseRequest{
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
		return zero, fmt.Errorf("whoisxmlapi: reverse %s request failed: %w", mode, err)
	}

	var body whoisXMLAPIReverseResponse
	if err := json.Unmarshal(raw, &body); err != nil {
		return zero, fmt.Errorf("whoisxmlapi: parse %s response: %w", mode, err)
	}
	return body, nil
}

type datedCandidate struct {
	candidate
	observed time.Time
}

func (p *WhoisXMLAPIReverseWhoisPlugin) candidatesFrom(hits []whoisXMLAPIReverseHit, query string) []datedCandidate {
	out := make([]datedCandidate, 0, len(hits))
	for _, hit := range hits {
		observed := whoisXMLAPIObservedAt(hit.Audit.UpdatedDate)
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hit.DomainName), "."))
		if domain == "" {
			continue
		}
		out = append(out, datedCandidate{
			candidate: candidate{
				domain: domain,
				finding: plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  domain,
					Source: p.Name(),
					Data: map[string]any{
						"org": query,
					},
				},
			},
			observed: observed,
		})
	}
	return out
}

// whoisXMLAPIObservedAt parses an audit timestamp, returning the zero time when
// the field is absent or unparseable. Zero sorts last, so records of unknown age
// rank below dated ones without being discarded. Used for ordering only.
func whoisXMLAPIObservedAt(updated string) time.Time {
	t, err := time.Parse(time.RFC3339, updated)
	if err != nil {
		return time.Time{}
	}
	return t
}

// advancedSearchTerm is one field/term predicate. Up to 4 per request, ANDed.
type advancedSearchTerm struct {
	Field      string `json:"field"`
	Term       string `json:"term"`
	ExactMatch bool   `json:"exactMatch,omitempty"`
}

type whoisXMLAPIReverseRequest struct {
	SearchType          string               `json:"searchType"`
	Mode                string               `json:"mode"`
	IncludeAuditDates   bool                 `json:"includeAuditDates"`
	SearchAfter         string               `json:"searchAfter,omitempty"`
	AdvancedSearchTerms []advancedSearchTerm `json:"advancedSearchTerms"`
}

type whoisXMLAPIReverseResponse struct {
	NextPageSearchAfter string                  `json:"nextPageSearchAfter"`
	DomainsCount        int                     `json:"domainsCount"`
	DomainsList         []whoisXMLAPIReverseHit `json:"domainsList"`
}

// whoisXMLAPIReverseHit is one match. The audit block is when WhoisXMLAPI last
// refreshed its copy of the record, NOT the registration's age
type whoisXMLAPIReverseHit struct {
	DomainName string `json:"domainName"`
	Audit      struct {
		UpdatedDate string `json:"updatedDate"`
	} `json:"audit"`
}
