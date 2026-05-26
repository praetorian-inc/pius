package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("ga-tracking", func() plugins.Plugin {
		return &GATrackingPlugin{client: client.New()}
	})
}

// GATrackingPlugin discovers related domains by correlating Google Analytics
// and AdSense tracking IDs via the SpyOnWeb REST API.
//
// Platform mode: reads tracking IDs from Input.Meta["ga_tracking_ids"]
// Standalone mode: fetches the target domain's HTML and extracts tracking IDs
//
// Phase 0 (independent): runs concurrently, requires SPYONWEB_API_KEY.
// Mode: Active (fetches target HTML in standalone mode).
type GATrackingPlugin struct {
	client      *client.Client
	spyonwebURL string // override for testing; empty = real SpyOnWeb API
	targetURL   string // override for testing; empty = https://{domain}/
}

func (p *GATrackingPlugin) Name() string { return "ga-tracking" }
func (p *GATrackingPlugin) Description() string {
	return "GA Tracking: discovers related domains via shared Google Analytics/AdSense IDs on SpyOnWeb (requires SPYONWEB_API_KEY)"
}
func (p *GATrackingPlugin) Category() string { return "domain" }
func (p *GATrackingPlugin) Phase() int       { return 0 }
func (p *GATrackingPlugin) Mode() string     { return plugins.ModeActive }

// Accepts returns true if SPYONWEB_API_KEY is set and either Meta tracking IDs
// or a valid domain is present.
func (p *GATrackingPlugin) Accepts(input plugins.Input) bool {
	if os.Getenv("SPYONWEB_API_KEY") == "" {
		return false
	}
	return input.Meta["ga_tracking_ids"] != "" || isDomainName(input.Domain)
}

// trackingID holds a single GA or AdSense tracking identifier.
type trackingID struct {
	value  string // e.g. "UA-15207196-1" or "pub-1234567890123456"
	idType string // "analytics" or "adsense"
}

// maxTrackingIDsPerDomain caps the number of UA or pub IDs extracted from a
// single HTML page. Any legitimate page will have far fewer than 10.
const maxTrackingIDsPerDomain = 10

// gaRegex matches Universal Analytics IDs (UA-XXXXX-X).
var gaRegex = regexp.MustCompile(`\bUA-\d{4,10}-\d{1,4}\b`)

// adsenseRegex matches Google AdSense publisher IDs (pub-XXXXXXXXXX).
var adsenseRegex = regexp.MustCompile(`\bpub-\d{10,20}\b`)

// Run executes the plugin. It collects tracking IDs from Meta and/or HTML,
// then queries SpyOnWeb for each ID and returns deduplicated domain findings.
func (p *GATrackingPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	var allIDs []trackingID

	// Platform mode: read IDs from meta.
	if metaIDs := input.Meta["ga_tracking_ids"]; metaIDs != "" {
		allIDs = append(allIDs, parseTrackingIDList(metaIDs)...)
	}

	// Standalone mode: fetch target HTML and extract IDs.
	if isDomainName(input.Domain) {
		extracted, err := p.extractFromDomain(ctx, input.Domain)
		if err != nil {
			slog.Warn("ga-tracking: failed to extract tracking IDs from domain",
				"domain", input.Domain, "error", err)
			// Graceful degradation: if we have no meta IDs either, return nothing.
			if len(allIDs) == 0 {
				return nil, nil
			}
		} else {
			allIDs = append(allIDs, extracted...)
		}
	}

	// Deduplicate tracking IDs.
	allIDs = deduplicateTrackingIDs(allIDs)

	if len(allIDs) == 0 {
		return nil, nil
	}

	// Query SpyOnWeb for each tracking ID.
	var findings []plugins.Finding
	for _, tid := range allIDs {
		tidFindings, err := p.querySpyOnWeb(ctx, tid, input)
		if err != nil {
			slog.Warn("ga-tracking: SpyOnWeb query failed",
				"tracking_id", tid.value, "error", err)
			continue
		}
		findings = append(findings, tidFindings...)
	}

	return deduplicateFindings(findings, p.Name()), nil
}

// parseTrackingIDList parses a comma-separated list of tracking IDs.
// UA-XXXXX → analytics, pub-XXXXX → adsense.
// Unknown formats are warned and skipped.
func parseTrackingIDList(raw string) []trackingID {
	parts := strings.Split(raw, ",")
	result := make([]trackingID, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch {
		case strings.HasPrefix(part, "UA-"):
			if match := gaRegex.FindString(part); match != "" {
				result = append(result, trackingID{value: match, idType: "analytics"})
			} else {
				slog.Warn("ga-tracking: malformed UA tracking ID, skipping", "id", part)
			}
		case strings.HasPrefix(part, "pub-"):
			if match := adsenseRegex.FindString(part); match != "" {
				result = append(result, trackingID{value: match, idType: "adsense"})
			} else {
				slog.Warn("ga-tracking: malformed AdSense publisher ID, skipping", "id", part)
			}
		default:
			slog.Warn("ga-tracking: unrecognized tracking ID format, skipping", "id", part)
		}
	}
	return result
}

// extractFromDomain fetches the target domain's root HTML and extracts
// GA and AdSense tracking IDs via regex.
func (p *GATrackingPlugin) extractFromDomain(ctx context.Context, domain string) ([]trackingID, error) {
	targetURL := fmt.Sprintf("https://%s/", domain)
	if p.targetURL != "" {
		targetURL = p.targetURL
	}

	body, err := p.client.GetWithHeaders(ctx, targetURL, map[string]string{
		"Accept": "text/html,application/xhtml+xml,*/*",
	})
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", domain, err)
	}

	html := string(body)
	var ids []trackingID

	for _, ua := range gaRegex.FindAllString(html, maxTrackingIDsPerDomain) {
		ids = append(ids, trackingID{value: ua, idType: "analytics"})
	}
	for _, pub := range adsenseRegex.FindAllString(html, maxTrackingIDsPerDomain) {
		ids = append(ids, trackingID{value: pub, idType: "adsense"})
	}

	return ids, nil
}

// deduplicateTrackingIDs removes duplicate tracking IDs by value.
func deduplicateTrackingIDs(ids []trackingID) []trackingID {
	seen := make(map[string]bool, len(ids))
	result := make([]trackingID, 0, len(ids))
	for _, id := range ids {
		if !seen[id.value] {
			seen[id.value] = true
			result = append(result, id)
		}
	}
	return result
}

// spyonwebResponse mirrors the SpyOnWeb API response structure.
type spyonwebResponse struct {
	Status string                       `json:"status"`
	Result map[string]spyonwebCategory  `json:"result"`
}

// spyonwebCategory holds the items for a given tracking ID.
type spyonwebCategory struct {
	// key is the tracking ID (e.g. "UA-15207196"), value maps domain → last-seen date.
	Items map[string]map[string]string `json:"-"`
}

// UnmarshalJSON handles the nested SpyOnWeb result format where the tracking ID
// is itself a key within the category.
func (c *spyonwebCategory) UnmarshalJSON(data []byte) error {
	// The format is: { "UA-15207196": { "items": { "domain.com": "2024-01-15" } } }
	// We unmarshal the outer tracking ID key, then extract items.
	var raw map[string]struct {
		Items map[string]string `json:"items"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Items = make(map[string]map[string]string, len(raw))
	for trackID, v := range raw {
		c.Items[trackID] = v.Items
	}
	return nil
}

// querySpyOnWeb queries the SpyOnWeb API for a single tracking ID and returns
// domain findings.
func (p *GATrackingPlugin) querySpyOnWeb(ctx context.Context, tid trackingID, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("SPYONWEB_API_KEY")

	// Endpoint matches idType: /v1/analytics/{id} or /v1/adsense/{id}.
	if tid.idType != "analytics" && tid.idType != "adsense" {
		return nil, fmt.Errorf("ga-tracking: unknown tracking type %q", tid.idType)
	}

	base := "https://api.spyonweb.com/v1"
	if p.spyonwebURL != "" {
		base = p.spyonwebURL
	}

	// SpyOnWeb indexes by account ID (UA-15207196), not property ID (UA-15207196-1).
	// Strip the last "-N" suffix for analytics queries so the lookup succeeds.
	queryID := tid.value
	if tid.idType == "analytics" {
		if i := strings.LastIndex(queryID, "-"); i > 0 {
			queryID = queryID[:i]
		}
	}

	reqURL := fmt.Sprintf("%s/%s/%s?access_token=%s",
		base, tid.idType, url.PathEscape(queryID), url.QueryEscape(apiKey))

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		// pkg/client sanitizes the access_token via sanitizeURL() before wrapping errors,
		// so it is safe to wrap and propagate here.
		return nil, fmt.Errorf("ga-tracking: SpyOnWeb request for %s: %w", tid.value, err)
	}

	return parseSpyOnWebResponse(body, tid, input)
}

// confidenceForType returns the confidence score for a given tracking type.
func confidenceForType(idType string) float64 {
	if idType == "analytics" {
		return 0.85
	}
	return 0.70 // adsense
}

// parseSpyOnWebResponse parses the SpyOnWeb API response and returns findings.
func parseSpyOnWebResponse(body []byte, tid trackingID, input plugins.Input) ([]plugins.Finding, error) {
	var resp spyonwebResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("ga-tracking: parse SpyOnWeb response for %s: %w", tid.value, err)
	}

	if resp.Status == "not_found" {
		return nil, nil
	}
	if resp.Status != "found" {
		slog.Warn("ga-tracking: SpyOnWeb returned unexpected status", "status", resp.Status, "tracking_id", tid.value)
		return nil, nil
	}

	// The category key matches the idType ("analytics" or "adsense").
	category, ok := resp.Result[tid.idType]
	if !ok {
		return nil, nil
	}

	confidence := confidenceForType(tid.idType)
	var findings []plugins.Finding

	for _, domainMap := range category.Items {
		for domain, lastSeen := range domainMap {
			domain = normalizeDomain(domain)
			if domain == "" {
				continue
			}
			f := plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  domain,
				Source: "ga-tracking",
				Data: map[string]any{
					"org":           input.OrgName,
					"tracking_id":   tid.value,
					"tracking_type": tid.idType,
					"last_seen":     lastSeen,
					"source_domain": input.Domain,
				},
			}
			plugins.SetConfidence(&f, confidence)
			findings = append(findings, f)
		}
	}

	return findings, nil
}
