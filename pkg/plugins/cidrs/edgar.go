package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// handlePattern matches potential RIR org handles in SEC EDGAR entity names.
var handlePattern = regexp.MustCompile(`\b([A-Z]{2,8}-[0-9A-Z]+)\b`)

// nonRIRPrefixes are known SEC/government/financial prefixes that match
// handlePattern but are not RIR org handles.
var nonRIRPrefixes = []string{
	"SEC-", "EIN-", "CIK-", "SIC-", "IRS-", "NYSE-", "NASDAQ-",
	"FCC-", "DOJ-", "FBI-", "CIA-", "EPA-", "FDA-", "SSN-", "TIN-",
	"DEL-", "INC-", "FORM-", "SC-", "SR-", "US-", "CUSIP-",
}

// isLikelyRIRHandle returns true if the candidate is not a known non-RIR prefix.
func isLikelyRIRHandle(handle string) bool {
	for _, prefix := range nonRIRPrefixes {
		if strings.HasPrefix(handle, prefix) {
			return false
		}
	}
	return true
}

func init() {
	plugins.Register("edgar", func() plugins.Plugin {
		return &EDGARPlugin{client: client.New()}
	})
}

// EDGARPlugin discovers RIR org handles from SEC EDGAR company filings.
// Phase 1 plugin: emits FindingCIDRHandle findings.
type EDGARPlugin struct {
	client *client.Client
}

func (p *EDGARPlugin) Name() string        { return "edgar" }
func (p *EDGARPlugin) Description() string { return "SEC EDGAR: discovers org handles from company filings" }
func (p *EDGARPlugin) Category() string    { return "cidr" }
func (p *EDGARPlugin) Phase() int          { return 1 }
func (p *EDGARPlugin) Mode() string        { return plugins.ModePassive }

func (p *EDGARPlugin) Accepts(input plugins.Input) bool {
	return input.OrgName != ""
}

func (p *EDGARPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	// EDGAR full-text search
	apiURL := fmt.Sprintf(
		"https://efts.sec.gov/LATEST/search-index?q=%%22%s%%22&dateRange=custom&startdt=2020-01-01&enddt=%s&_source=period_of_report,entity_name,file_num,form_type",
		url.QueryEscape(input.OrgName),
		time.Now().Format("2006-01-02"),
	)

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return nil, nil // Graceful degradation
	}

	var resp EDGARResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}

	var findings []plugins.Finding
	seenHandles := make(map[string]bool)

	for _, hit := range resp.Hits.Hits {
		if hit.Source.EntityName == "" {
			continue
		}

		matches := handlePattern.FindAllString(hit.Source.EntityName, -1)
		for _, handle := range matches {
			if seenHandles[handle] || !isLikelyRIRHandle(handle) {
				continue
			}
			seenHandles[handle] = true

			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingCIDRHandle,
				Value:  handle,
				Source: "edgar",
				Data: map[string]any{
					"registry": "unknown", // Runner will try all RIRs
					"org":      input.OrgName,
				},
			})
		}
	}

	return findings, nil
}

// EDGARResponse represents SEC EDGAR search results
type EDGARResponse struct {
	Hits struct {
		Hits []struct {
			Source struct {
				EntityName string `json:"entity_name"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}
