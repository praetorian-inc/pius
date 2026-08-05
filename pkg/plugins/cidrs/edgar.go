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

			data := map[string]any{
				"registry":    "unknown", // Runner will try all RIRs
				"org":         input.OrgName,
				"entity_name": hit.Source.EntityName,
			}
			if hit.Source.FormType != "" {
				data["form_type"] = hit.Source.FormType
			}
			if hit.Source.FileNum != "" {
				data["file_num"] = hit.Source.FileNum
			}

			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingCIDRHandle,
				Value:  handle,
				Source: "edgar",
				Confidences: []plugins.Confidence{{
					Score:         confEDGARHandleExtraction,
					Justification: edgarJustification(input.OrgName, handle, hit.Source),
				}},
				Data: data,
			})
		}
	}

	return findings, nil
}

// confEDGARHandleExtraction is the evidence weight of an RIR-shaped token found
// in an SEC filing returned by an organization search.
//
// It is the weakest handle discovery in the pipeline and scored accordingly.
// Two inferences stack: that the filing belongs to the queried organization
// (EDGAR full-text search is a name match, so a filing merely *mentioning* the
// name qualifies), and that a token shaped like PREFIX-123 is an RIR handle
// rather than a docket, ticker, or internal reference. nonRIRPrefixes removes
// the known impostors, not the unknown ones.
const confEDGARHandleExtraction = 0.40

// edgarJustification explains one extracted handle, naming the filing it came
// out of so a reviewer can go read the same document.
func edgarJustification(org, handle string, source edgarSource) string {
	justification := fmt.Sprintf("SEC EDGAR filing for %q contained the RIR-style handle %q",
		org, handle)

	if source.EntityName != "" && source.EntityName != org {
		justification += fmt.Sprintf(", filed under entity %q", source.EntityName)
	}

	var identifiers []string
	if source.FormType != "" {
		identifiers = append(identifiers, "form "+source.FormType)
	}
	if source.FileNum != "" {
		identifiers = append(identifiers, "file "+source.FileNum)
	}
	if len(identifiers) > 0 {
		justification += " (" + strings.Join(identifiers, ", ") + ")"
	}

	return justification
}

// edgarSource is the per-hit metadata EDGAR returns for the fields the query
// asks for in _source.
type edgarSource struct {
	EntityName string `json:"entity_name"`
	FormType   string `json:"form_type"`
	FileNum    string `json:"file_num"`
}

// EDGARResponse represents SEC EDGAR search results
type EDGARResponse struct {
	Hits struct {
		Hits []struct {
			Source edgarSource `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}
