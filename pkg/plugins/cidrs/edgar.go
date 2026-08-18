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

const confEDGARApparentHandle = 55

var (
	// handlePattern matches potential RIR org handles in SEC EDGAR entity names.
	handlePattern    = regexp.MustCompile(`\b([A-Z]{2,8}-[0-9A-Z]+)\b`)
	accessionPattern = regexp.MustCompile(`^\d{10}-\d{2}-\d{6}$`)
	cikPattern       = regexp.MustCompile(`^\d+$`)
	filenamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

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

func (p *EDGARPlugin) Name() string { return "edgar" }
func (p *EDGARPlugin) Description() string {
	return "SEC EDGAR: discovers org handles from company filings"
}
func (p *EDGARPlugin) Category() string { return "cidr" }
func (p *EDGARPlugin) Phase() int       { return 1 }
func (p *EDGARPlugin) Mode() string     { return plugins.ModePassive }

func (p *EDGARPlugin) Accepts(input plugins.Input) bool {
	return input.OrgName != ""
}

func (p *EDGARPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	// EDGAR full-text search
	apiURL := fmt.Sprintf(
		"https://efts.sec.gov/LATEST/search-index?q=%%22%s%%22&dateRange=custom&startdt=2020-01-01&enddt=%s&_source=period_of_report,display_names,file_num,form,ciks",
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

	return findingsFromEDGARResponse(input, resp), nil
}

func findingsFromEDGARResponse(input plugins.Input, resp EDGARResponse) []plugins.Finding {
	var findings []plugins.Finding
	seenHandles := make(map[string]bool)

	for _, hit := range resp.Hits.Hits {
		for displayNameIndex, displayName := range hit.Source.DisplayNames {
			matches := handlePattern.FindAllString(displayName, -1)
			for _, handle := range matches {
				if seenHandles[handle] || !isLikelyRIRHandle(handle) {
					continue
				}
				seenHandles[handle] = true

				finding := plugins.Finding{
					Type:   plugins.FindingCIDRHandle,
					Value:  handle,
					Source: "edgar",
					Data: map[string]any{
						"registry": "unknown", // Runner will try all RIRs
						"org":      input.OrgName,
					},
				}
				cik := cikForDisplayName(hit, displayNameIndex)
				var references []*plugins.Reference
				if documentURL := secDocumentURL(hit.ID, cik); documentURL != "" {
					references = append(references, plugins.URLReference("SEC EDGAR document", documentURL))
				}
				justification := edgarJustification(hit, displayName, handle)
				if len(references) == 0 {
					plugins.AddConfidence(&finding, confEDGARApparentHandle, justification, nil)
				} else {
					plugins.AddConfidence(&finding, confEDGARApparentHandle, justification, references[0])
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func cikForDisplayName(hit EDGARHit, displayNameIndex int) string {
	if displayNameIndex >= len(hit.Source.CIKs) {
		return ""
	}
	return hit.Source.CIKs[displayNameIndex]
}

func edgarJustification(hit EDGARHit, displayName, handle string) string {
	justification := "SEC EDGAR search result"
	if hit.ID != "" {
		justification = fmt.Sprintf("SEC EDGAR document %q", hit.ID)
	}
	if displayName != "" {
		justification += fmt.Sprintf(" for entity %q", displayName)
	}
	justification += fmt.Sprintf(" contains apparent RIR organization handle %q", handle)
	return justification
}

func secDocumentURL(documentID, cik string) string {
	if !cikPattern.MatchString(cik) {
		return ""
	}

	idComponents := strings.Split(documentID, ":")
	if len(idComponents) != 2 || !accessionPattern.MatchString(idComponents[0]) || !filenamePattern.MatchString(idComponents[1]) {
		return ""
	}

	numericCIK := strings.TrimLeft(cik, "0")
	if numericCIK == "" {
		return ""
	}
	accession := strings.ReplaceAll(idComponents[0], "-", "")
	return fmt.Sprintf("https://www.sec.gov/Archives/edgar/data/%s/%s/%s", numericCIK, accession, idComponents[1])
}

// EDGARResponse represents SEC EDGAR search results.
type EDGARResponse struct {
	Hits struct {
		Hits []EDGARHit `json:"hits"`
	} `json:"hits"`
}

type EDGARHit struct {
	ID     string `json:"_id"`
	Source struct {
		CIKs         []string `json:"ciks"`
		DisplayNames []string `json:"display_names"`
		Form         string   `json:"form"`
	} `json:"_source"`
}
