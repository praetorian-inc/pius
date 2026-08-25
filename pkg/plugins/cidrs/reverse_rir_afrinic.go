package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// queryAFRINIC queries AFRINIC RDAP entity search for organisation handles.
func (p *ReverseRIRPlugin) queryAFRINIC(ctx context.Context, org string) ([]plugins.Finding, error) {
	apiURL := fmt.Sprintf("https://rdap.afrinic.net/rdap/entities?fn=%s", url.QueryEscape(org))

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"Accept": "application/rdap+json",
	})
	if err != nil {
		return nil, nil
	}

	var response RdapEntitySearchResponse
	if json.Unmarshal(body, &response) != nil {
		return nil, nil
	}

	var findings []plugins.Finding
	for _, record := range response.EntitySearchResults {
		entity := record.Value
		handle := entity.Handle
		if handle == "" || !strings.HasPrefix(strings.ToUpper(handle), "ORG-") {
			continue
		}

		resultData := ReverseRIRFindingData{
			Registry:            "afrinic",
			Handle:              handle,
			QueriedOrganization: org,
			Record:              record.Raw,
		}
		applyRDAPResultData(&resultData, entity, record.Raw)
		findings = append(findings,
			newReverseRIRFinding("AFRINIC RDAP database", resultData)...,
		)
	}

	return findings, nil
}

type RdapEntitySearchResponse struct {
	EntitySearchResults []nativeRecord[RdapEntity] `json:"entitySearchResults"`
}
