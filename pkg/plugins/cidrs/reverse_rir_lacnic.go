package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// queryLACNIC queries the LACNIC RDAP entity search API.
func (p *ReverseRIRPlugin) queryLACNIC(ctx context.Context, org string) ([]plugins.Finding, error) {
	apiURL := fmt.Sprintf("https://rdap.lacnic.net/rdap/entities?fn=%s", url.QueryEscape(org))

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"Accept": "application/rdap+json",
	})
	if err != nil {
		return nil, nil
	}

	var response LacnicSearchResponse
	if json.Unmarshal(body, &response) != nil {
		return nil, nil
	}

	var findings []plugins.Finding
	for _, record := range response.Entities {
		entity := record.Value
		if entity.Handle == "" {
			continue
		}

		resultData := ReverseRIRFindingData{
			Registry:            "lacnic",
			Handle:              entity.Handle,
			QueriedOrganization: org,
			Record:              record.Raw,
		}
		applyRDAPResultData(&resultData, entity, record.Raw)
		findings = append(findings,
			newReverseRIRFinding("LACNIC RDAP database", resultData)...,
		)
	}

	return findings, nil
}

type LacnicSearchResponse struct {
	Entities []nativeRecord[RdapEntity] `json:"entities"`
}
