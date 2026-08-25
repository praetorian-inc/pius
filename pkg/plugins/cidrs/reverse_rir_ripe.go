package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// queryRIPE queries the RIPE search API.
func (p *ReverseRIRPlugin) queryRIPE(ctx context.Context, org string) ([]plugins.Finding, error) {
	apiURL := fmt.Sprintf("https://rest.db.ripe.net/search?query-string=%s", url.QueryEscape(org))

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return nil, nil
	}

	var response RipeWhoisResponse
	if json.Unmarshal(body, &response) != nil {
		return nil, nil
	}

	var findings []plugins.Finding
	for _, record := range response.Objects.Object {
		object := record.Value
		if len(object.PrimaryKey.Attribute) == 0 {
			continue
		}

		primaryKey := object.PrimaryKey.Attribute[0]
		if primaryKey.Name != "organisation" {
			continue
		}

		attributes := ripeAttributes(object.Attributes.Attribute)
		resultData := newRPSLResultData(
			"ripe", primaryKey.Value, org, object.Link.Href, attributes, record.Raw,
		)
		findings = append(findings,
			newReverseRIRFinding("RIPE database", resultData)...,
		)
	}

	return findings, nil
}

type RipeAttribute struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

type RipeWhoisObject struct {
	Type string `json:"type,omitempty"`
	Link struct {
		Href string `json:"href,omitempty"`
	} `json:"link,omitempty"`
	PrimaryKey struct {
		Attribute []RipeAttribute `json:"attribute,omitempty"`
	} `json:"primary-key,omitempty"`
	Attributes struct {
		Attribute []RipeAttribute `json:"attribute,omitempty"`
	} `json:"attributes,omitempty"`
}

type RipeWhoisResponse struct {
	Objects struct {
		Object []nativeRecord[RipeWhoisObject] `json:"object,omitempty"`
	} `json:"objects,omitempty"`
}

func ripeAttributes(rawAttributes []RipeAttribute) rpslAttributes {
	var attributes rpslAttributes
	for _, attribute := range rawAttributes {
		if attribute.Value != "" {
			attributes.add(attribute.Name, attribute.Value)
		}
	}
	return attributes
}
