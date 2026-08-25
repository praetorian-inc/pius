package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// queryAPNIC queries APNIC REST WHOIS for organisation handles.
func (p *ReverseRIRPlugin) queryAPNIC(ctx context.Context, org string) ([]plugins.Finding, error) {
	apiURL := fmt.Sprintf("https://wq.apnic.net/query?searchtext=%s&type=organisation", url.QueryEscape(org))

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return nil, nil
	}

	var records []nativeRecord[ApnicQueryItem]
	if json.Unmarshal(body, &records) != nil {
		return nil, nil
	}

	var findings []plugins.Finding
	for _, record := range records {
		item := record.Value
		if item.ObjectType != "organisation" || item.PrimaryKey == "" {
			continue
		}

		attributes := apnicAttributes(item.Attributes)
		sourceURL := "https://rdap.apnic.net/entity/" + url.PathEscape(item.PrimaryKey)
		resultData := newRPSLResultData(
			"apnic", item.PrimaryKey, org, sourceURL, attributes, record.Raw,
		)
		if detail := p.queryRDAPEntity(ctx, sourceURL); detail != nil {
			applyRDAPResultData(&resultData, detail.Entity, detail.Record)
			resultData.Record = jsonRecord(apnicNativeRecord{
				Search: record.Raw,
				Detail: detail.Record,
			})
		}
		findings = append(findings,
			newReverseRIRFinding("APNIC WHOIS database", resultData)...,
		)
	}

	return findings, nil
}

func (p *ReverseRIRPlugin) queryRDAPEntity(ctx context.Context, detailURL string) *rdapEntityResult {
	body, err := p.client.GetWithHeaders(ctx, detailURL, map[string]string{
		"Accept": "application/rdap+json",
	})
	if err != nil {
		return nil
	}

	var entity RdapEntity
	if json.Unmarshal(body, &entity) != nil {
		return nil
	}
	return &rdapEntityResult{Entity: entity, Record: json.RawMessage(body)}
}

type rdapEntityResult struct {
	Entity RdapEntity
	Record json.RawMessage
}

type apnicNativeRecord struct {
	Search json.RawMessage `json:"search"`
	Detail json.RawMessage `json:"detail"`
}

type ApnicAttribute struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type ApnicQueryItem struct {
	ObjectType string           `json:"objectType"`
	PrimaryKey string           `json:"primaryKey"`
	Attributes []ApnicAttribute `json:"attributes"`
}

func apnicAttributes(rawAttributes []ApnicAttribute) rpslAttributes {
	var attributes rpslAttributes
	for _, attribute := range rawAttributes {
		attributes.add(attribute.Name, attribute.Values...)
	}
	return attributes
}
