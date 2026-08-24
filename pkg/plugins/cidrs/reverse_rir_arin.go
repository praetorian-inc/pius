package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

type arinEntityType struct {
	collection string
	references func(arinSearchResponse) ArinRefs
	detail     func(arinDetailResponse) *arinEntityDetail
}

var arinOrganizations = arinEntityType{
	collection: "orgs",
	references: func(response arinSearchResponse) ArinRefs {
		return response.Organizations.Refs
	},
	detail: func(response arinDetailResponse) *arinEntityDetail {
		return response.Organization
	},
}

var arinCustomers = arinEntityType{
	collection: "customers",
	references: func(response arinSearchResponse) ArinRefs {
		return response.Customers.Refs
	},
	detail: func(response arinDetailResponse) *arinEntityDetail {
		return response.Customer
	},
}

var queriedARINEntities = []arinEntityType{arinOrganizations, arinCustomers}

// queryARIN queries multiple ARIN entity types with handle deduplication.
func (p *ReverseRIRPlugin) queryARIN(ctx context.Context, org string) ([]plugins.Finding, error) {
	seen := make(map[string]bool)
	var findings []plugins.Finding

	for _, entity := range queriedARINEntities {
		for _, finding := range p.queryArinEntity(ctx, entity, org) {
			key := string(finding.Type) + ":" + finding.Value
			if !seen[key] {
				seen[key] = true
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// queryArinEntity queries a specific ARIN entity type.
func (p *ReverseRIRPlugin) queryArinEntity(
	ctx context.Context,
	entity arinEntityType,
	org string,
) []plugins.Finding {
	apiURL := fmt.Sprintf(
		"https://whois.arin.net/rest/%s;name=%s",
		entity.collection,
		arinNamePattern(org),
	)

	body, err := p.client.GetWithHeaders(ctx, apiURL, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return nil
	}

	var response arinSearchResponse
	if json.Unmarshal(body, &response) != nil {
		return nil
	}

	var findings []plugins.Finding
	for _, ref := range entity.references(response) {
		resultData := p.queryARINDetail(ctx, ref, entity, org)
		findings = append(findings,
			newReverseRIRFinding("ARIN "+entity.collection+" database", resultData)...,
		)
	}

	return findings
}

func arinNamePattern(value string) string {
	tokens := strings.Fields(value)
	for i, token := range tokens {
		tokens[i] = url.PathEscape(token)
	}
	return "*" + strings.Join(tokens, "*") + "*"
}

func (p *ReverseRIRPlugin) queryARINDetail(
	ctx context.Context,
	ref ArinRef,
	entityType arinEntityType,
	queriedOrganization string,
) ReverseRIRFindingData {
	record := ref.Record
	if len(record) == 0 {
		record = jsonRecord(ref)
	}
	data := ReverseRIRFindingData{
		Registry:            "arin",
		Handle:              ref.Handle,
		Name:                ref.Name,
		QueriedOrganization: queriedOrganization,
		SourceURL:           ref.URL,
		Record:              record,
	}
	if ref.URL == "" {
		return data
	}

	body, err := p.client.GetWithHeaders(ctx, ref.URL, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return data
	}

	var response arinDetailResponse
	if json.Unmarshal(body, &response) != nil {
		return data
	}
	data.Record = json.RawMessage(body)

	entity := entityType.detail(response)
	if entity == nil {
		return data
	}
	data.Name = firstNonempty(string(entity.Name), data.Name)
	data.City = string(entity.City)
	data.StateProvince = string(entity.StateProvince)
	data.PostalCode = string(entity.PostalCode)
	data.Country = string(entity.Country.Code2)
	data.RegistrationDate = string(entity.RegistrationDate)
	data.LastUpdated = string(entity.UpdateDate)
	data.SourceURL = firstNonempty(
		data.SourceURL, string(entity.Ref), string(entity.RDAPRef))
	data.Street = entity.StreetAddress.strings()
	data.Comments = entity.Comment.strings()
	return data
}

type arinSearchResponse struct {
	Organizations arinOrganizationReferences `json:"orgs"`
	Customers     arinCustomerReferences     `json:"customers"`
}

type arinOrganizationReferences struct {
	Refs ArinRefs `json:"orgRef"`
}

type arinCustomerReferences struct {
	Refs ArinRefs `json:"customerRef"`
}

type arinDetailResponse struct {
	Organization *arinEntityDetail `json:"org"`
	Customer     *arinEntityDetail `json:"customer"`
}

type arinEntityDetail struct {
	Name             arinText    `json:"name"`
	StreetAddress    arinLines   `json:"streetAddress"`
	City             arinText    `json:"city"`
	StateProvince    arinText    `json:"iso3166-2"`
	PostalCode       arinText    `json:"postalCode"`
	Country          arinCountry `json:"iso3166-1"`
	RegistrationDate arinText    `json:"registrationDate"`
	UpdateDate       arinText    `json:"updateDate"`
	Ref              arinText    `json:"ref"`
	RDAPRef          arinText    `json:"rdapRef"`
	Comment          arinLines   `json:"comment"`
}

type arinCountry struct {
	Code2 arinText `json:"code2"`
}

type arinLines struct {
	Line arinTextList `json:"line"`
}

func (lines arinLines) strings() []string {
	values := make([]string, 0, len(lines.Line))
	for _, line := range lines.Line {
		if line != "" {
			values = append(values, string(line))
		}
	}
	return values
}

type arinText string

func (text *arinText) UnmarshalJSON(data []byte) error {
	var direct string
	if err := json.Unmarshal(data, &direct); err == nil {
		*text = arinText(direct)
		return nil
	}

	var wrapped struct {
		Value string `json:"$"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return err
	}
	*text = arinText(wrapped.Value)
	return nil
}

type arinTextList []arinText

func (values *arinTextList) UnmarshalJSON(data []byte) error {
	var multiple []arinText
	if err := json.Unmarshal(data, &multiple); err == nil {
		*values = multiple
		return nil
	}

	var single arinText
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*values = arinTextList{single}
	return nil
}

type ArinRef struct {
	Handle string          `json:"@handle"`
	Name   string          `json:"@name"`
	URL    string          `json:"$"`
	Record json.RawMessage `json:"-"`
}

func (ref *ArinRef) UnmarshalJSON(data []byte) error {
	type arinRefFields ArinRef
	var fields arinRefFields
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*ref = ArinRef(fields)
	ref.Record = append(json.RawMessage(nil), data...)
	return nil
}

// ArinRefs handles ARIN's JSON quirk: single results are returned as a bare
// object, not a single-element array.
type ArinRefs []ArinRef

func (refs *ArinRefs) UnmarshalJSON(data []byte) error {
	var array []ArinRef
	if err := json.Unmarshal(data, &array); err == nil {
		*refs = array
		return nil
	}

	var single ArinRef
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*refs = ArinRefs{single}
	return nil
}
