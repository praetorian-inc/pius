package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	piuscache "github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var wikidataTestNow = time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)

const (
	wikidataClaimWebsite    = "website"
	wikidataClaimParent     = "parent"
	wikidataClaimSubsidiary = "subsidiary"
)

type wikidataTestResponses struct {
	companies     []map[string]any
	relationships []map[string]any
	claims        []map[string]any
}

func newWikidataPlugin(t *testing.T, responses wikidataTestResponses) (*WikidataPlugin, *int) {
	t.Helper()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestCount++
		switch request.URL.Query().Get("action") {
		case "wbsearchentities":
			writeEntitySearchResults(t, w, responses.companies)
			return
		case "wbgetentities":
			writeEntityDocuments(
				t,
				w,
				responses.companies,
				responses.claims,
				request.URL.Query().Get("ids"),
			)
			return
		}

		query := request.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/sparql-results+json")
		switch {
		case strings.Contains(query, "?matchKind"):
			writeWikidataResponse(t, w, responses.companies)
		case strings.Contains(query, "?claimType") && strings.Contains(query, "p:"+wdPropertyOfficialWebsite):
			writeWikidataResponse(t, w, contextClaimResults(responses.claims))
		case strings.Contains(query, "ps:"+wdPropertySubsidiary):
			writeWikidataResponse(t, w, claimResultsByType(responses.claims, wikidataClaimSubsidiary))
		case strings.Contains(query, "ps:"+wdPropertyParent):
			writeWikidataResponse(t, w, targetParentClaimResults(responses.claims))
		default:
			writeWikidataResponse(t, w, responses.relationships)
		}
	}))
	t.Cleanup(server.Close)

	apiCache, err := piuscache.NewAPI(t.TempDir(), "wikidata")
	require.NoError(t, err)
	return &WikidataPlugin{
		httpClient: server.Client(),
		baseURL:    server.URL,
		entityURL:  server.URL,
		apiCache:   apiCache,
		now:        func() time.Time { return wikidataTestNow },
	}, &requestCount
}

func claimResultsByType(bindings []map[string]any, expected string) []map[string]any {
	return filterClaimResults(bindings, func(claimType, _ string) bool {
		return claimType == expected
	})
}

func targetParentClaimResults(bindings []map[string]any) []map[string]any {
	return filterClaimResults(bindings, func(claimType, value string) bool {
		return claimType == wikidataClaimParent && strings.HasSuffix(value, "/Q1")
	})
}

func contextClaimResults(bindings []map[string]any) []map[string]any {
	return filterClaimResults(bindings, func(claimType, _ string) bool {
		return claimType == wikidataClaimWebsite || claimType == wikidataClaimParent
	})
}

func filterClaimResults(
	bindings []map[string]any,
	keep func(claimType, value string) bool,
) []map[string]any {
	filtered := make([]map[string]any, 0, len(bindings))
	for _, binding := range bindings {
		claimType, _ := binding["claimType"].(map[string]string)
		value, _ := binding["value"].(map[string]string)
		if keep(claimType["value"], value["value"]) {
			filtered = append(filtered, binding)
		}
	}
	return filtered
}

func writeEntitySearchResults(t *testing.T, w http.ResponseWriter, companies []map[string]any) {
	t.Helper()
	results := make([]entitySearchResult, 0, len(companies))
	for _, company := range companies {
		results = append(results, entitySearchResult{ID: bindingEntityID(company, "entity")})
	}
	require.NoError(t, json.NewEncoder(w).Encode(entitySearchResponse{Search: results}))
}

func writeEntityDocuments(
	t *testing.T,
	w http.ResponseWriter,
	companies []map[string]any,
	bindings []map[string]any,
	requested string,
) {
	t.Helper()
	documents := map[string]entityDocument{}
	for _, company := range companies {
		entityID := bindingEntityID(company, "entity")
		matchKind := bindingValue(company, "matchKind")
		document := entityDocument{ID: entityID}
		switch matchKind {
		case wikidataMatchAlias:
			document.Aliases = map[string][]entityLabel{"en": {{Value: "Acme Holdings"}}}
		default:
			document.Labels = map[string]entityLabel{"en": {Value: "Acme Holdings"}}
		}
		if website := bindingValue(company, "website"); website != "" {
			document.Claims = map[string][]entityStatement{
				wdPropertyOfficialWebsite: {{MainSnak: entitySnak{DataValue: entityDataValue{Value: mustJSON(t, website)}}}},
			}
		}
		documents[entityID] = document
	}
	for _, binding := range bindings {
		entityID := bindingEntityID(binding, "entity")
		ensureTestDocument(documents, entityID, testEntityName(entityID))

		claimType := bindingValue(binding, "claimType")
		property := ""
		claimOwnerID := entityID
		switch claimType {
		case wikidataClaimWebsite:
			property = wdPropertyOfficialWebsite
		case wikidataClaimParent:
			property = wdPropertyParent
			parentID := bindingEntityID(binding, "value")
			ensureTestDocument(documents, parentID, bindingValue(binding, "valueLabel"))
		case wikidataClaimSubsidiary:
			property = wdPropertySubsidiary
			claimOwnerID = "Q1"
		}
		if property == "" {
			continue
		}

		document := documents[claimOwnerID]
		if document.Claims == nil {
			document.Claims = make(map[string][]entityStatement)
		}
		document.Claims[property] = append(document.Claims[property], testEntityStatement(t, binding, claimType))
		documents[claimOwnerID] = document
	}

	requestedIDs := strings.Split(requested, "|")
	responseDocuments := make(map[string]entityDocument, len(requestedIDs))
	for _, entityID := range requestedIDs {
		if document, ok := documents[entityID]; ok {
			responseDocuments[entityID] = document
		}
	}
	require.NoError(t, json.NewEncoder(w).Encode(entityResponse{Entities: responseDocuments}))
}

func ensureTestDocument(documents map[string]entityDocument, entityID, name string) {
	if entityID == "" {
		return
	}
	if _, ok := documents[entityID]; ok {
		return
	}
	documents[entityID] = entityDocument{
		ID:     entityID,
		Labels: map[string]entityLabel{"en": {Value: name}},
	}
}

func testEntityStatement(t *testing.T, binding map[string]any, claimType string) entityStatement {
	t.Helper()
	value := bindingValue(binding, "value")
	switch claimType {
	case wikidataClaimParent:
		value = bindingEntityID(binding, "value")
	case wikidataClaimSubsidiary:
		value = bindingEntityID(binding, "entity")
	}

	statement := entityStatement{
		ID:         bindingValue(binding, "statement"),
		Rank:       "normal",
		Qualifiers: make(map[string][]entitySnak),
	}
	if claimType == wikidataClaimWebsite {
		statement.MainSnak.DataValue.Value = mustJSON(t, value)
	} else {
		statement.MainSnak.DataValue.Value = mustJSON(t, entityIDValue{ID: value})
	}
	if start := bindingValue(binding, "start"); start != "" {
		statement.Qualifiers[wdPropertyStartTime] = []entitySnak{{
			DataValue: entityDataValue{Value: mustJSON(t, entityTimeValue{Time: start})},
		}}
	}
	if end := bindingValue(binding, "end"); end != "" {
		statement.Qualifiers[wdPropertyEndTime] = []entitySnak{{
			DataValue: entityDataValue{Value: mustJSON(t, entityTimeValue{Time: end})},
		}}
	}
	if bindingValue(binding, "reference") != "" {
		statement.References = []entityReference{{
			Snaks: map[string][]entitySnak{wdPropertyReferenceURL: {{}}},
		}}
	}
	return statement
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func bindingEntityID(binding map[string]any, key string) string {
	return extractEntityID(bindingValue(binding, key))
}

func bindingValue(binding map[string]any, key string) string {
	value, _ := binding[key].(map[string]string)
	return value["value"]
}

func writeWikidataResponse(t *testing.T, w http.ResponseWriter, bindings []map[string]any) {
	t.Helper()
	require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
		"results": map[string]any{"bindings": bindings},
	}))
}

func wikidataURI(value string) map[string]string {
	return map[string]string{"type": "uri", "value": value}
}

func wikidataLiteral(value string) map[string]string {
	return map[string]string{"type": "literal", "value": value}
}

func companyResult(id, matchKind, website string) map[string]any {
	result := map[string]any{
		"entity":    wikidataURI("http://www.wikidata.org/entity/" + id),
		"matchKind": wikidataLiteral(matchKind),
	}
	if website != "" {
		result["website"] = wikidataURI(website)
	}
	return result
}

func relationshipResult(
	entityID string,
	entityName string,
	statementID string,
	property string,
	start string,
	end string,
	referenced bool,
) map[string]any {
	result := map[string]any{
		"entity":      wikidataURI("http://www.wikidata.org/entity/" + entityID),
		"entityLabel": wikidataLiteral(entityName),
		"statement":   wikidataURI("http://www.wikidata.org/entity/statement/" + statementID),
		"property":    wikidataLiteral(property),
		"rank":        wikidataURI("http://wikiba.se/ontology#NormalRank"),
	}
	if start != "" {
		result["start"] = wikidataLiteral(start)
	}
	if end != "" {
		result["end"] = wikidataLiteral(end)
	}
	if referenced {
		result["reference"] = wikidataURI("http://www.wikidata.org/reference/R1")
	}
	return result
}

func websiteResult(
	entityID string,
	statementID string,
	website string,
	referenced bool,
) map[string]any {
	result := map[string]any{
		"entity":      wikidataURI("http://www.wikidata.org/entity/" + entityID),
		"entityLabel": wikidataLiteral(testEntityName(entityID)),
		"claimType":   wikidataLiteral(wikidataClaimWebsite),
		"value":       wikidataURI(website),
		"statement":   wikidataURI("http://www.wikidata.org/entity/statement/" + statementID),
		"rank":        wikidataURI("http://wikiba.se/ontology#NormalRank"),
	}
	if referenced {
		result["reference"] = wikidataURI("http://www.wikidata.org/reference/R2")
	}
	return result
}

func subsidiaryResult(
	entityID string,
	statementID string,
	start string,
	end string,
	referenced bool,
) map[string]any {
	return entityRelationshipResult(
		entityID,
		statementID,
		wikidataClaimSubsidiary,
		"Q1",
		"Acme Holdings",
		start,
		end,
		referenced,
	)
}

func parentResult(
	entityID string,
	statementID string,
	parentID string,
	parentName string,
	start string,
	end string,
	referenced bool,
) map[string]any {
	return entityRelationshipResult(
		entityID,
		statementID,
		wikidataClaimParent,
		parentID,
		parentName,
		start,
		end,
		referenced,
	)
}

func entityRelationshipResult(
	entityID string,
	statementID string,
	claimType string,
	valueID string,
	valueName string,
	start string,
	end string,
	referenced bool,
) map[string]any {
	result := map[string]any{
		"entity":      wikidataURI("http://www.wikidata.org/entity/" + entityID),
		"entityLabel": wikidataLiteral(testEntityName(entityID)),
		"claimType":   wikidataLiteral(claimType),
		"value":       wikidataURI("http://www.wikidata.org/entity/" + valueID),
		"valueLabel":  wikidataLiteral(valueName),
		"statement":   wikidataURI("http://www.wikidata.org/entity/statement/" + statementID),
		"rank":        wikidataURI("http://wikiba.se/ontology#NormalRank"),
	}
	if start != "" {
		result["start"] = wikidataLiteral(start)
	}
	if end != "" {
		result["end"] = wikidataLiteral(end)
	}
	if referenced {
		result["reference"] = wikidataURI("http://www.wikidata.org/reference/R3")
	}
	return result
}

func testEntityName(entityID string) string {
	if entityID == "Q3" {
		return "Better Widgets"
	}
	return "Acme Widgets"
}

func basicWikidataResponses() wikidataTestResponses {
	return wikidataTestResponses{
		companies: []map[string]any{
			companyResult("Q1", wikidataMatchLabel, "https://acme.example"),
		},
		relationships: []map[string]any{
			relationshipResult("Q2", "Acme Widgets", "S1", wdPropertySubsidiary, "", "", false),
		},
		claims: []map[string]any{
			websiteResult("Q2", "W1", "https://www.acmewidgets.com/about", false),
			subsidiaryResult("Q2", "S1", "", "", false),
		},
	}
}

func TestWikidataPlugin_Run_EmitsPlainLanguageEvidence(t *testing.T) {
	plugin, requestCount := newWikidataPlugin(t, basicWikidataResponses())

	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "ACME HOLDINGS INC"})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	finding := findings[0]
	assert.Equal(t, plugins.FindingDomain, finding.Type)
	assert.Equal(t, "acmewidgets.com", finding.Value)
	assert.Equal(t, wikidataBaseScore, plugins.TotalConfidence(finding))
	assert.True(t, plugins.NeedsReview(finding))
	assert.Equal(t, "Q1", finding.Data["target_wikidata_id"])
	assert.Equal(t, "Q2", finding.Data["wikidata_id"])
	assert.Equal(t, "open_ended", finding.Data["relationship_status"])
	require.Len(t, finding.Confidences, 1)
	assert.Equal(t,
		fmt.Sprintf(
			`Wikidata lists "Acme Widgets" as a subsidiary of "ACME HOLDINGS INC" and lists "https://www.acmewidgets.com/about" as its official website (subsidiary (%s); Wikidata items Q1 and Q2). Wikidata does not provide an end date for the relationship.`,
			wdPropertySubsidiary,
		),
		finding.Confidences[0].Justification)
	require.Len(t, finding.Confidences[0].References, 2)
	assert.Equal(t, "https://www.wikidata.org/wiki/Q1", finding.Confidences[0].References[0].URL)
	assert.Equal(t, "https://www.wikidata.org/wiki/Q2", finding.Confidences[0].References[1].URL)
	assert.Equal(t, 5, *requestCount)
}

func TestWikidataPlugin_Run_ScoresReciprocalReferencedEvidence(t *testing.T) {
	responses := basicWikidataResponses()
	responses.claims = []map[string]any{
		websiteResult("Q2", "W1", "https://acmewidgets.com", true),
		subsidiaryResult("Q2", "S1", "", "", true),
		parentResult("Q2", "S2", "Q1", "Acme Holdings", "", "", true),
	}

	plugin, _ := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme Holdings"})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, wikidataMaxScore, plugins.TotalConfidence(findings[0]))
	justification := findings[0].Confidences[0].Justification
	assert.Contains(t, justification, fmt.Sprintf("subsidiary (%s)", wdPropertySubsidiary))
	assert.Contains(t, justification, fmt.Sprintf("parent organization (%s)", wdPropertyParent))
	assert.Contains(t, justification, "both organizations' Wikidata records")
	assert.Contains(t, justification, "source references for both")
}

func TestWikidataPlugin_Run_ScoresOtherCurrentParentAtZero(t *testing.T) {
	responses := basicWikidataResponses()
	responses.claims = append(responses.claims,
		parentResult("Q2", "P2", "Q3", "Other Holdings", "", "", false),
	)

	plugin, _ := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme Holdings"})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, wikidataOtherOwnerScore, plugins.TotalConfidence(findings[0]))
	assert.Equal(t, "conflicting", findings[0].Data["relationship_status"])
	justification := findings[0].Confidences[0].Justification
	assert.NotContains(t, justification, "also records this relationship as ended")
	assert.Contains(t, justification, `also lists "Other Holdings" as a parent organization`)
	assert.Contains(t, justification, "reviewed before treating the domain as in scope")
}

func TestWikidataPlugin_Run_ScoresUnreconciledEndedRelationshipAtTen(t *testing.T) {
	responses := basicWikidataResponses()
	responses.claims = append(responses.claims,
		parentResult(
			"Q2", "P1", "Q1", "Acme Holdings",
			"2010-01-01T00:00:00Z", "2020-01-01T00:00:00Z", true,
		),
	)

	plugin, _ := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme Holdings"})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, wikidataEndedScore, plugins.TotalConfidence(findings[0]))
	assert.Equal(t, "conflicting", findings[0].Data["relationship_status"])
	assert.Contains(t, findings[0].Confidences[0].Justification, "also records this relationship as ended")
}

func TestWikidataPlugin_Run_AllowsDatedReacquisition(t *testing.T) {
	responses := basicWikidataResponses()
	responses.claims = []map[string]any{
		websiteResult("Q2", "W1", "https://acmewidgets.com", false),
		parentResult(
			"Q2", "S1", "Q1", "Acme Holdings",
			"2010-01-01T00:00:00Z", "2020-01-01T00:00:00Z", true,
		),
		parentResult(
			"Q2", "S2", "Q1", "Acme Holdings",
			"2024-01-01T00:00:00Z", "", true,
		),
	}

	plugin, _ := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme Holdings"})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, wikidataBaseScore+wikidataReferenceScore, plugins.TotalConfidence(findings[0]))
	assert.Equal(t, "open_ended", findings[0].Data["relationship_status"])
	assert.NotContains(t, findings[0].Confidences[0].Justification, "also records this relationship as ended")
}

func TestWikidataPlugin_Run_ScoresHistoricalRelationshipsAtTen(t *testing.T) {
	responses := basicWikidataResponses()
	responses.claims = []map[string]any{
		websiteResult("Q2", "W1", "https://acmewidgets.com", false),
		parentResult(
			"Q2", "S1", "Q1", "Acme Holdings",
			"2010-01-01T00:00:00Z", "2020-01-01T00:00:00Z", true,
		),
	}

	plugin, _ := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme Holdings"})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, wikidataEndedScore, plugins.TotalConfidence(findings[0]))
	assert.Equal(t, "ended", findings[0].Data["relationship_status"])
	assert.Contains(t, findings[0].Confidences[0].Justification, "records this relationship as ended on January 2020")
}

func TestWikidataPlugin_Run_SuppressesFutureRelationships(t *testing.T) {
	responses := basicWikidataResponses()
	responses.claims = []map[string]any{
		websiteResult("Q2", "W1", "https://acmewidgets.com", false),
		parentResult(
			"Q2", "S1", "Q1", "Acme Holdings",
			"2027-01-01T00:00:00Z", "", true,
		),
	}

	plugin, _ := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme Holdings"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWikidataPlugin_Run_SuppressesEndedWebsites(t *testing.T) {
	responses := basicWikidataResponses()
	responses.claims[0]["end"] = wikidataLiteral("2020-01-01T00:00:00Z")

	plugin, _ := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme Holdings"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWikidataPlugin_Run_RejectsAmbiguousCompany(t *testing.T) {
	responses := basicWikidataResponses()
	responses.companies = append(responses.companies,
		companyResult("Q9", wikidataMatchLabel, "https://other.example"),
	)

	plugin, requestCount := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme Holdings"})
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, 2, *requestCount)
}

func TestWikidataPlugin_Run_UsesKnownDomainToResolveAmbiguity(t *testing.T) {
	responses := basicWikidataResponses()
	responses.companies = append(responses.companies,
		companyResult("Q9", wikidataMatchLabel, "https://other.example"),
	)

	plugin, _ := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{
		OrgName: "Acme Holdings",
		Domain:  "acme.example",
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "Q1", findings[0].Data["target_wikidata_id"])
}

func TestWikidataPlugin_Run_CachesCompleteResults(t *testing.T) {
	plugin, requestCount := newWikidataPlugin(t, basicWikidataResponses())
	input := plugins.Input{OrgName: "Acme Holdings"}

	first, err := plugin.Run(context.Background(), input)
	require.NoError(t, err)
	second, err := plugin.Run(context.Background(), input)
	require.NoError(t, err)

	require.Len(t, first, 1)
	require.Len(t, second, 1)
	assert.Equal(t, first[0].Value, second[0].Value)
	assert.Equal(t, first[0].Confidences, second[0].Confidences)
	assert.Equal(t, first[0].Data["wikidata_id"], second[0].Data["wikidata_id"])
	assert.Equal(t, 5, *requestCount)
}

func TestWikidataPlugin_Run_DeduplicatesDomainUsingStrongestEvidence(t *testing.T) {
	responses := basicWikidataResponses()
	responses.relationships = append(responses.relationships,
		relationshipResult("Q3", "Better Widgets", "S3", wdPropertySubsidiary, "", "", true),
		relationshipResult("Q3", "Better Widgets", "S4", wdPropertyParent, "", "", true),
	)
	responses.claims = append(responses.claims,
		websiteResult("Q3", "W3", "https://acmewidgets.com", true),
		subsidiaryResult("Q3", "S3", "", "", true),
		parentResult("Q3", "P3", "Q1", "Acme Holdings", "", "", true),
	)

	plugin, _ := newWikidataPlugin(t, responses)
	findings, err := plugin.Run(context.Background(), plugins.Input{OrgName: "Acme Holdings"})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, "Q3", findings[0].Data["wikidata_id"])
	assert.Equal(t, wikidataMaxScore, plugins.TotalConfidence(findings[0]))
}

func TestCompanyNameVariants(t *testing.T) {
	assert.Equal(t,
		[]string{"ROCKWELL AUTOMATION Inc.", "ROCKWELL AUTOMATION", "Rockwell Automation"},
		companyNameVariants("  ROCKWELL  AUTOMATION Inc.  "),
	)
	assert.Equal(t,
		[]string{"COMPAGNIE FINANCIÈRE LAZARD FRÈRES", "Compagnie Financière Lazard Frères"},
		companyNameVariants("COMPAGNIE FINANCIÈRE LAZARD FRÈRES"),
	)
}

func TestSelectCompany(t *testing.T) {
	documents := map[string]entityDocument{
		"Q1": {
			ID:      "Q1",
			Aliases: map[string][]entityLabel{"en": {{Value: "Acme Holdings"}}},
			Claims: map[string][]entityStatement{
				wdPropertyOfficialWebsite: {{MainSnak: entitySnak{DataValue: entityDataValue{Value: json.RawMessage(`"https://acme.example"`)}}}},
			},
		},
		"Q2": {
			ID:     "Q2",
			Labels: map[string]entityLabel{"en": {Value: "Acme Holdings"}},
		},
	}
	variants := []string{"Acme Holdings"}

	assert.Equal(t,
		companyResolution{id: "Q1", matchKind: wikidataMatchAlias},
		selectCompany(documents, variants, "acme.example"),
	)
	assert.Equal(t,
		companyResolution{id: "Q2", matchKind: wikidataMatchLabel},
		selectCompany(documents, variants, ""),
	)
}

func TestDiscoveryQuery_RejectsInvalidEntityID(t *testing.T) {
	assert.Empty(t, discoveryQuery("Q1 } UNION { ?entity ?p ?o", wdPropertyParent))
	assert.NotEmpty(t, discoveryQuery("Q248", wdPropertyParent))
}

func TestClassifyClaim(t *testing.T) {
	tests := []struct {
		name     string
		claim    datedClaim
		expected claimState
	}{
		{
			name:     "open ended",
			claim:    datedClaim{},
			expected: claimOpenEnded,
		},
		{
			name:     "active until future end",
			claim:    datedClaim{end: time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)},
			expected: claimActive,
		},
		{
			name:     "future start",
			claim:    datedClaim{start: time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)},
			expected: claimFuture,
		},
		{
			name:     "past end",
			claim:    datedClaim{end: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)},
			expected: claimEnded,
		},
		{
			name:     "deprecated",
			claim:    datedClaim{rank: "http://wikiba.se/ontology#DeprecatedRank"},
			expected: claimDeprecated,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, classifyClaim(test.claim, wikidataTestNow))
		})
	}
}

func TestParseWikidataTime(t *testing.T) {
	assert.Equal(t,
		time.Date(2018, time.August, 1, 0, 0, 0, 0, time.UTC),
		parseWikidataTime("+2018-08-00T00:00:00Z"),
	)
	assert.True(t, parseWikidataTime("unknown").IsZero())
}

func TestExtractDomainFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{name: "normalizes host", url: "https://WWW.Example.COM:443/path", expected: "example.com"},
		{name: "rejects bare text", url: "example.com", expected: ""},
		{name: "rejects localhost", url: "https://localhost", expected: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, extractDomainFromURL(test.url))
		})
	}
}
