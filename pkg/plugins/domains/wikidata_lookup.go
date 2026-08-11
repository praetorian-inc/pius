package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	whoisdata "github.com/praetorian-inc/pius/pkg/whois/data"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func companyNameVariants(orgName string) []string {
	orgName = strings.Join(strings.Fields(orgName), " ")
	variants := []string{orgName}

	titled := titleCaseUppercase(orgName)
	if titled != "" {
		variants = append(variants, titled)
	}

	canonical := canonicalCompanyName(orgName)
	if canonical != "" {
		variants = append(variants, canonical, cases.Title(language.English).String(canonical))
	}
	return strutil.Unique(variants)
}

func titleCaseUppercase(value string) string {
	if value != strings.ToUpper(value) || value == strings.ToLower(value) {
		return value
	}
	return cases.Title(language.English).String(strings.ToLower(value))
}

func canonicalCompanyName(value string) string {
	words := strings.Fields(value)
	companyWords := make([]string, 0, len(words))
	for _, word := range words {
		normalized := strings.ToLower(strings.Trim(word, " .,;:()[]{}"))
		if !whoisdata.LegalSuffixes[normalized] {
			companyWords = append(companyWords, strings.Trim(word, " .,;:()[]{}"))
		}
	}
	return strings.Join(companyWords, " ")
}

func (p *WikidataPlugin) searchEntityIDs(
	ctx context.Context,
	variants []string,
) ([]string, error) {
	for _, variant := range variants {
		query := url.Values{
			"action":   {"wbsearchentities"},
			"format":   {"json"},
			"language": {"en"},
			"limit":    {"10"},
			"search":   {variant},
			"type":     {"item"},
			"uselang":  {"en"},
		}
		body, err := p.getWikidata(ctx, p.entityEndpoint()+"?"+query.Encode(), "application/json")
		if err != nil {
			return nil, err
		}

		var response entitySearchResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("parse entity search response: %w", err)
		}
		entityIDs := make([]string, 0, len(response.Search))
		for _, result := range response.Search {
			if isWikidataEntityID(result.ID) {
				entityIDs = append(entityIDs, result.ID)
			}
		}
		if len(entityIDs) > 0 {
			return strutil.Unique(entityIDs), nil
		}
	}
	return []string{}, nil
}

func selectCompany(
	documents map[string]entityDocument,
	variants []string,
	knownDomain string,
) companyResolution {
	var best companyCandidate
	bestScore := 0
	isAmbiguous := false
	for entityID, document := range documents {
		candidate := scoreCompanyDocument(entityID, document, variants, knownDomain)
		switch {
		case candidate.matchScore > bestScore:
			best = candidate
			bestScore = candidate.matchScore
			isAmbiguous = false
		case candidate.matchScore > 0 && candidate.matchScore == bestScore:
			isAmbiguous = true
		}
	}
	if best.id == "" || isAmbiguous {
		return companyResolution{}
	}
	return companyResolution{id: best.id, matchKind: best.matchKind}
}

func scoreCompanyDocument(
	entityID string,
	document entityDocument,
	variants []string,
	knownDomain string,
) companyCandidate {
	candidate := companyCandidate{id: entityID}
	if labelsMatch(document.Labels, variants) {
		candidate.matchKind = wikidataMatchLabel
		candidate.matchScore += 3
	}
	if officialNamesMatch(document.Claims["P1448"], variants) {
		if candidate.matchKind == "" {
			candidate.matchKind = wikidataMatchOfficialName
		}
		candidate.matchScore += 2
	}
	if aliasesMatch(document.Aliases, variants) {
		if candidate.matchKind == "" {
			candidate.matchKind = wikidataMatchAlias
		}
		candidate.matchScore++
	}
	matchesSite := slices.ContainsFunc(document.Claims["P856"], func(statement entityStatement) bool {
		return websiteMatchesDomain(statementStringValue(statement), knownDomain)
	})
	if matchesSite {
		candidate.matchScore += 10
	}
	return candidate
}

func labelsMatch(labels map[string]entityLabel, variants []string) bool {
	return companyNamesMatch([]string{labels["en"].Value, labels["mul"].Value}, variants)
}

func aliasesMatch(aliases map[string][]entityLabel, variants []string) bool {
	values := []string{}
	for _, languageCode := range []string{"en", "mul"} {
		for _, alias := range aliases[languageCode] {
			values = append(values, alias.Value)
		}
	}
	return companyNamesMatch(values, variants)
}

func officialNamesMatch(statements []entityStatement, variants []string) bool {
	values := make([]string, 0, len(statements))
	for _, statement := range statements {
		values = append(values, statementTextValue(statement))
	}
	return companyNamesMatch(values, variants)
}

func companyNamesMatch(values, variants []string) bool {
	for _, value := range values {
		for _, variant := range variants {
			if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(variant)) {
				return true
			}
		}
	}
	return false
}

func websiteMatchesDomain(rawURL, knownDomain string) bool {
	return knownDomain != "" && extractDomainFromURL(rawURL) == normalizeKnownDomain(knownDomain)
}

func normalizeKnownDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "www.")
	return strings.TrimSuffix(domain, ".")
}

func (p *WikidataPlugin) discoverEntityIDs(
	ctx context.Context,
	targetID string,
) ([]string, error) {
	entityIDs := []string{}
	failedQueries := 0
	for _, property := range []string{wikidataPropertySubsidiary, wikidataPropertyParent} {
		query := discoveryQuery(targetID, property)
		if query == "" {
			return nil, fmt.Errorf("invalid Wikidata entity ID %q", targetID)
		}
		bindings, err := executeSPARQL[discoveryBinding](p, ctx, query)
		if err != nil {
			failedQueries++
			slog.Debug("wikidata: relationship discovery failed", "property", property, "error", err)
			continue
		}
		entityIDs = append(entityIDs, discoveredEntityIDs(bindings)...)
	}
	if failedQueries == 2 {
		return nil, fmt.Errorf("all relationship discovery queries failed")
	}
	slices.Sort(entityIDs)
	return strutil.Unique(entityIDs), nil
}

func discoveryQuery(targetID, property string) string {
	if !isWikidataEntityID(targetID) {
		return ""
	}
	if property == wikidataPropertyParent {
		return fmt.Sprintf(`
SELECT DISTINCT ?entity WHERE {
  ?entity wdt:P749 wd:%s .
}
LIMIT %d
`, targetID, wikidataMaxCandidates)
	}
	return fmt.Sprintf(`
SELECT DISTINCT ?entity WHERE {
  wd:%s wdt:P355 ?entity .
}
LIMIT %d
`, targetID, wikidataMaxCandidates)
}

func discoveredEntityIDs(bindings []discoveryBinding) []string {
	entityIDs := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		if entityID := extractEntityID(binding.Entity.Value); entityID != "" {
			entityIDs = append(entityIDs, entityID)
		}
	}
	slices.Sort(entityIDs)
	return strutil.Unique(entityIDs)
}

func (p *WikidataPlugin) fetchEntities(
	ctx context.Context,
	entityIDs []string,
	props string,
) (map[string]entityDocument, error) {
	documents := make(map[string]entityDocument, len(entityIDs))
	for batch := range slices.Chunk(entityIDs, wikidataBatchSize) {
		query := url.Values{
			"action":           {"wbgetentities"},
			"format":           {"json"},
			"ids":              {strings.Join(batch, "|")},
			"languagefallback": {"1"},
			"languages":        {"en|mul"},
			"props":            {props},
		}
		body, err := p.getWikidata(ctx, p.entityEndpoint()+"?"+query.Encode(), "application/json")
		if err != nil {
			return nil, err
		}

		var response entityResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("parse entity response: %w", err)
		}
		for entityID, document := range response.Entities {
			documents[entityID] = document
		}
	}
	return documents, nil
}

func (p *WikidataPlugin) entityEndpoint() string {
	if p.entityURL != "" {
		return p.entityURL
	}
	return wikidataEntityEndpoint
}

func relatedEntityIDs(
	documents map[string]entityDocument,
	candidateIDs []string,
	targetID string,
) []string {
	related := []string{}
	for _, candidateID := range candidateIDs {
		document, ok := documents[candidateID]
		if !ok {
			continue
		}
		for _, property := range []string{wikidataPropertyParent, "P127"} {
			for _, statement := range document.Claims[property] {
				entityID := statementEntityID(statement)
				if entityID != "" && entityID != targetID {
					related = append(related, entityID)
				}
			}
		}
	}
	slices.Sort(related)
	return strutil.Unique(related)
}

func missingEntityIDs(documents map[string]entityDocument, entityIDs []string) []string {
	missing := make([]string, 0, len(entityIDs))
	for _, entityID := range entityIDs {
		if _, ok := documents[entityID]; !ok {
			missing = append(missing, entityID)
		}
	}
	return missing
}

func buildEntityEvidence(
	targetID string,
	candidateIDs []string,
	documents map[string]entityDocument,
) []entityEvidence {
	entities := make(map[string]*entityEvidence, len(candidateIDs))
	for _, candidateID := range candidateIDs {
		document := documents[candidateID]
		entities[candidateID] = &entityEvidence{
			id:   candidateID,
			name: entityName(document, candidateID),
		}
	}

	for _, statement := range documents[targetID].Claims[wikidataPropertySubsidiary] {
		candidateID := statementEntityID(statement)
		if entity := entities[candidateID]; entity != nil {
			entity.relationships = append(entity.relationships, relationshipClaim{
				datedClaim: datedClaimFromStatement(statement),
				property:   wikidataPropertySubsidiary,
			})
		}
	}

	for _, candidateID := range candidateIDs {
		addCandidateClaims(entities[candidateID], targetID, documents)
	}

	result := make([]entityEvidence, 0, len(candidateIDs))
	for _, candidateID := range candidateIDs {
		result = append(result, *entities[candidateID])
	}
	return result
}

func addCandidateClaims(
	entity *entityEvidence,
	targetID string,
	documents map[string]entityDocument,
) {
	document := documents[entity.id]
	for _, statement := range document.Claims[wikidataPropertyParent] {
		parentID := statementEntityID(statement)
		claim := affiliationClaim{
			datedClaim: datedClaimFromStatement(statement),
			property:   wikidataPropertyParent,
			entityID:   parentID,
			name:       entityName(documents[parentID], parentID),
		}
		entity.affiliations = append(entity.affiliations, claim)
		if parentID == targetID {
			entity.relationships = append(entity.relationships, relationshipClaim{
				datedClaim: claim.datedClaim,
				property:   wikidataPropertyParent,
			})
		}
	}

	for _, statement := range document.Claims["P127"] {
		ownerID := statementEntityID(statement)
		entity.affiliations = append(entity.affiliations, affiliationClaim{
			datedClaim: datedClaimFromStatement(statement),
			property:   "P127",
			entityID:   ownerID,
			name:       entityName(documents[ownerID], ownerID),
		})
	}

	for _, statement := range document.Claims["P856"] {
		website := statementStringValue(statement)
		if domain := extractDomainFromURL(website); domain != "" {
			entity.websites = append(entity.websites, websiteClaim{
				datedClaim: datedClaimFromStatement(statement),
				url:        website,
				domain:     domain,
			})
		}
	}
}

func datedClaimFromStatement(statement entityStatement) datedClaim {
	return datedClaim{
		statement:  statement.ID,
		rank:       statement.Rank,
		start:      statementQualifierTime(statement, "P580"),
		end:        statementQualifierTime(statement, "P582"),
		referenced: hasSourceReference(statement.References),
	}
}

func hasSourceReference(references []entityReference) bool {
	return slices.ContainsFunc(references, func(reference entityReference) bool {
		return len(reference.Snaks["P854"]) > 0 || len(reference.Snaks["P248"]) > 0
	})
}

func statementEntityID(statement entityStatement) string {
	var value entityIDValue
	if err := json.Unmarshal(statement.MainSnak.DataValue.Value, &value); err != nil {
		return ""
	}
	return value.ID
}

func statementStringValue(statement entityStatement) string {
	var value string
	if err := json.Unmarshal(statement.MainSnak.DataValue.Value, &value); err != nil {
		return ""
	}
	return value
}

func statementTextValue(statement entityStatement) string {
	var value struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(statement.MainSnak.DataValue.Value, &value); err != nil {
		return ""
	}
	return value.Text
}

func statementQualifierTime(statement entityStatement, property string) time.Time {
	qualifiers := statement.Qualifiers[property]
	if len(qualifiers) == 0 {
		return time.Time{}
	}
	var value entityTimeValue
	if err := json.Unmarshal(qualifiers[0].DataValue.Value, &value); err != nil {
		return time.Time{}
	}
	return parseWikidataTime(value.Time)
}

func entityName(document entityDocument, fallback string) string {
	if label := document.Labels["en"].Value; label != "" {
		return label
	}
	if label := document.Labels["mul"].Value; label != "" {
		return label
	}
	return fallback
}

func executeSPARQL[T any](
	plugin *WikidataPlugin,
	ctx context.Context,
	query string,
) ([]T, error) {
	body, err := plugin.executeSPARQL(ctx, query)
	if err != nil {
		return nil, err
	}

	var response sparqlResponse[T]
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return response.Results.Bindings, nil
}

func (p *WikidataPlugin) executeSPARQL(ctx context.Context, query string) ([]byte, error) {
	requestURL := p.sparqlEndpoint() + "?query=" + url.QueryEscape(query) + "&format=json"
	return p.getWikidata(ctx, requestURL, "application/sparql-results+json")
}

func (p *WikidataPlugin) getWikidata(
	ctx context.Context,
	requestURL string,
	accept string,
) ([]byte, error) {
	for attempt := 1; attempt <= wikidataMaxAttempts; attempt++ {
		body, retryAfter, err := p.getWikidataOnce(ctx, requestURL, accept)
		if err == nil {
			return body, nil
		}
		if attempt == wikidataMaxAttempts || retryAfter < 0 {
			return nil, err
		}
		if err := waitForWikidataRetry(ctx, retryAfter, attempt); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("wikidata request attempts exhausted")
}

func (p *WikidataPlugin) getWikidataOnce(
	ctx context.Context,
	requestURL string,
	accept string,
) ([]byte, time.Duration, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, -1, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", "Pius/1.0 (https://github.com/praetorian-inc/pius)")

	response, err := p.httpClient.Do(request)
	if err != nil {
		return nil, -1, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		retryAfter := time.Duration(-1)
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError {
			retryAfter = parseRetryAfter(response.Header.Get("Retry-After"))
		}
		return nil, retryAfter, fmt.Errorf("unexpected status: %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, wikidataMaxResponse+1))
	if err != nil {
		return nil, time.Second, fmt.Errorf("read response: %w", err)
	}
	if len(body) > wikidataMaxResponse {
		return nil, -1, fmt.Errorf("response too large (>%d bytes)", wikidataMaxResponse)
	}
	return body, 0, nil
}

func parseRetryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds < 1 {
		return time.Second
	}
	return time.Duration(seconds) * time.Second
}

func waitForWikidataRetry(ctx context.Context, retryAfter time.Duration, attempt int) error {
	if retryAfter <= 0 {
		retryAfter = time.Duration(attempt) * time.Second
	}
	timer := time.NewTimer(retryAfter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isWikidataEntityID(entityID string) bool {
	if len(entityID) < 2 || entityID[0] != 'Q' || entityID[1] == '0' {
		return false
	}
	_, err := strconv.ParseUint(entityID[1:], 10, 64)
	return err == nil
}

func extractEntityID(uri string) string {
	if index := strings.LastIndex(uri, "/"); index >= 0 {
		return uri[index+1:]
	}
	return uri
}

func extractDomainFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	host = strings.TrimPrefix(host, "www.")
	if !strings.Contains(host, ".") {
		return ""
	}
	return strings.TrimSuffix(host, ".")
}
