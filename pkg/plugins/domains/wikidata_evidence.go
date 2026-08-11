package domains

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func assessRelationship(
	entity entityEvidence,
	targetID string,
	now time.Time,
) relationshipAssessment {
	usable := make([]relationshipClaim, 0, len(entity.relationships))
	ended := make([]relationshipClaim, 0, len(entity.relationships))
	for _, claim := range entity.relationships {
		switch classifyClaim(claim.datedClaim, now) {
		case claimOpenEnded, claimActive:
			usable = append(usable, claim)
		case claimEnded:
			ended = append(ended, claim)
		}
	}
	if len(usable) == 0 {
		return relationshipAssessment{}
	}

	assessment := relationshipAssessment{
		score:           wikidataBaseScore,
		status:          relationshipClaimStatus(usable),
		details:         relationshipDetails(usable),
		referenced:      hasReferencedRelationship(usable),
		reciprocal:      hasReciprocalRelationship(usable),
		hasRelationship: true,
	}

	conflicts := relationshipConflicts(entity, targetID, usable, ended, now)
	if len(conflicts) > 0 {
		assessment.score = wikidataConflictScore
		assessment.status = "conflicting"
		assessment.note = strings.Join(conflicts, " ")
		return assessment
	}

	if assessment.referenced {
		assessment.score += wikidataReferenceScore
	}
	if assessment.reciprocal {
		assessment.score += wikidataReciprocalScore
	}
	assessment.score = min(assessment.score, wikidataMaxScore)
	assessment.note = relationshipDateNote(usable)
	return assessment
}

type claimState int

const (
	claimOpenEnded claimState = iota
	claimActive
	claimFuture
	claimEnded
	claimDeprecated
)

func classifyClaim(claim datedClaim, now time.Time) claimState {
	if claim.rank == "deprecated" || strings.HasSuffix(claim.rank, "DeprecatedRank") {
		return claimDeprecated
	}
	if !claim.start.IsZero() && claim.start.After(now) {
		return claimFuture
	}
	if claim.end.IsZero() {
		return claimOpenEnded
	}
	if claim.end.After(now) {
		return claimActive
	}
	return claimEnded
}

func relationshipConflicts(
	entity entityEvidence,
	targetID string,
	usable []relationshipClaim,
	ended []relationshipClaim,
	now time.Time,
) []string {
	conflicts := []string{}
	if endedRelationshipConflicts(usable, ended) {
		conflicts = append(conflicts, "Wikidata also records this relationship as ended.")
	}

	otherParents := currentAffiliationNames(
		entity.affiliations,
		targetID,
		wikidataPropertyParent,
		now,
	)
	if len(otherParents) > 0 {
		conflicts = append(conflicts,
			fmt.Sprintf("Wikidata also lists %s as a parent organization.", quotedList(otherParents)))
	}
	otherOwners := currentAffiliationNames(entity.affiliations, targetID, "P127", now)
	if len(otherOwners) > 0 {
		conflicts = append(conflicts,
			fmt.Sprintf("Wikidata also lists %s as an owner.", quotedList(otherOwners)))
	}
	if len(conflicts) > 0 {
		conflicts = append(conflicts, "The relationship should be reviewed before treating the domain as in scope.")
	}
	return conflicts
}

func endedRelationshipConflicts(usable, ended []relationshipClaim) bool {
	if len(ended) == 0 {
		return false
	}

	latestEnd := time.Time{}
	for _, claim := range ended {
		if claim.end.After(latestEnd) {
			latestEnd = claim.end
		}
	}
	for _, claim := range usable {
		if !claim.start.IsZero() && claim.start.After(latestEnd) {
			return false
		}
	}
	return true
}

func currentAffiliationNames(
	affiliations []affiliationClaim,
	targetID string,
	property string,
	now time.Time,
) []string {
	names := []string{}
	for _, affiliation := range affiliations {
		if affiliation.property != property ||
			affiliation.entityID == "" ||
			affiliation.entityID == targetID {
			continue
		}
		state := classifyClaim(affiliation.datedClaim, now)
		if state != claimOpenEnded && state != claimActive {
			continue
		}
		names = append(names, affiliation.name)
	}
	slices.Sort(names)
	return strutil.Unique(names)
}

func relationshipDetails(claims []relationshipClaim) []string {
	details := make([]string, 0, len(claims))
	for _, claim := range claims {
		switch claim.property {
		case wikidataPropertySubsidiary:
			details = append(details, "subsidiary (P355)")
		case wikidataPropertyParent:
			details = append(details, "parent organization (P749)")
		}
	}
	slices.Sort(details)
	return strutil.Unique(details)
}

func hasReferencedRelationship(claims []relationshipClaim) bool {
	return slices.ContainsFunc(claims, func(claim relationshipClaim) bool {
		return claim.referenced
	})
}

func hasReciprocalRelationship(claims []relationshipClaim) bool {
	hasSubsidiary := slices.ContainsFunc(claims, func(claim relationshipClaim) bool {
		return claim.property == wikidataPropertySubsidiary
	})
	hasParent := slices.ContainsFunc(claims, func(claim relationshipClaim) bool {
		return claim.property == wikidataPropertyParent
	})
	return hasSubsidiary && hasParent
}

func relationshipClaimStatus(claims []relationshipClaim) string {
	if slices.ContainsFunc(claims, func(claim relationshipClaim) bool {
		return !claim.end.IsZero()
	}) {
		return "active"
	}
	return "open_ended"
}

func relationshipDateNote(claims []relationshipClaim) string {
	for _, claim := range claims {
		if !claim.end.IsZero() {
			return fmt.Sprintf("Wikidata dates the relationship through %s.", formatWikidataDate(claim.end))
		}
	}
	return "Wikidata does not provide an end date for the relationship."
}

func bestWebsitesByDomain(websites []websiteClaim, now time.Time) []websiteClaim {
	best := make(map[string]websiteClaim)
	for _, website := range websites {
		state := classifyClaim(website.datedClaim, now)
		if state != claimOpenEnded && state != claimActive {
			continue
		}

		current, exists := best[website.domain]
		if !exists || betterWebsite(website, current) {
			best[website.domain] = website
		}
	}

	domains := make([]string, 0, len(best))
	for domain := range best {
		domains = append(domains, domain)
	}
	slices.Sort(domains)

	result := make([]websiteClaim, 0, len(domains))
	for _, domain := range domains {
		result = append(result, best[domain])
	}
	return result
}

func betterWebsite(candidate, current websiteClaim) bool {
	if candidate.referenced != current.referenced {
		return candidate.referenced
	}
	return candidate.url < current.url
}

func websiteReferenceScore(website websiteClaim) int {
	if website.referenced {
		return wikidataReferenceScore
	}
	return 0
}

func wikidataJustification(
	orgName string,
	targetID string,
	entity entityEvidence,
	assessment relationshipAssessment,
	website websiteClaim,
) string {
	details := strings.Join(assessment.details, ", ")
	justification := fmt.Sprintf(
		"Wikidata lists %q as a subsidiary of %q and lists %q as its official website (%s; Wikidata items %s and %s).",
		entity.name,
		orgName,
		website.url,
		details,
		targetID,
		entity.id,
	)

	if assessment.note != "" {
		justification += " " + assessment.note
	}
	if assessment.reciprocal {
		justification += " The relationship appears in both organizations' Wikidata records."
	}
	if assessment.referenced && website.referenced {
		justification += " Wikidata includes source references for both the relationship and website statements."
	} else if assessment.referenced || website.referenced {
		justification += " Wikidata includes a source reference for part of this information."
	}
	return justification
}

func betterWikidataFinding(candidate, current plugins.Finding) bool {
	candidateScore := plugins.TotalConfidence(candidate)
	currentScore := plugins.TotalConfidence(current)
	if candidateScore != currentScore {
		return candidateScore > currentScore
	}
	return wikidataFindingID(candidate) < wikidataFindingID(current)
}

func wikidataFindingID(finding plugins.Finding) string {
	id, _ := finding.Data["wikidata_id"].(string)
	return id
}

func quotedList(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = fmt.Sprintf("%q", value)
	}
	return strings.Join(quoted, ", ")
}

func parseWikidataTime(value string) time.Time {
	value = strings.TrimPrefix(value, "+")
	if len(value) < len("2006-01-02") {
		return time.Time{}
	}

	date := value[:len("2006-01-02")]
	parts := strings.Split(date, "-")
	if len(parts) != 3 {
		return time.Time{}
	}
	if parts[1] == "00" {
		parts[1] = "01"
	}
	if parts[2] == "00" {
		parts[2] = "01"
	}
	parsed, err := time.Parse(time.DateOnly, strings.Join(parts, "-"))
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func formatWikidataDate(value time.Time) string {
	return value.Format("January 2006")
}
