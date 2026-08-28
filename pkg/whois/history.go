package whois

import (
	"slices"
	"strings"
	"time"
)

const maxDomainHistoryRecords = 30

// DomainHistoryRecord is one historical WHOIS observation.
type DomainHistoryRecord struct {
	DomainResult
	QueryTime string `json:"query_time,omitempty"`
}

func normalizeDomainHistory(domain, provider string, records []DomainHistoryRecord) []DomainHistoryRecord {
	for i := range records {
		if records[i].Domain == "" {
			records[i].Domain = domain
		}
		records[i].Sources = []string{provider}
		records[i].QueryTime = strings.TrimSpace(records[i].QueryTime)
		records[i].Normalize()
	}

	slices.SortStableFunc(records, compareDomainHistoryRecords)
	if len(records) <= maxDomainHistoryRecords {
		return records
	}
	return slices.Clone(records[:maxDomainHistoryRecords])
}

func compareDomainHistoryRecords(left, right DomainHistoryRecord) int {
	leftTime, leftOK := parseDomainHistoryTime(left.QueryTime)
	rightTime, rightOK := parseDomainHistoryTime(right.QueryTime)

	switch {
	case leftOK && rightOK:
		return rightTime.Compare(leftTime)
	case leftOK:
		return -1
	case rightOK:
		return 1
	default:
		return 0
	}
}

func parseDomainHistoryTime(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, time.DateTime, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
