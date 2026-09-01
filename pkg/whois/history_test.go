package whois

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeDomainHistory(t *testing.T) {
	records := make([]DomainHistoryRecord, 0, 33)
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	for day := range 32 {
		records = append(records, DomainHistoryRecord{
			DomainResult: DomainResult{Registrar: fmt.Sprintf("Registrar %d", day)},
			QueryTime:    start.AddDate(0, 0, day).Format(time.DateTime),
		})
	}
	records = append(records, DomainHistoryRecord{
		DomainResult: DomainResult{Registrar: "Undated Registrar"},
	})

	result := normalizeDomainHistory("example.com", ProviderWhoxy, records)

	require.Len(t, result, maxDomainHistoryRecords)
	assert.Equal(t, "2026-08-01 00:00:00", result[0].QueryTime)
	assert.Equal(t, "2026-07-03 00:00:00", result[len(result)-1].QueryTime)
	for _, record := range result {
		assert.Equal(t, "example.com", record.Domain)
		assert.Equal(t, []string{ProviderWhoxy}, record.Sources)
	}
}

func TestNormalizeDomainHistory_SortsUndatedRecordsLast(t *testing.T) {
	records := []DomainHistoryRecord{
		{DomainResult: DomainResult{Registrar: "Undated One"}},
		{DomainResult: DomainResult{Registrar: "Older"}, QueryTime: "2024-01-01T00:00:00Z"},
		{DomainResult: DomainResult{Registrar: "Newest"}, QueryTime: "2025-01-01T00:00:00Z"},
		{DomainResult: DomainResult{Registrar: "Undated Two"}},
	}

	result := normalizeDomainHistory("example.com", ProviderWhoisXML, records)

	require.Len(t, result, 4)
	assert.Equal(t, []string{"Newest", "Older", "Undated One", "Undated Two"}, []string{
		result[0].Registrar,
		result[1].Registrar,
		result[2].Registrar,
		result[3].Registrar,
	})
}
