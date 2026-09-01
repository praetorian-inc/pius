package whois

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// LookupDomainHistory walks the commercial providers until one returns records.
func (w *WHOIS) LookupDomainHistory(ctx context.Context, domain string) ([]DomainHistoryRecord, error) {
	domain = RootDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("whois: no registrable domain")
	}
	var errs []error

	results, err := w.doDomainHistoryLookup(ctx, domain, w.WhoxyClient.(WHOISDomainHistoryClient))
	if err == nil && len(results) > 0 {
		return results, nil
	}
	if err != nil {
		errs = append(errs, err)
	}

	results, err = w.doDomainHistoryLookup(ctx, domain, w.WhoisFreaksClient.(WHOISDomainHistoryClient))
	if err == nil && len(results) > 0 {
		return results, nil
	}
	if err != nil {
		errs = append(errs, err)
	}

	results, err = w.doDomainHistoryLookup(ctx, domain, w.WhoisXMLClient.(WHOISDomainHistoryClient))
	if err == nil && len(results) > 0 {
		return results, nil
	}
	if err != nil {
		errs = append(errs, err)
	}

	if len(errs) == 3 {
		return nil, fmt.Errorf("whois: all history methods failed for %s: %w", domain, errors.Join(errs...))
	}
	// If we didn't err on all 3, it means there just are no history records available.
	return nil, nil
}

func (w *WHOIS) doDomainHistoryLookup(ctx context.Context, domain string, client WHOISDomainHistoryClient) ([]DomainHistoryRecord, error) {
	started := time.Now()
	records, err := client.LookupDomainHistory(ctx, domain)
	if err != nil {
		slog.Info("WHOIS history leg failed",
			"resolver", client.Name(), "domain", domain,
			"duration_ms", time.Since(started).Milliseconds())
		return nil, err
	}
	if len(records) == 0 {
		slog.Info("WHOIS history leg returned no records",
			"resolver", client.Name(), "domain", domain,
			"duration_ms", time.Since(started).Milliseconds())
		return nil, nil
	}

	slog.Info("WHOIS history leg complete",
		"resolver", client.Name(), "domain", domain,
		"duration_ms", time.Since(started).Milliseconds(), "records", len(records))
	return records, nil
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
