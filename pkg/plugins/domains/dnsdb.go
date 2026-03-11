package domains

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

const (
	dnsdbDefaultBaseURL = "https://api.dnsdb.info"
	dnsdbSplitThreshold = 50
	dnsdbTimeout        = 15 * time.Minute
	dnsdbMaxResponse    = 100 << 20 // 100 MB — DNSDB regex queries can return large result sets
)

// Domains that produce excessive noise and should be excluded from DNSDB queries.
var dnsdbBlacklist = []string{
	"azurewebsites.net",
	"amazonaws.com",
	"github.com",
	"onmicrosoft.com",
}

func init() {
	plugins.Register("dnsdb", func() plugins.Plugin {
		return &DNSDBPlugin{
			doer:    &http.Client{Timeout: dnsdbTimeout},
			baseURL: dnsdbDefaultBaseURL,
		}
	})
}

// httpDoer abstracts HTTP requests for testability.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// DNSDBPlugin discovers subdomains via the DNSDB passive DNS database.
// It accepts a batch of seed domains and uses regex-based query batching
// to minimise API credit consumption.
type DNSDBPlugin struct {
	doer    httpDoer
	baseURL string
}

func (p *DNSDBPlugin) Name() string     { return "dnsdb" }
func (p *DNSDBPlugin) Description() string {
	return "DNSDB: discovers subdomains via passive DNS database (requires DNSDB_API_KEY)"
}
func (p *DNSDBPlugin) Category() string { return "domain" }
func (p *DNSDBPlugin) Phase() int       { return 0 }
func (p *DNSDBPlugin) Mode() string     { return plugins.ModePassive }

// Accepts returns true when a DNSDB API key is set and seed domains are provided.
func (p *DNSDBPlugin) Accepts(input plugins.Input) bool {
	return os.Getenv("DNSDB_API_KEY") != "" && len(input.Domains) > 0
}

// Run queries DNSDB for subdomains of all seed domains using efficient regex batching.
func (p *DNSDBPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("DNSDB_API_KEY")

	parts := parseDomains(input.Domains)
	if len(parts) == 0 {
		return nil, nil
	}

	queries := buildQueries(p.baseURL, parts)

	seen := make(map[string]bool)
	var findings []plugins.Finding

	for _, q := range queries {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		domains, err := p.fetch(ctx, apiKey, q.url)
		if err != nil {
			slog.Warn("dnsdb query failed", "batch", q.label, "error", err)
			continue
		}

		for _, domain := range domains {
			if !seen[domain] {
				seen[domain] = true
				findings = append(findings, plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  domain,
					Source: p.Name(),
					Data: map[string]any{
						"org": input.OrgName,
					},
				})
			}
		}
	}

	return findings, nil
}

// --- domain parsing and grouping ---

// domainParts holds a seed domain split into its registrable name and public suffix.
type domainParts struct {
	name   string // e.g. "acme" for acme.com, "sub.acme" for sub.acme.co.uk
	suffix string // e.g. "com", "co.uk"
}

// parseDomains splits seed domains into (name, suffix) pairs, filtering blacklisted entries.
func parseDomains(domains []string) []domainParts {
	var out []domainParts
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if isBlacklisted(d) {
			continue
		}

		suffix, _ := publicsuffix.PublicSuffix(d)
		name := strings.TrimSuffix(d, "."+suffix)
		if name == "" || name == d {
			continue
		}
		out = append(out, domainParts{name: name, suffix: suffix})
	}
	return out
}

func isBlacklisted(domain string) bool {
	for _, bl := range dnsdbBlacklist {
		if domain == bl || strings.HasSuffix(domain, "."+bl) {
			return true
		}
	}
	return false
}

// --- query building ---

// dnsdbQuery is a single DNSDB API request to execute.
type dnsdbQuery struct {
	url   string
	label string // human-readable description for logging
}

// buildQueries creates batched regex queries from parsed domain parts.
//
// Domains that share the same name but differ in TLD are grouped by name
// (e.g. acme under [com, org] → regex: \.acme\.(com|org)\.$/ANY).
//
// Remaining domains are grouped by TLD
// (e.g. [alpha, beta] under com → regex: \.(alpha|beta)\.com\.$/ANY).
func buildQueries(baseURL string, parts []domainParts) []dnsdbQuery {
	// Group by name to detect multi-TLD names.
	nameToSuffixes := make(map[string]map[string]bool)
	for _, dp := range parts {
		if nameToSuffixes[dp.name] == nil {
			nameToSuffixes[dp.name] = make(map[string]bool)
		}
		nameToSuffixes[dp.name][dp.suffix] = true
	}

	multiTLD := make(map[string]bool)
	var queries []dnsdbQuery

	// Multi-TLD names: group by name, batch TLDs.
	for name, suffixSet := range nameToSuffixes {
		if len(suffixSet) <= 1 {
			continue
		}
		multiTLD[name] = true
		suffixes := setToSlice(suffixSet)
		queries = append(queries, batchByDomain(baseURL, name, suffixes)...)
	}

	// Single-TLD: group by suffix, batch names.
	suffixToNames := make(map[string][]string)
	for _, dp := range parts {
		if multiTLD[dp.name] {
			continue
		}
		suffixToNames[dp.suffix] = append(suffixToNames[dp.suffix], dp.name)
	}
	for suffix, names := range suffixToNames {
		names = uniqueStrings(names)
		queries = append(queries, batchByTLD(baseURL, suffix, names)...)
	}

	return queries
}

// batchByDomain creates queries for a single domain name appearing under multiple TLDs.
// Pattern: \.{name}\.({tld1}|{tld2}|...)\.$/ANY
func batchByDomain(baseURL, name string, suffixes []string) []dnsdbQuery {
	var queries []dnsdbQuery
	for i := 0; i < len(suffixes); i += dnsdbSplitThreshold {
		end := min(i+dnsdbSplitThreshold, len(suffixes))
		batch := suffixes[i:end]

		escapedName := escapeDots(name)
		pattern := fmt.Sprintf(`\.%s\.(%s)\.$/ANY`, escapedName, strings.Join(batch, "|"))
		url := fmt.Sprintf("%s/dnsdb/v2/regex/rrnames/%s?limit=0", baseURL, pattern)
		queries = append(queries, dnsdbQuery{
			url:   url,
			label: fmt.Sprintf("domain=%s tlds=%d", name, len(batch)),
		})
	}
	return queries
}

// batchByTLD creates queries for multiple domain names sharing the same TLD.
// Pattern: \.({name1}|{name2}|...)\.{tld}\.$/ANY
func batchByTLD(baseURL, suffix string, names []string) []dnsdbQuery {
	var queries []dnsdbQuery
	for i := 0; i < len(names); i += dnsdbSplitThreshold {
		end := min(i+dnsdbSplitThreshold, len(names))
		batch := names[i:end]

		escaped := make([]string, len(batch))
		for j, n := range batch {
			escaped[j] = escapeDots(n)
		}
		escapedSuffix := escapeDots(suffix)
		pattern := fmt.Sprintf(`\.(%s)\.%s\.$/ANY`, strings.Join(escaped, "|"), escapedSuffix)
		url := fmt.Sprintf("%s/dnsdb/v2/regex/rrnames/%s?limit=0", baseURL, pattern)
		queries = append(queries, dnsdbQuery{
			url:   url,
			label: fmt.Sprintf("tld=%s names=%d", suffix, len(batch)),
		})
	}
	return queries
}

func escapeDots(s string) string {
	return strings.ReplaceAll(s, ".", "\\.")
}

// --- DNSDB API interaction ---

// fetch executes a single DNSDB query and returns deduplicated domain names.
func (p *DNSDBPlugin) fetch(ctx context.Context, apiKey, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Accept", "application/x-ndjson")

	resp, err := p.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dnsdb request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dnsdb returned status %d", resp.StatusCode)
	}

	return parseNDJSON(io.LimitReader(resp.Body, dnsdbMaxResponse))
}

// dnsdbRecord represents a single DNSDB NDJSON record.
type dnsdbRecord struct {
	Obj *struct {
		RRName string `json:"rrname"`
		RRType string `json:"rrtype"`
	} `json:"obj"`
}

// parseNDJSON reads DNSDB NDJSON response and extracts unique domain names.
// Only A, CNAME, NS, and SOA record types are included.
func parseNDJSON(r io.Reader) ([]string, error) {
	validTypes := map[string]bool{"A": true, "CNAME": true, "NS": true, "SOA": true}
	seen := make(map[string]bool)
	var domains []string

	scanner := bufio.NewScanner(r)
	// DNSDB can return very long lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec dnsdbRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // skip metadata/malformed lines
		}
		if rec.Obj == nil {
			continue
		}
		if !validTypes[rec.Obj.RRType] {
			continue
		}

		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rec.Obj.RRName), "."))
		if domain == "" {
			continue
		}
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}

	return domains, scanner.Err()
}

// --- helpers ---

func setToSlice(s map[string]bool) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

func uniqueStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
