package domains

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("wayback", func() plugins.Plugin { return &WaybackPlugin{client: client.New()} })
}

const confWaybackArchiveObservation = 0.60

const (
	archiveSourceWayback     = "Wayback Machine"
	archiveSourceCommonCrawl = "Common Crawl"
)

type archiveObservation struct {
	hostname string
	source   string
}

// WaybackPlugin discovers historical subdomains via Wayback Machine CDX API and Common Crawl index.
type WaybackPlugin struct {
	client         *client.Client
	waybackURL     string // override for testing
	commoncrawlURL string // override for testing
}

// NewWaybackPlugin builds the plugin around a caller-supplied client, so its
// egress runs through the embedder's transport. It needs no credential.
func NewWaybackPlugin(c *client.Client) *WaybackPlugin {
	return &WaybackPlugin{client: c}
}

func (p *WaybackPlugin) waybackBase() string {
	if p.waybackURL != "" {
		return p.waybackURL
	}
	return "http://web.archive.org"
}

func (p *WaybackPlugin) commoncrawlBase() string {
	if p.commoncrawlURL != "" {
		return p.commoncrawlURL
	}
	return "https://index.commoncrawl.org"
}

func (p *WaybackPlugin) Name() string { return "wayback" }
func (p *WaybackPlugin) Description() string {
	return "Wayback Machine / Common Crawl: discovers historical subdomains from archived URLs"
}
func (p *WaybackPlugin) Category() string { return "domain" }
func (p *WaybackPlugin) Phase() int       { return 0 }
func (p *WaybackPlugin) Mode() string     { return plugins.ModePassive }

// Accepts returns true only when a domain is provided. Wayback CDX queries require a domain.
func (p *WaybackPlugin) Accepts(input plugins.Input) bool {
	return input.Domain != ""
}

func (p *WaybackPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	waybackObservations, err := p.queryWayback(ctx, input.Domain)
	if err != nil {
		slog.Debug("wayback CDX query failed", "domain", input.Domain, "err", err)
	}

	commonCrawlObservations, err := p.queryCommonCrawl(ctx, input.Domain)
	if err != nil {
		slog.Debug("common crawl query failed", "domain", input.Domain, "err", err)
	}

	observations := append(waybackObservations, commonCrawlObservations...)
	return p.findingsFromArchiveObservations(observations, input.Domain), nil
}

func (p *WaybackPlugin) findingsFromArchiveObservations(observations []archiveObservation, baseDomain string) []plugins.Finding {
	sourcesByHostname := make(map[string]map[string]bool)
	var hostnames []string
	for _, observation := range observations {
		hostname := normalizeDomain(observation.hostname)
		if hostname == "" || !matchesDomain(hostname, baseDomain) {
			continue
		}
		if sourcesByHostname[hostname] == nil {
			sourcesByHostname[hostname] = make(map[string]bool)
			hostnames = append(hostnames, hostname)
		}
		sourcesByHostname[hostname][observation.source] = true
	}

	findings := make([]plugins.Finding, 0, len(hostnames))
	for _, hostname := range hostnames {
		sources := archiveSources(sourcesByHostname[hostname])
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  hostname,
			Source: p.Name(),
			Confidences: []plugins.Confidence{{
				Score: confWaybackArchiveObservation,
				Justification: fmt.Sprintf("Archive evidence from %s records hostname %q under base domain %q",
					strings.Join(sources, " and "), hostname, baseDomain),
			}},
			Data: map[string]any{
				"base_domain": baseDomain,
			},
		})
	}
	return findings
}

func archiveSources(sourceSet map[string]bool) []string {
	sources := make([]string, 0, len(sourceSet))
	for source := range sourceSet {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return sources
}

const (
	waybackFanoutConcurrency = 10
	waybackPerPrefixLimit    = 1000
)

// queryWayback discovers subdomains by fanning out 37 concurrent CDX queries
// (a-z, 0-9, plus apex domain). Each prefix query targets subdomains starting
// with that character, avoiding the SURT ordering problem where large domains
// consume all result slots before subdomains appear.
func (p *WaybackPlugin) queryWayback(ctx context.Context, domain string) ([]archiveObservation, error) {
	// Build prefix list: a-z, 0-9, then empty string for apex domain
	prefixes := make([]string, 0, 37)
	for c := 'a'; c <= 'z'; c++ {
		prefixes = append(prefixes, string(c))
	}
	for c := '0'; c <= '9'; c++ {
		prefixes = append(prefixes, string(c))
	}
	prefixes = append(prefixes, "") // empty prefix = apex domain query

	var (
		mu              sync.Mutex
		allObservations []archiveObservation
	)
	sem := make(chan struct{}, waybackFanoutConcurrency)

	var wg sync.WaitGroup
	for _, prefix := range prefixes {
		select {
		case <-ctx.Done():
			wg.Wait()
			return allObservations, nil
		default:
		}

		wg.Add(1)
		sem <- struct{}{} // acquire concurrency slot
		go func(pfx string) {
			defer wg.Done()
			defer func() { <-sem }()

			observations, err := p.queryWaybackPrefix(ctx, domain, pfx)
			if err != nil {
				slog.Debug("wayback prefix query failed", "prefix", pfx, "domain", domain, "error", err)
				return
			}
			mu.Lock()
			allObservations = append(allObservations, observations...)
			mu.Unlock()
		}(prefix)
	}
	wg.Wait()

	return allObservations, nil
}

// queryWaybackPrefix queries the CDX API for a single prefix pattern.
// If prefix is empty, queries the apex domain directly.
// The CDX API returns a JSON array of arrays: [["original"],["url1"],["url2"],...]
func (p *WaybackPlugin) queryWaybackPrefix(ctx context.Context, domain, prefix string) ([]archiveObservation, error) {
	var urlStr string
	if prefix == "" {
		// Apex domain query: url=domain.com (no wildcard)
		urlStr = fmt.Sprintf("%s/cdx/search/cdx?url=%s&output=json&fl=original&collapse=urlkey&limit=100",
			p.waybackBase(), url.QueryEscape(domain))
	} else {
		urlStr = fmt.Sprintf("%s/cdx/search/cdx?url=%s*.%s&output=json&fl=original&collapse=urlkey&limit=%d",
			p.waybackBase(), url.QueryEscape(prefix), url.QueryEscape(domain), waybackPerPrefixLimit)
	}

	body, err := p.client.Get(ctx, urlStr)
	if err != nil {
		return nil, fmt.Errorf("wayback CDX request (prefix=%q): %w", prefix, err)
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("parse wayback CDX response: %w", err)
	}

	var observations []archiveObservation
	for i, row := range rows {
		// Skip header row: [["original"]]
		if i == 0 {
			continue
		}
		if len(row) == 0 {
			continue
		}
		host := extractHost(row[0])
		if host != "" {
			observations = append(observations, archiveObservation{hostname: host, source: archiveSourceWayback})
		}
	}
	return observations, nil
}

// queryCommonCrawl fetches the latest Common Crawl index from collinfo.json and then
// queries that index for archived URLs matching the domain.
// The index endpoint returns NDJSON with a "url" field per line.
// On error, returns nil (non-fatal).
func (p *WaybackPlugin) queryCommonCrawl(ctx context.Context, domain string) ([]archiveObservation, error) {
	indexURL, err := p.fetchLatestCCIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch common crawl index list: %w", err)
	}

	queryURL := fmt.Sprintf("%s?url=*.%s&output=json", indexURL, url.QueryEscape(domain))

	body, err := p.client.Get(ctx, queryURL)
	if err != nil {
		return nil, fmt.Errorf("common crawl CDX request: %w", err)
	}

	var observations []archiveObservation
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var record struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			slog.Debug("skipping unparseable common crawl line", "line", line)
			continue
		}
		host := extractHost(record.URL)
		if host != "" {
			observations = append(observations, archiveObservation{hostname: host, source: archiveSourceCommonCrawl})
		}
	}

	return observations, nil
}

// fetchLatestCCIndex fetches the Common Crawl collinfo.json to find the most recent CDX API URL.
func (p *WaybackPlugin) fetchLatestCCIndex(ctx context.Context) (string, error) {
	collinfoURL := fmt.Sprintf("%s/collinfo.json", p.commoncrawlBase())

	body, err := p.client.Get(ctx, collinfoURL)
	if err != nil {
		return "", fmt.Errorf("fetch collinfo.json: %w", err)
	}

	var collections []struct {
		CDXAPI string `json:"cdx-api"`
	}
	if err := json.Unmarshal(body, &collections); err != nil {
		return "", fmt.Errorf("parse collinfo.json: %w", err)
	}

	if len(collections) == 0 {
		return "", fmt.Errorf("no common crawl collections found")
	}

	cdxAPI := collections[0].CDXAPI
	if cdxAPI == "" {
		return "", fmt.Errorf("empty cdx-api in collinfo.json")
	}

	// Ensure the URL has a scheme — the mock returns just host+path without scheme
	if !strings.HasPrefix(cdxAPI, "http://") && !strings.HasPrefix(cdxAPI, "https://") {
		cdxAPI = "http://" + cdxAPI
	}

	return cdxAPI, nil
}

// extractHost parses a URL string and returns only the hostname.
// Returns empty string if the URL is invalid or has no host.
func extractHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
