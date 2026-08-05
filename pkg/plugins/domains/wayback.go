package domains

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("wayback", func() plugins.Plugin { return &WaybackPlugin{client: client.New()} })
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

// Web archives this plugin queries. The archive is retained per hostname
// because the two are independent crawlers: Wayback archives what its crawler
// and its submitters reached, Common Crawl archives what its own crawl found,
// and a host appearing in both was seen by two unrelated observers.
const (
	archiveWayback     = "Wayback Machine"
	archiveCommonCrawl = "Common Crawl"
)

// confArchiveObservation is the evidence weight of one archive holding URLs on a
// host beneath a known domain.
//
// It is review-level on its own, and the reason is time: an archive is a record
// of what existed when it crawled, with no claim about now. A host that was
// archived in 2016 and decommissioned in 2017 is a true archive record and a
// dead asset. What it does establish is zone membership at some point, which is
// why two archives independently holding it adds up to a clean finding — that
// crosses the threshold on corroboration rather than on recency.
const confArchiveObservation = 0.45

// archiveObservation is one hostname together with the archive that held it.
type archiveObservation struct {
	host    string
	archive string
}

func (p *WaybackPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	observations, err := p.queryWayback(ctx, input.Domain)
	if err != nil {
		slog.Debug("wayback CDX query failed", "domain", input.Domain, "err", err)
	}

	ccObservations, err := p.queryCommonCrawl(ctx, input.Domain)
	if err != nil {
		slog.Debug("common crawl query failed", "domain", input.Domain, "err", err)
	}
	observations = append(observations, ccObservations...)

	base := normalizeDomain(input.Domain)

	// Aggregate by hostname, one entry per archive that held it. Many archived
	// URLs on one host from one archive is one crawler's sighting repeated — the
	// archive crawled a site and stored its pages — so those collapse.
	var order []string
	archives := make(map[string][]string)

	for _, observation := range observations {
		host := normalizeDomain(observation.host)
		if host == "" || !matchesDomain(host, base) {
			continue
		}

		held, seen := archives[host]
		if !seen {
			order = append(order, host)
		}
		if slices.Contains(held, observation.archive) {
			continue
		}
		archives[host] = append(held, observation.archive)
	}

	findings := make([]plugins.Finding, 0, len(order))
	for _, host := range order {
		held := archives[host]

		confidences := make([]plugins.Confidence, 0, len(held))
		for _, archive := range held {
			confidences = append(confidences, plugins.Confidence{
				Score:         confArchiveObservation,
				Justification: describeArchiveObservation(archive, host, base),
			})
		}

		findings = append(findings, plugins.Finding{
			Type:        plugins.FindingDomain,
			Value:       host,
			Source:      p.Name(),
			Confidences: confidences,
			Data: map[string]any{
				"base_domain": input.Domain,
				"archives":    strings.Join(held, ","),
				"historical":  true,
			},
		})
	}

	return findings, nil
}

// describeArchiveObservation explains one archive's sighting of a host, and says
// plainly that the evidence is historical.
func describeArchiveObservation(archive, host, base string) string {
	verb := "archived"
	if archive == archiveCommonCrawl {
		verb = "indexed"
	}

	return fmt.Sprintf("%s %s URLs containing hostname %q beneath %q",
		archive, verb, host, base)
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
		mu           sync.Mutex
		observations []archiveObservation
	)
	sem := make(chan struct{}, waybackFanoutConcurrency)

	var wg sync.WaitGroup
	for _, prefix := range prefixes {
		select {
		case <-ctx.Done():
			wg.Wait()
			return observations, nil
		default:
		}

		wg.Add(1)
		sem <- struct{}{} // acquire concurrency slot
		go func(pfx string) {
			defer wg.Done()
			defer func() { <-sem }()

			hosts, err := p.queryWaybackPrefix(ctx, domain, pfx)
			if err != nil {
				slog.Debug("wayback prefix query failed", "prefix", pfx, "domain", domain, "error", err)
				return
			}
			mu.Lock()
			for _, host := range hosts {
				observations = append(observations, archiveObservation{host: host, archive: archiveWayback})
			}
			mu.Unlock()
		}(prefix)
	}
	wg.Wait()

	return observations, nil
}

// queryWaybackPrefix queries the CDX API for a single prefix pattern.
// If prefix is empty, queries the apex domain directly.
// The CDX API returns a JSON array of arrays: [["original"],["url1"],["url2"],...]
func (p *WaybackPlugin) queryWaybackPrefix(ctx context.Context, domain, prefix string) ([]string, error) {
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

	var hosts []string
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
			hosts = append(hosts, host)
		}
	}
	return hosts, nil
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
			observations = append(observations, archiveObservation{host: host, archive: archiveCommonCrawl})
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
