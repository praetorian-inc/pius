package domains

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

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

func (p *WaybackPlugin) Name() string        { return "wayback" }
func (p *WaybackPlugin) Description() string { return "Wayback Machine / Common Crawl: discovers historical subdomains from archived URLs" }
func (p *WaybackPlugin) Category() string    { return "domain" }
func (p *WaybackPlugin) Phase() int          { return 0 }
func (p *WaybackPlugin) Mode() string        { return plugins.ModePassive }

// Accepts returns true only when a domain is provided. Wayback CDX queries require a domain.
func (p *WaybackPlugin) Accepts(input plugins.Input) bool {
	return input.Domain != ""
}

func (p *WaybackPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	seen := make(map[string]bool)
	var findings []plugins.Finding

	wbHosts, err := p.queryWayback(ctx, input.Domain)
	if err != nil {
		slog.Debug("wayback CDX query failed", "domain", input.Domain, "err", err)
	}

	ccHosts, err := p.queryCommonCrawl(ctx, input.Domain)
	if err != nil {
		slog.Debug("common crawl query failed", "domain", input.Domain, "err", err)
	}

	allHosts := append(wbHosts, ccHosts...)
	for _, host := range allHosts {
		host = normalizeHost(host)
		if host == "" {
			continue
		}
		if !isSubdomainOf(host, input.Domain) {
			continue
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  host,
			Source: p.Name(),
			Data: map[string]any{
				"base_domain": input.Domain,
			},
		})
	}

	return findings, nil
}

// queryWayback queries the Wayback Machine CDX API and returns discovered hostnames.
// The CDX API returns a JSON array of arrays: [["original"],["url1"],["url2"],...]
// On error, returns nil (non-fatal).
func (p *WaybackPlugin) queryWayback(ctx context.Context, domain string) ([]string, error) {
	urlStr := fmt.Sprintf(
		"%s/cdx/search/cdx?url=*.%s&output=json&fl=original&collapse=urlkey&limit=10000",
		p.waybackBase(),
		url.QueryEscape(domain),
	)

	body, err := p.client.Get(ctx, urlStr)
	if err != nil {
		return nil, fmt.Errorf("wayback CDX request: %w", err)
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
func (p *WaybackPlugin) queryCommonCrawl(ctx context.Context, domain string) ([]string, error) {
	indexURL, err := p.fetchLatestCCIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch common crawl index list: %w", err)
	}

	queryURL := fmt.Sprintf("%s?url=*.%s&output=json", indexURL, url.QueryEscape(domain))

	body, err := p.client.Get(ctx, queryURL)
	if err != nil {
		return nil, fmt.Errorf("common crawl CDX request: %w", err)
	}

	var hosts []string
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
			hosts = append(hosts, host)
		}
	}

	return hosts, nil
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

// normalizeHost lowercases, trims whitespace, and removes trailing dots from a hostname.
func normalizeHost(host string) string {
	host = strings.ToLower(host)
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return host
}

// isSubdomainOf returns true if host equals domain or is a subdomain of domain.
func isSubdomainOf(host, domain string) bool {
	domain = strings.ToLower(domain)
	host = strings.ToLower(host)
	return host == domain || strings.HasSuffix(host, "."+domain)
}
