package domains

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

//go:embed wordlists/subdomains.txt
var defaultDoHWordlist string

const (
	dohEnumConcurrency    = 50
	dohEnumChannelBufSize = 1000
	dohEnumMaxRetries     = 3
)

// dohHTTPDoer abstracts HTTP operations for DoH queries (testability).
type dohHTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// DoHEndpoint holds configuration for a single DoH server or proxy.
type DoHEndpoint struct {
	URL  string
	Name string
}

// defaultDoHEndpoints are the built-in DoH resolvers.
var defaultDoHEndpoints = []DoHEndpoint{
	{URL: "https://cloudflare-dns.com/dns-query", Name: "cloudflare"},
	{URL: "https://dns.google/resolve", Name: "google"},
	{URL: "https://dns.adguard.com/dns-query", Name: "adguard"},
}

func init() {
	plugins.Register("doh-enum", func() plugins.Plugin {
		return &DoHEnumPlugin{
			doer: &http.Client{Timeout: 10 * time.Second},
		}
	})
}

// DoHEnumPlugin performs active subdomain enumeration using DNS-over-HTTPS resolvers.
// It supports a three-stage concurrent pipeline: generate → resolve → collect.
type DoHEnumPlugin struct {
	doer dohHTTPDoer
}

func (p *DoHEnumPlugin) Name() string        { return "doh-enum" }
func (p *DoHEnumPlugin) Description() string { return "Subdomain enumeration via DNS-over-HTTPS (DoH)" }
func (p *DoHEnumPlugin) Category() string    { return "domain" }
func (p *DoHEnumPlugin) Phase() int          { return 0 }
func (p *DoHEnumPlugin) Mode() string        { return plugins.ModeActive }

// Accepts requires a Domain to enumerate.
func (p *DoHEnumPlugin) Accepts(input plugins.Input) bool {
	return isDomainName(input.Domain)
}

// Run executes the three-stage pipeline: generate FQDNs → DoH query → collect findings.
func (p *DoHEnumPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	domain := normalizeDomain(input.Domain)

	// Resolve wordlist
	wordlist, err := p.resolveWordlist(input.Meta)
	if err != nil {
		return nil, fmt.Errorf("doh-enum: load wordlist: %w", err)
	}

	// Resolve endpoints (priority: deploy gateways > provided gateways > provided servers > defaults)
	endpoints, cleanup, err := p.resolveEndpoints(ctx, input.Meta)
	if err != nil {
		slog.Warn("doh-enum: endpoint resolution failed, using defaults", "error", err)
		endpoints = defaultDoHEndpoints
		cleanup = func() {}
	}
	defer cleanup()

	if len(endpoints) == 0 {
		endpoints = defaultDoHEndpoints
	}

	// Detect wildcard DNS — if domain resolves everything, skip enumeration.
	if p.detectWildcardDoH(ctx, domain, endpoints) {
		return nil, nil
	}

	// Stage 1: generator → subdomainCh
	subdomainCh := make(chan string, dohEnumChannelBufSize)
	go func() {
		defer close(subdomainCh)
		for _, word := range wordlist {
			select {
			case <-ctx.Done():
				return
			case subdomainCh <- word + "." + domain:
			}
		}
	}()

	// Stage 2: worker pool → resultCh
	resultCh := make(chan plugins.Finding, dohEnumChannelBufSize)

	numEndpoints := len(endpoints)
	var endpointIdx atomic.Uint64

	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		var wg sync.WaitGroup
		sem := make(chan struct{}, dohEnumConcurrency)

		for fqdn := range subdomainCh {
			if ctx.Err() != nil {
				return
			}

			sem <- struct{}{}
			idx := endpointIdx.Add(1) - 1
			primaryIdx := int(idx) % numEndpoints
			rotation := buildRotation(endpoints, primaryIdx)

			wg.Add(1)
			go func(fqdn string, rot []DoHEndpoint) {
				defer wg.Done()
				defer func() { <-sem }()

				if finding, ok := p.queryWithRetry(ctx, fqdn, rot); ok {
					select {
					case resultCh <- finding:
					case <-ctx.Done():
					}
				}
			}(fqdn, rotation)
		}

		wg.Wait()
	}()

	// Stage 3: collector
	go func() {
		<-workerDone
		close(resultCh)
	}()

	var findings []plugins.Finding
	for f := range resultCh {
		findings = append(findings, f)
	}

	return findings, nil
}

// detectWildcardDoH queries a random non-existent subdomain via DoH to detect wildcard DNS.
// Returns true if the domain has wildcard DNS (the random subdomain resolves).
func (p *DoHEnumPlugin) detectWildcardDoH(ctx context.Context, domain string, endpoints []DoHEndpoint) bool {
	randomLabel := randomHex(16)
	fqdn := randomLabel + "." + domain

	for _, ep := range endpoints {
		exists, err := p.queryDoH(ctx, fqdn, ep)
		if err != nil {
			continue
		}
		if exists {
			slog.Info("doh-enum: wildcard detected", "domain", domain)
			return true
		}
		// If we got a clean NXDOMAIN, no wildcard
		return false
	}
	// All endpoints failed — assume no wildcard (fail open)
	return false
}

// queryWithRetry performs a DoH JSON query for fqdn, retrying with different
// endpoints on rate-limit (429) or server errors (5xx). Returns (finding, true)
// when the subdomain exists. rotation[0] is the primary endpoint; subsequent
// entries are used for retries in order.
func (p *DoHEnumPlugin) queryWithRetry(ctx context.Context, fqdn string, rotation []DoHEndpoint) (plugins.Finding, bool) {
	for attempt := 0; attempt < dohEnumMaxRetries; attempt++ {
		ep := rotation[attempt%len(rotation)]
		exists, err := p.queryDoH(ctx, fqdn, ep)
		if err == nil {
			if exists {
				return plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  fqdn,
					Source: "doh-enum",
					Data: map[string]any{
						"method":   "doh-enum",
						"resolver": rotation[0].Name,
					},
				}, true
			}
			return plugins.Finding{}, false
		}

		// Only retry on retryable errors
		if !isRetryableDoHError(err) {
			slog.Debug("doh-enum: non-retryable error", "fqdn", fqdn, "error", err)
			return plugins.Finding{}, false
		}

		slog.Debug("doh-enum: retryable error, trying next endpoint", "fqdn", fqdn, "attempt", attempt+1, "error", err)
	}

	return plugins.Finding{}, false
}

// buildRotation constructs an endpoint rotation slice with the primary endpoint
// (at primaryIdx) first, followed by the remaining endpoints in order.
func buildRotation(endpoints []DoHEndpoint, primaryIdx int) []DoHEndpoint {
	rotation := make([]DoHEndpoint, 0, len(endpoints))
	rotation = append(rotation, endpoints[primaryIdx])
	for i, ep := range endpoints {
		if i != primaryIdx {
			rotation = append(rotation, ep)
		}
	}
	return rotation
}

// dohResponse represents the JSON response from a DoH server.
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// dohError types for retry logic.
type dohRateLimitError struct{ msg string }
type dohServerError struct{ msg string }

func (e *dohRateLimitError) Error() string { return e.msg }
func (e *dohServerError) Error() string    { return e.msg }

func isRetryableDoHError(err error) bool {
	switch err.(type) {
	case *dohRateLimitError, *dohServerError:
		return true
	}
	return false
}

// queryDoH performs a single DNS-over-HTTPS JSON query.
// Returns (true, nil) when the domain exists (NOERROR + answers).
// Returns (false, nil) for NXDOMAIN.
// Returns (false, err) on HTTP errors.
func (p *DoHEnumPlugin) queryDoH(ctx context.Context, fqdn string, endpoint DoHEndpoint) (bool, error) {
	reqURL := endpoint.URL + "?" + url.Values{"name": {fqdn}, "type": {"A"}}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := p.doer.Do(req)
	if err != nil {
		return false, fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return false, &dohRateLimitError{msg: fmt.Sprintf("rate limited by %s", endpoint.URL)}
	}
	if resp.StatusCode >= 500 {
		return false, &dohServerError{msg: fmt.Sprintf("server error %d from %s", resp.StatusCode, endpoint.URL)}
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, endpoint.URL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10)) // 64 KB limit
	if err != nil {
		return false, fmt.Errorf("read response: %w", err)
	}

	var result dohResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("parse response: %w", err)
	}

	// NOERROR (0) with at least one answer means the domain exists
	return result.Status == 0 && len(result.Answer) > 0, nil
}

// resolveEndpoints determines which DoH endpoints to use based on Meta configuration.
// Priority:
//  1. doh_deploy_gateways=true + doh_servers → deploy API gateways
//  2. doh_gateways → use provided gateway URLs
//  3. doh_servers (no deployment) → use directly
//  4. fallback → default DoH servers
func (p *DoHEnumPlugin) resolveEndpoints(ctx context.Context, meta map[string]string) ([]DoHEndpoint, func(), error) {
	if meta == nil {
		return defaultDoHEndpoints, func() {}, nil
	}

	deployGateways := meta["doh_deploy_gateways"] == "true"
	serversCSV := meta["doh_servers"]
	gatewaysCSV := meta["doh_gateways"]

	// Priority 1: deploy gateways
	if deployGateways && serversCSV != "" {
		servers := parseCSV(serversCSV)
		endpoints, cleanup, err := deployAPIGateways(ctx, servers)
		if err != nil {
			return nil, func() {}, fmt.Errorf("deploy gateways: %w", err)
		}
		return endpoints, cleanup, nil
	}

	// Priority 2: provided gateway URLs
	if gatewaysCSV != "" {
		endpoints := urlsToEndpoints(parseCSV(gatewaysCSV), "gateway")
		return endpoints, func() {}, nil
	}

	// Priority 3: provided server URLs (direct use)
	if serversCSV != "" {
		endpoints := urlsToEndpoints(parseCSV(serversCSV), "custom")
		return endpoints, func() {}, nil
	}

	// Priority 4: defaults
	return defaultDoHEndpoints, func() {}, nil
}

// resolveWordlist returns the wordlist to use for enumeration.
// If meta["doh_wordlist"] is set, loads from that file path; otherwise uses the embedded default.
func (p *DoHEnumPlugin) resolveWordlist(meta map[string]string) ([]string, error) {
	if meta != nil {
		if path, ok := meta["doh_wordlist"]; ok && path != "" {
			return loadWordlistFile(path)
		}
	}
	// Use embedded default wordlist
	return parseWordlist(defaultDoHWordlist), nil
}

// loadWordlistFile reads a wordlist from a file path.
func loadWordlistFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wordlist %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read wordlist %s: %w", path, err)
	}
	return words, nil
}

// parseCSV splits a comma-separated string into trimmed, non-empty values.
func parseCSV(csv string) []string {
	parts := strings.Split(csv, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// urlsToEndpoints converts URL strings into DoHEndpoints.
func urlsToEndpoints(urls []string, namePrefix string) []DoHEndpoint {
	endpoints := make([]DoHEndpoint, 0, len(urls))
	for i, u := range urls {
		endpoints = append(endpoints, DoHEndpoint{
			URL:  u,
			Name: fmt.Sprintf("%s-%d", namePrefix, i),
		})
	}
	return endpoints
}
