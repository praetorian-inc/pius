package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaybackPlugin_Metadata(t *testing.T) {
	p, ok := plugins.Get("wayback")
	if !ok {
		t.Fatal("wayback plugin not registered")
	}

	assert.Equal(t, "wayback", p.Name())
	assert.Contains(t, p.Description(), "Wayback")
	assert.Equal(t, "domain", p.Category())
	assert.Equal(t, 0, p.Phase(), "wayback is independent (phase 0)")
	assert.Equal(t, plugins.ModePassive, p.Mode())
}

func TestWaybackPlugin_Accepts(t *testing.T) {
	p, ok := plugins.Get("wayback")
	if !ok {
		t.Fatal("wayback plugin not registered")
	}

	tests := []struct {
		name     string
		input    plugins.Input
		expected bool
	}{
		{
			name:     "accepts with domain",
			input:    plugins.Input{Domain: "example.com"},
			expected: true,
		},
		{
			name:     "rejects without domain",
			input:    plugins.Input{OrgName: "Acme Corp"},
			expected: false,
		},
		{
			name:     "rejects empty input",
			input:    plugins.Input{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.Accepts(tt.input))
		})
	}
}

// mockWaybackServer returns an httptest server that serves Wayback CDX JSON responses.
// Wayback CDX with output=json&fl=original returns: [["original"],["url1"],["url2"],...]
// It inspects the url= query parameter for a prefix pattern (e.g. url=a*.example.com) and
// returns URLs from prefixURLs[prefix] if configured, otherwise returns defaultURLs.
func mockWaybackServer(urls []string) *httptest.Server {
	return mockWaybackServerWithPrefixes(urls, nil)
}

// mockWaybackServerWithPrefixes returns a Wayback mock server that handles prefix fan-out queries.
// prefixURLs maps the single-character prefix (e.g. "a", "b") to the URLs that should be returned
// for queries of the form url=a*.domain. An empty-string key handles the apex domain query
// (url=domain without wildcard). If a prefix is not found in the map, defaultURLs is returned.
func mockWaybackServerWithPrefixes(defaultURLs []string, prefixURLs map[string][]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		urlParam := q.Get("url")

		// Detect prefix: url=X*.domain → prefix is the leading character before '*'
		// Apex query: url=domain (no wildcard) → prefix is ""
		prefix := ""
		if starIdx := strings.Index(urlParam, "*"); starIdx > 0 {
			prefix = urlParam[:starIdx]
		}

		var urlsToReturn []string
		if prefixURLs != nil {
			if mapped, ok := prefixURLs[prefix]; ok {
				urlsToReturn = mapped
			} else {
				urlsToReturn = defaultURLs
			}
		} else {
			urlsToReturn = defaultURLs
		}

		w.Header().Set("Content-Type", "application/json")
		rows := [][]string{{"original"}}
		for _, u := range urlsToReturn {
			rows = append(rows, []string{u})
		}
		json.NewEncoder(w).Encode(rows)
	}))
}

// mockWaybackServerWithPages returns a Wayback mock server that supports paging.
// numPages is the page count returned by showNumPages. pageURLs maps page index → urls for that page.
// When numPages <= 0, the showNumPages query returns 0 and all requests return the full urls list.
// Kept for compatibility with tests that haven't been updated to fan-out style.
func mockWaybackServerWithPages(defaultURLs []string, numPages int, pageURLs map[int][]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// showNumPages=true → return plain integer page count
		if q.Get("showNumPages") == "true" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "%d", numPages)
			return
		}

		// page=N → return urls for that specific page
		if pageStr := q.Get("page"); pageStr != "" {
			var page int
			fmt.Sscanf(pageStr, "%d", &page)
			w.Header().Set("Content-Type", "application/json")
			rows := [][]string{{"original"}}
			if pageURLs != nil {
				for _, u := range pageURLs[page] {
					rows = append(rows, []string{u})
				}
			}
			json.NewEncoder(w).Encode(rows)
			return
		}

		// Default: return the full urls list (limit= query, no paging)
		w.Header().Set("Content-Type", "application/json")
		rows := [][]string{{"original"}}
		for _, u := range defaultURLs {
			rows = append(rows, []string{u})
		}
		json.NewEncoder(w).Encode(rows)
	}))
}

// mockCommonCrawlServer returns an httptest server that serves Common Crawl NDJSON responses.
func mockCommonCrawlServer(urls []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// collinfo.json request
		if strings.Contains(r.URL.Path, "collinfo") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]string{
				{"cdx-api": r.Host + "/CC-MAIN-2026-01-index"},
			})
			return
		}
		// CDX index query — returns NDJSON
		w.Header().Set("Content-Type", "text/plain")
		for _, u := range urls {
			fmt.Fprintf(w, `{"url":"%s","status":"200"}%s`, u, "\n")
		}
	}))
}

func TestWaybackPlugin_ParsesWaybackDomains(t *testing.T) {
	wbSrv := mockWaybackServer([]string{
		"http://api.example.com/v1/users",
		"https://staging.example.com/login",
		"http://old.example.com/legacy",
	})
	defer wbSrv.Close()

	// Empty Common Crawl server
	ccSrv := mockCommonCrawlServer(nil)
	defer ccSrv.Close()

	p := &WaybackPlugin{
		client:       client.New(),
		waybackURL:   wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	values := findingValues(findings)
	assert.Contains(t, values, "api.example.com")
	assert.Contains(t, values, "staging.example.com")
	assert.Contains(t, values, "old.example.com")
	for _, f := range findings {
		assert.Equal(t, plugins.FindingDomain, f.Type)
		assert.Equal(t, "wayback", f.Source)
	}
}

func TestWaybackPlugin_ParsesCommonCrawlDomains(t *testing.T) {
	// Empty Wayback server
	wbSrv := mockWaybackServer(nil)
	defer wbSrv.Close()

	ccSrv := mockCommonCrawlServer([]string{
		"http://cdn.example.com/assets/style.css",
		"https://blog.example.com/post/1",
	})
	defer ccSrv.Close()

	p := &WaybackPlugin{
		client:       client.New(),
		waybackURL:   wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	values := findingValues(findings)
	assert.Contains(t, values, "cdn.example.com")
	assert.Contains(t, values, "blog.example.com")
}

func TestWaybackPlugin_DeduplicatesAcrossSources(t *testing.T) {
	// Same domain from both sources
	wbSrv := mockWaybackServer([]string{
		"http://api.example.com/v1",
		"http://api.example.com/v2",
	})
	defer wbSrv.Close()

	ccSrv := mockCommonCrawlServer([]string{
		"https://api.example.com/v3",
	})
	defer ccSrv.Close()

	p := &WaybackPlugin{
		client:       client.New(),
		waybackURL:   wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	count := 0
	for _, f := range findings {
		if f.Value == "api.example.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "api.example.com should appear exactly once")
}

func TestWaybackPlugin_FiltersToSubdomainsOnly(t *testing.T) {
	wbSrv := mockWaybackServer([]string{
		"http://api.example.com/path",
		"http://evil.com/example.com",       // not a subdomain
		"http://notexample.com/something",   // not a subdomain
		"http://example.com/root",           // apex domain — should be included
	})
	defer wbSrv.Close()

	ccSrv := mockCommonCrawlServer(nil)
	defer ccSrv.Close()

	p := &WaybackPlugin{
		client:       client.New(),
		waybackURL:   wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	values := findingValues(findings)
	assert.Contains(t, values, "api.example.com")
	assert.Contains(t, values, "example.com")
	assert.NotContains(t, values, "evil.com")
	assert.NotContains(t, values, "notexample.com")
}

func TestWaybackPlugin_NormalizesDomains(t *testing.T) {
	wbSrv := mockWaybackServer([]string{
		"http://API.EXAMPLE.COM/path",
		"http://api.example.com./trailing-dot",
	})
	defer wbSrv.Close()

	ccSrv := mockCommonCrawlServer(nil)
	defer ccSrv.Close()

	p := &WaybackPlugin{
		client:       client.New(),
		waybackURL:   wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	for _, f := range findings {
		assert.Equal(t, strings.ToLower(f.Value), f.Value, "should be lowercase")
		assert.False(t, strings.HasSuffix(f.Value, "."), "trailing dot should be removed")
	}
	// Both should normalize to same domain — deduped
	assert.Len(t, findings, 1)
	assert.Equal(t, "api.example.com", findings[0].Value)
}

func TestWaybackPlugin_GracefulOnWaybackError(t *testing.T) {
	// Closed server = network error
	wbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	wbSrv.Close()

	ccSrv := mockCommonCrawlServer([]string{
		"http://cdn.example.com/file",
	})
	defer ccSrv.Close()

	p := &WaybackPlugin{
		client:       client.New(),
		waybackURL:   wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	// Should still return Common Crawl results even if Wayback fails
	assert.NoError(t, err)
	values := findingValues(findings)
	assert.Contains(t, values, "cdn.example.com")
}

func TestWaybackPlugin_GracefulOnBothErrors(t *testing.T) {
	wbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	wbSrv.Close()
	ccSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ccSrv.Close()

	p := &WaybackPlugin{
		client:       client.New(),
		waybackURL:   wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWaybackPlugin_HandlesInvalidURLsGracefully(t *testing.T) {
	wbSrv := mockWaybackServer([]string{
		"http://valid.example.com/path",
		"not-a-url",
		"://broken",
		"",
	})
	defer wbSrv.Close()

	ccSrv := mockCommonCrawlServer(nil)
	defer ccSrv.Close()

	p := &WaybackPlugin{
		client:       client.New(),
		waybackURL:   wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	// Should only contain the valid subdomain
	values := findingValues(findings)
	assert.Contains(t, values, "valid.example.com")
	assert.Len(t, findings, 1)
}

// TestWaybackPlugin_PrefixFanoutDiscoversAll verifies that the fan-out strategy discovers
// subdomains returned by different prefix queries. Each prefix query targets a different
// letter prefix, so subdomains that would be skipped by a single paged query are found.
func TestWaybackPlugin_PrefixFanoutDiscoversAll(t *testing.T) {
	prefixURLs := map[string][]string{
		"a": {"http://api.example.com/v1"},
		"s": {"https://staging.example.com/login"},
		"m": {"https://mail.example.com/inbox"},
	}

	wbSrv := mockWaybackServerWithPrefixes(nil, prefixURLs)
	defer wbSrv.Close()

	ccSrv := mockCommonCrawlServer(nil)
	defer ccSrv.Close()

	p := &WaybackPlugin{
		client:         client.New(),
		waybackURL:     wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	values := findingValues(findings)
	assert.Contains(t, values, "api.example.com", "prefix 'a' query should discover api.example.com")
	assert.Contains(t, values, "staging.example.com", "prefix 's' query should discover staging.example.com")
	assert.Contains(t, values, "mail.example.com", "prefix 'm' query should discover mail.example.com")
}

// TestWaybackPlugin_PrefixFanoutApexDomain verifies that the empty-prefix query (apex domain)
// is included in the fan-out and discovers the domain itself.
func TestWaybackPlugin_PrefixFanoutApexDomain(t *testing.T) {
	// Apex query (empty prefix) returns the domain root itself
	prefixURLs := map[string][]string{
		"": {"http://example.com/"},
	}

	wbSrv := mockWaybackServerWithPrefixes(nil, prefixURLs)
	defer wbSrv.Close()

	ccSrv := mockCommonCrawlServer(nil)
	defer ccSrv.Close()

	p := &WaybackPlugin{
		client:         client.New(),
		waybackURL:     wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	findings, err := p.Run(context.Background(), plugins.Input{Domain: "example.com"})

	require.NoError(t, err)
	values := findingValues(findings)
	assert.Contains(t, values, "example.com", "apex domain query should discover example.com itself")
}

// TestWaybackPlugin_PrefixFanoutContextCancellation verifies that a cancelled context
// does not cause panics or hangs in the fan-out goroutine pool.
func TestWaybackPlugin_PrefixFanoutContextCancellation(t *testing.T) {
	wbSrv := mockWaybackServerWithPrefixes([]string{"http://api.example.com/v1"}, nil)
	defer wbSrv.Close()

	ccSrv := mockCommonCrawlServer(nil)
	defer ccSrv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately before Run

	p := &WaybackPlugin{
		client:         client.New(),
		waybackURL:     wbSrv.URL,
		commoncrawlURL: ccSrv.URL,
	}
	// Must not panic or block even with a pre-cancelled context
	_, err := p.Run(ctx, plugins.Input{Domain: "example.com"})
	// Run swallows wayback errors at the top level
	assert.NoError(t, err)
}

// findingValues extracts all .Value fields from findings.
func findingValues(findings []plugins.Finding) []string {
	var vals []string
	for _, f := range findings {
		vals = append(vals, f.Value)
	}
	return vals
}
