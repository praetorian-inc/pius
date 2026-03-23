package domains

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/twmb/murmur3"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("favicon-hash", func() plugins.Plugin {
		return &FaviconHashPlugin{client: client.New()}
	})
}

// FaviconHashPlugin discovers related infrastructure by computing MurmurHash3
// of a target's favicon and querying internet scanners (Shodan, FOFA) for
// hosts sharing the same favicon hash. This technique reveals origin IPs
// behind CDNs, subsidiaries, staging environments, and internal services.
//
// Phase 0 (independent): runs concurrently, requires Domain + SHODAN_API_KEY.
// Mode: Active (fetches favicon from target).
type FaviconHashPlugin struct {
	client     *client.Client
	faviconURL string // override for testing; empty means https://{domain}/favicon.ico
	shodanURL  string // override for testing; empty means real Shodan API
	fofaURL    string // override for testing; empty means real FOFA API
}

func (p *FaviconHashPlugin) Name() string { return "favicon-hash" }
func (p *FaviconHashPlugin) Description() string {
	return "Favicon Hash: discovers related infrastructure via MurmurHash3 favicon matching on Shodan/FOFA (requires SHODAN_API_KEY)"
}
func (p *FaviconHashPlugin) Category() string { return "domain" }
func (p *FaviconHashPlugin) Phase() int       { return 0 }
func (p *FaviconHashPlugin) Mode() string     { return plugins.ModeActive }

func (p *FaviconHashPlugin) Accepts(input plugins.Input) bool {
	return isDomainName(input.Domain) && os.Getenv("SHODAN_API_KEY") != ""
}

func (p *FaviconHashPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	// Step 1: Fetch favicon
	faviconBody, err := p.fetchFavicon(ctx, input.Domain)
	if err != nil {
		slog.Warn("favicon-hash: failed to fetch favicon", "domain", input.Domain, "error", err)
		return nil, nil // graceful degradation
	}
	if len(faviconBody) == 0 {
		return nil, nil
	}

	// Step 2: Base64-encode per RFC 2045 (76-char wrapped lines) and compute hash
	hash := faviconHash(faviconBody)

	// Step 3: Query Shodan and FOFA concurrently
	var findings []plugins.Finding

	shodanFindings, err := p.queryShodan(ctx, hash, input)
	if err != nil {
		slog.Warn("favicon-hash: Shodan query failed", "error", err)
	} else {
		findings = append(findings, shodanFindings...)
	}

	if os.Getenv("FOFA_API_KEY") != "" {
		fofaFindings, err := p.queryFOFA(ctx, hash, input)
		if err != nil {
			slog.Warn("favicon-hash: FOFA query failed", "error", err)
		} else {
			findings = append(findings, fofaFindings...)
		}
	}

	// Deduplicate findings by value
	return deduplicateFindings(findings, p.Name()), nil
}

// fetchFavicon downloads the favicon from the target domain.
func (p *FaviconHashPlugin) fetchFavicon(ctx context.Context, domain string) ([]byte, error) {
	faviconURL := fmt.Sprintf("https://%s/favicon.ico", domain)
	if p.faviconURL != "" {
		faviconURL = p.faviconURL
	}
	return p.client.GetWithHeaders(ctx, faviconURL, map[string]string{
		"Accept": "image/x-icon,image/*,*/*",
	})
}

// faviconHash computes the MurmurHash3 of a favicon body using the standard
// technique: base64-encode with RFC 2045 line wrapping (76 chars), then hash.
func faviconHash(body []byte) int32 {
	encoded := base64RFC2045(body)
	return int32(murmur3.Sum32([]byte(encoded)))
}

// base64RFC2045 encodes data to base64 with 76-character line wrapping
// per RFC 2045, matching the encoding used by httpx and Shodan.
func base64RFC2045(data []byte) string {
	raw := base64.StdEncoding.EncodeToString(data)
	var wrapped strings.Builder
	wrapped.Grow(len(raw) + len(raw)/76 + 1)
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		wrapped.WriteString(raw[i:end])
		wrapped.WriteByte('\n')
	}
	return wrapped.String()
}

// queryShodan queries Shodan for hosts matching the favicon hash.
func (p *FaviconHashPlugin) queryShodan(ctx context.Context, hash int32, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("SHODAN_API_KEY")
	base := "https://api.shodan.io"
	if p.shodanURL != "" {
		base = p.shodanURL
	}

	query := fmt.Sprintf("http.favicon.hash:%d", hash)
	reqURL := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s",
		base, url.QueryEscape(apiKey), url.QueryEscape(query))

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("shodan request: %w", err)
	}

	return parseShodanResponse(body, hash, input)
}

// shodanResponse mirrors the subset of the Shodan /shodan/host/search response we use.
type shodanResponse struct {
	Matches []shodanMatch `json:"matches"`
}

type shodanMatch struct {
	IPStr     string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
}

func parseShodanResponse(body []byte, hash int32, input plugins.Input) ([]plugins.Finding, error) {
	var resp shodanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse shodan response: %w", err)
	}

	var findings []plugins.Finding
	for _, match := range resp.Matches {
		data := map[string]any{
			"org":           input.OrgName,
			"source_domain": input.Domain,
			"favicon_hash":  hash,
			"scanner":       "shodan",
		}

		// Emit IP as CIDR (/32)
		if match.IPStr != "" {
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingCIDR,
				Value:  match.IPStr + "/32",
				Source: "favicon-hash",
				Data:   copyData(data),
			})
		}

		// Emit hostnames as domains
		for _, hostname := range match.Hostnames {
			hostname = normalizeFaviconHost(hostname)
			if hostname == "" {
				continue
			}
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  hostname,
				Source: "favicon-hash",
				Data:   copyData(data),
			})
		}
	}
	return findings, nil
}

// queryFOFA queries FOFA for hosts matching the favicon hash.
func (p *FaviconHashPlugin) queryFOFA(ctx context.Context, hash int32, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := os.Getenv("FOFA_API_KEY")
	base := "https://fofa.info"
	if p.fofaURL != "" {
		base = p.fofaURL
	}

	// FOFA expects base64-encoded query
	query := fmt.Sprintf(`icon_hash="%d"`, hash)
	encodedQuery := base64.StdEncoding.EncodeToString([]byte(query))

	reqURL := fmt.Sprintf("%s/api/v1/search/all?key=%s&qbase64=%s&fields=host,ip",
		base, url.QueryEscape(apiKey), url.QueryEscape(encodedQuery))

	body, err := p.client.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("fofa request: %w", err)
	}

	return parseFOFAResponse(body, hash, input)
}

// fofaResponse mirrors the subset of the FOFA /api/v1/search/all response we use.
type fofaResponse struct {
	Results [][]string `json:"results"` // each entry is [host, ip]
}

func parseFOFAResponse(body []byte, hash int32, input plugins.Input) ([]plugins.Finding, error) {
	var resp fofaResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse fofa response: %w", err)
	}

	var findings []plugins.Finding
	for _, result := range resp.Results {
		if len(result) < 2 {
			continue
		}
		host, ip := result[0], result[1]
		data := map[string]any{
			"org":           input.OrgName,
			"source_domain": input.Domain,
			"favicon_hash":  hash,
			"scanner":       "fofa",
		}

		if ip != "" {
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingCIDR,
				Value:  ip + "/32",
				Source: "favicon-hash",
				Data:   copyData(data),
			})
		}

		host = normalizeFaviconHost(host)
		if host != "" {
			findings = append(findings, plugins.Finding{
				Type:   plugins.FindingDomain,
				Value:  host,
				Source: "favicon-hash",
				Data:   copyData(data),
			})
		}
	}
	return findings, nil
}

// normalizeFaviconHost normalizes a hostname from scanner results:
// strips scheme/path (FOFA hosts may include them), lowercases, removes trailing dots.
func normalizeFaviconHost(d string) string {
	d = strings.TrimSpace(d)
	// Strip scheme if present (FOFA hosts may include it)
	d = stripScheme(d)
	return normalizeDomain(d)
}

// deduplicateFindings removes duplicate findings by type+value, keeping the first.
func deduplicateFindings(findings []plugins.Finding, source string) []plugins.Finding {
	type key struct {
		typ   plugins.FindingType
		value string
	}
	seen := make(map[key]bool, len(findings))
	result := make([]plugins.Finding, 0, len(findings))
	for _, f := range findings {
		k := key{f.Type, f.Value}
		if !seen[k] {
			seen[k] = true
			result = append(result, f)
		}
	}
	return result
}

// copyData creates a shallow copy of a data map for safe reuse.
func copyData(d map[string]any) map[string]any {
	cp := make(map[string]any, len(d))
	for k, v := range d {
		cp[k] = v
	}
	return cp
}
