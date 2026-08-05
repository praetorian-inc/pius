package domains

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"slices"
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

	// Collapse repeats within each scanner, keep both scanners' evidence.
	return mergeScannerFindings(findings), nil
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
		findings = appendFaviconMatch(findings, scannerShodan, match.IPStr, match.Hostnames, hash, input)
	}
	return findings, nil
}

// appendFaviconMatch emits the IP and hostnames of one scanner match.
//
// Both scanners produce the same two finding shapes from the same evidence, and
// differ only in how their JSON is decoded — so decoding is all their parse
// functions do, and the emit half lives here once.
func appendFaviconMatch(findings []plugins.Finding, scanner, ip string, hostnames []string, hash int32, input plugins.Input) []plugins.Finding {
	data := map[string]any{
		"org":           input.OrgName,
		"source_domain": input.Domain,
		"favicon_hash":  hash,
		"scanner":       scanner,
	}

	// Emit IP as CIDR (/32)
	if ip != "" {
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingCIDR,
			Value:  ip + "/32",
			Source: "favicon-hash",
			Confidences: []plugins.Confidence{{
				Score:         confSharedFaviconHash,
				Justification: describeFaviconMatch(scanner, "IP "+ip, hash, input.Domain),
			}},
			Data: copyData(data),
		})
	}

	// Emit hostnames as domains
	for _, hostname := range hostnames {
		hostname = normalizeFaviconHost(hostname)
		if hostname == "" {
			continue
		}
		findings = append(findings, plugins.Finding{
			Type:   plugins.FindingDomain,
			Value:  hostname,
			Source: "favicon-hash",
			Confidences: []plugins.Confidence{{
				Score: confSharedFaviconHash,
				Justification: describeFaviconMatch(scanner,
					fmt.Sprintf("host %q", hostname), hash, input.Domain),
			}},
			Data: copyData(data),
		})
	}

	return findings
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
		findings = appendFaviconMatch(findings, scannerFOFA, ip, []string{host}, hash, input)
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

// Scanners this plugin asks about a favicon hash. The identifiers are the stable
// machine-readable form that Data and the merge key use; scannerDisplayName
// renders them for justifications.
const (
	scannerShodan = "shodan"
	scannerFOFA   = "fofa"
)

// scannerDisplayName renders a scanner identifier the way its operators spell it.
func scannerDisplayName(scanner string) string {
	switch scanner {
	case scannerShodan:
		return "Shodan"
	case scannerFOFA:
		return "FOFA"
	default:
		return scanner
	}
}

// confSharedFaviconHash is the evidence weight of one scanner reporting a host
// that serves the same favicon as the target.
//
// One scanner's answer is review-level however many hosts come back, because a
// favicon is not an identity. Default framework icons, unmodified CMS installs,
// and stock hosting-panel logos all hash to values shared by thousands of
// unrelated hosts, and this plugin cannot tell a distinctive corporate logo from
// a WordPress default. When the icon IS distinctive the signal is strong — which
// is exactly the judgement a reviewer can make and this code cannot.
//
// Two scanners reporting the same host therefore DO clear the clean threshold
// (0.45 + 0.45), and that is a deliberate consequence of treating Shodan and
// FOFA as independent observers rather than an oversight. The alternative was to
// pick a score low enough that both scanners together stayed under
// ConfidenceHigh, but nothing below 0.325 does, and that puts a single-scanner
// match under ConfidenceLow — the noise floor, where findings are dropped
// outright. Losing every single-scanner match to protect against a generic-icon
// false positive is the worse trade: the false positive gets reviewed, the
// dropped finding is never seen again.
const confSharedFaviconHash = 0.45

// describeFaviconMatch explains one scanner's match, naming the hash so a
// reviewer can re-run the same query and judge whether the icon is distinctive.
func describeFaviconMatch(scanner, subject string, hash int32, sourceDomain string) string {
	return fmt.Sprintf("%s observed %s serving favicon hash %d, matching the favicon fetched from %q",
		scannerDisplayName(scanner), subject, hash, sourceDomain)
}

// mergeScannerFindings collapses findings by type+value, keeping ONE confidence
// entry per scanner.
//
// The two axes of repetition differ, and the old dedup-by-value collapsed both.
// Many matches from one scanner are one answer to one question: asking Shodan
// which hosts serve this icon and getting forty back is a single observation
// about a single hash, so those merge into one entry. Two scanners are
// independent crawls of the internet, so Shodan and FOFA each keep their own
// entry — and that is the corroboration the plugin exists to surface.
//
// Keeping only the first finding, as this function used to, silently discarded
// the second scanner's provenance: the merged record claimed one source when two
// had seen it.
func mergeScannerFindings(findings []plugins.Finding) []plugins.Finding {
	type key struct {
		typ   plugins.FindingType
		value string
	}

	// merged holds the finding built so far plus the scanners already folded
	// into it. The scanner list is both the dedup set and what Data reports;
	// there are only ever two, so a scan beats a second map.
	type merge struct {
		finding  plugins.Finding
		scanners []string
	}

	var order []key
	merged := make(map[key]*merge, len(findings))

	for _, f := range findings {
		k := key{f.Type, f.Value}
		scanner, _ := f.Data["scanner"].(string)

		entry, ok := merged[k]
		if !ok {
			entry = &merge{finding: f}
			merged[k] = entry
			order = append(order, k)
		} else {
			if slices.Contains(entry.scanners, scanner) {
				continue
			}
			entry.finding.Confidences = append(entry.finding.Confidences, f.Confidences...)
		}
		entry.scanners = append(entry.scanners, scanner)
	}

	result := make([]plugins.Finding, 0, len(order))
	for _, k := range order {
		entry := merged[k]
		if entry.finding.Data != nil {
			entry.finding.Data["scanners"] = strings.Join(entry.scanners, ",")
		}
		result = append(result, entry.finding)
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
