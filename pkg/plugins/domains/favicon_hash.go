package domains

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/twmb/murmur3"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const confFaviconScannerObservation = 0.50

type faviconFindingKey struct {
	findingType plugins.FindingType
	value       string
}

type faviconFindingMap map[faviconFindingKey]plugins.Finding

type faviconObservation struct {
	scanner      string
	findingType  plugins.FindingType
	value        string
	associatedIP string
}

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

	// Step 3: Query Shodan and FOFA sequentially, aggregating their evidence.
	findings := make(faviconFindingMap)

	if err := p.queryShodan(ctx, hash, input, findings); err != nil {
		slog.Warn("favicon-hash: Shodan query failed", "error", err)
	}

	if os.Getenv("FOFA_API_KEY") != "" {
		if err := p.queryFOFA(ctx, hash, input, findings); err != nil {
			slog.Warn("favicon-hash: FOFA query failed", "error", err)
		}
	}

	return sortedFaviconFindings(findings), nil
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
func (p *FaviconHashPlugin) queryShodan(
	ctx context.Context,
	hash int32,
	input plugins.Input,
	findings faviconFindingMap,
) error {
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
		return fmt.Errorf("shodan request: %w", err)
	}

	return parseShodanResponse(body, hash, input, findings)
}

// shodanResponse mirrors the subset of the Shodan /shodan/host/search response we use.
type shodanResponse struct {
	Matches []shodanMatch `json:"matches"`
}

type shodanMatch struct {
	IPStr     string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
}

func parseShodanResponse(body []byte, hash int32, input plugins.Input, findings faviconFindingMap) error {
	var resp shodanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parse shodan response: %w", err)
	}

	observations := make([]faviconObservation, 0)
	seen := make(map[faviconObservation]bool)
	for _, match := range resp.Matches {
		ip := strings.TrimSpace(match.IPStr)
		if ip != "" {
			observations = appendUniqueFaviconObservation(observations, seen, faviconObservation{
				scanner:      "shodan",
				findingType:  plugins.FindingCIDR,
				value:        faviconHostCIDR(ip),
				associatedIP: ip,
			})
		}
		for _, hostname := range match.Hostnames {
			observations = appendUniqueFaviconObservation(observations, seen, faviconObservation{
				scanner:      "shodan",
				findingType:  plugins.FindingDomain,
				value:        hostname,
				associatedIP: ip,
			})
		}
	}

	addFaviconObservations(findings, observations, hash, input)
	return nil
}

// queryFOFA queries FOFA for hosts matching the favicon hash.
func (p *FaviconHashPlugin) queryFOFA(
	ctx context.Context,
	hash int32,
	input plugins.Input,
	findings faviconFindingMap,
) error {
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
		return fmt.Errorf("fofa request: %w", err)
	}

	return parseFOFAResponse(body, hash, input, findings)
}

// fofaResponse mirrors the subset of the FOFA /api/v1/search/all response we use.
type fofaResponse struct {
	Results [][]string `json:"results"` // each entry is [host, ip]
}

func parseFOFAResponse(body []byte, hash int32, input plugins.Input, findings faviconFindingMap) error {
	var resp fofaResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parse fofa response: %w", err)
	}

	observations := make([]faviconObservation, 0)
	seen := make(map[faviconObservation]bool)
	for _, result := range resp.Results {
		if len(result) < 2 {
			continue
		}
		host, ip := result[0], strings.TrimSpace(result[1])
		if ip != "" {
			observations = appendUniqueFaviconObservation(observations, seen, faviconObservation{
				scanner:      "fofa",
				findingType:  plugins.FindingCIDR,
				value:        faviconHostCIDR(ip),
				associatedIP: ip,
			})
		}
		observations = appendUniqueFaviconObservation(observations, seen, faviconObservation{
			scanner:      "fofa",
			findingType:  plugins.FindingDomain,
			value:        host,
			associatedIP: ip,
		})
	}

	addFaviconObservations(findings, observations, hash, input)
	return nil
}

// normalizeFaviconHost normalizes a hostname from scanner results:
// strips scheme/path (FOFA hosts may include them), lowercases, removes trailing dots.
func normalizeFaviconHost(d string) string {
	d = strings.TrimSpace(d)
	// Strip scheme if present (FOFA hosts may include it)
	d = stripScheme(d)
	return normalizeDomain(d)
}

func appendUniqueFaviconObservation(
	observations []faviconObservation,
	seen map[faviconObservation]bool,
	observation faviconObservation,
) []faviconObservation {
	observation.value = normalizeFaviconFindingValue(observation.findingType, observation.value)
	observation.associatedIP = strings.TrimSpace(observation.associatedIP)
	if observation.value == "" || seen[observation] {
		return observations
	}
	seen[observation] = true
	return append(observations, observation)
}

func addFaviconObservations(
	findings faviconFindingMap,
	observations []faviconObservation,
	hash int32,
	input plugins.Input,
) {
	for _, observation := range observations {
		addFaviconEvidence(findings, observation, hash, input)
	}
}

func addFaviconEvidence(
	findings faviconFindingMap,
	observation faviconObservation,
	hash int32,
	input plugins.Input,
) {
	value := normalizeFaviconFindingValue(observation.findingType, observation.value)
	if value == "" {
		return
	}

	key := faviconFindingKey{findingType: observation.findingType, value: value}
	finding, exists := findings[key]
	if !exists {
		finding = plugins.Finding{
			Type:   observation.findingType,
			Value:  value,
			Source: "favicon-hash",
			Data: map[string]any{
				"org":           input.OrgName,
				"source_domain": input.Domain,
				"favicon_hash":  hash,
				"scanners":      []string{},
			},
		}
	}

	finding.Data["scanners"] = appendFaviconScanner(finding.Data["scanners"], observation.scanner)
	plugins.AddConfidence(&finding, confFaviconScannerObservation,
		faviconJustification(observation, value, hash, input.Domain))
	findings[key] = finding
}

func appendFaviconScanner(value any, scanner string) []string {
	scanners, _ := value.([]string)
	for _, existing := range scanners {
		if existing == scanner {
			return scanners
		}
	}
	scanners = append(scanners, scanner)
	sort.Strings(scanners)
	return scanners
}

func faviconJustification(observation faviconObservation, value string, hash int32, sourceDomain string) string {
	scanner := faviconScannerDisplayName(observation.scanner)
	if observation.findingType == plugins.FindingCIDR {
		return fmt.Sprintf(`%s observed favicon hash %d on IP %q, matching the favicon fetched from domain %q`,
			scanner, hash, observation.associatedIP, sourceDomain)
	}
	if observation.associatedIP != "" {
		return fmt.Sprintf(`%s associated hostname %q with IP %q, where it observed favicon hash %d matching the favicon fetched from domain %q`,
			scanner, value, observation.associatedIP, hash, sourceDomain)
	}
	return fmt.Sprintf(`%s observed hostname %q with favicon hash %d matching the favicon fetched from domain %q`,
		scanner, value, hash, sourceDomain)
}

func faviconScannerDisplayName(scanner string) string {
	if scanner == "fofa" {
		return "FOFA"
	}
	if scanner == "" {
		return "Scanner"
	}
	return strings.ToUpper(scanner[:1]) + scanner[1:]
}

func faviconHostCIDR(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return ip + "/32"
	}
	return netip.PrefixFrom(address, address.BitLen()).String()
}

func normalizeFaviconFindingValue(findingType plugins.FindingType, value string) string {
	if findingType == plugins.FindingDomain {
		return normalizeFaviconHost(value)
	}
	value = strings.TrimSpace(value)
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return value
	}
	return prefix.Masked().String()
}

func sortedFaviconFindings(findings faviconFindingMap) []plugins.Finding {
	result := make([]plugins.Finding, 0, len(findings))
	for _, finding := range findings {
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		return result[i].Value < result[j].Value
	})
	return result
}
