package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("shodan", func() plugins.Plugin {
		return &ShodanPlugin{client: client.New()}
	})
}

// ShodanPlugin queries Shodan's pre-indexed internet scan data to discover
// hosts, IPs, and services associated with a target organization.
type ShodanPlugin struct {
	client  *client.Client
	baseURL string // override for testing
	apiKey  string // set by NewShodanPlugin; falls back to SHODAN_API_KEY when empty
}

// NewShodanPlugin builds the plugin around a caller-supplied client and API key,
// so embedders can route its egress through their own transport and resolve the
// key from their own secret store instead of the environment.
func NewShodanPlugin(c *client.Client, apiKey string) *ShodanPlugin {
	return &ShodanPlugin{client: c, apiKey: apiKey}
}

// key prefers an injected key so embedders never depend on process environment.
func (p *ShodanPlugin) key() string {
	if p.apiKey != "" {
		return p.apiKey
	}
	return os.Getenv("SHODAN_API_KEY")
}

func (p *ShodanPlugin) Name() string { return "shodan" }
func (p *ShodanPlugin) Description() string {
	return "Shodan: discovers hosts and services from pre-indexed internet scan data (requires SHODAN_API_KEY)"
}
func (p *ShodanPlugin) Category() string { return "cidr" }
func (p *ShodanPlugin) Phase() int       { return 0 }
func (p *ShodanPlugin) Mode() string     { return plugins.ModePassive }

func (p *ShodanPlugin) shodanBase() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return "https://api.shodan.io"
}

// Accepts if SHODAN_API_KEY is set and we have something to search
func (p *ShodanPlugin) Accepts(input plugins.Input) bool {
	if p.key() == "" {
		return false
	}
	return input.OrgName != "" || input.Domain != "" || input.ASN != "" || input.CIDR != ""
}

func (p *ShodanPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	apiKey := p.key()
	if apiKey == "" {
		return nil, nil
	}

	// Build individual queries for each filter
	queries := p.buildQueries(input)
	if len(queries) == 0 {
		return nil, nil
	}

	// Run separate queries and keep each match attached to the query that
	// returned it (Shodan uses AND for combined filters, so they run separately).
	//
	// Merging the matches first would be irreversible: "this IP is in the
	// netblock you gave me" and "this IP belongs to a company whose name
	// resembles yours" are worlds apart as ownership evidence, and once the
	// results are in one flat slice there is no way to tell which is which.
	var observations []shodanObservation
	for _, query := range queries {
		results, err := p.search(ctx, apiKey, query.query)
		if err != nil {
			continue // Graceful degradation on API errors
		}
		for _, match := range results.Matches {
			observations = append(observations, shodanObservation{query: query, match: match})
		}
	}

	return p.processResults(observations, input), nil
}

// shodanQueryKind classifies a Shodan search by what it actually asserts about
// the results, which is what its evidence is worth.
type shodanQueryKind string

const (
	// shodanQueryCIDR constrains results to a netblock the caller supplied.
	shodanQueryCIDR shodanQueryKind = "cidr"

	// shodanQueryASN constrains results to an ASN the caller supplied.
	shodanQueryASN shodanQueryKind = "asn"

	// shodanQueryHostname constrains results to hosts serving a known domain.
	shodanQueryHostname shodanQueryKind = "hostname"

	// shodanQueryOrg matches Shodan's own org field against a company name.
	shodanQueryOrg shodanQueryKind = "org"
)

// Evidence weights per query kind. They are ordered by how much of the answer
// the caller already supplied.
//
// A net: query returns what is inside a range the caller asserted is theirs, so
// the only doubt left is whether the range is still theirs. An asn: query is
// nearly as direct, one step removed through BGP. A hostname: query finds hosts
// serving a known domain — good, but shared hosting and CDN edges serve names
// for parties unrelated to each other. An org: query is the weak one: Shodan's
// org field is derived from WHOIS/registration strings, so it matches on a
// company name that hundreds of unrelated entities can share a prefix with, and
// it is exactly the kind of guess that must not read as clean on its own.
const (
	confShodanCIDRQuery     = 0.85
	confShodanASNQuery      = 0.80
	confShodanHostnameQuery = 0.65
	confShodanOrgQuery      = 0.50
)

// score returns the evidence weight of a match returned by this query kind.
func (k shodanQueryKind) score() float64 {
	switch k {
	case shodanQueryCIDR:
		return confShodanCIDRQuery
	case shodanQueryASN:
		return confShodanASNQuery
	case shodanQueryHostname:
		return confShodanHostnameQuery
	default:
		return confShodanOrgQuery
	}
}

// describe renders the query the way a reviewer would re-run it.
func (k shodanQueryKind) describe(value string) string {
	switch k {
	case shodanQueryCIDR:
		return fmt.Sprintf("within the queried network %q", value)
	case shodanQueryASN:
		return fmt.Sprintf("for ASN query %q", value)
	case shodanQueryHostname:
		return fmt.Sprintf("for hostname query %q", value)
	default:
		return fmt.Sprintf("for organization query %q", value)
	}
}

// shodanQuery is one search: its kind, the value it constrains on, and the
// Shodan query string sent to the API.
type shodanQuery struct {
	kind  shodanQueryKind
	value string
	query string
}

// shodanObservation is one match kept together with the query that returned it.
type shodanObservation struct {
	query shodanQuery
	match ShodanMatch
}

// buildQueries constructs individual Shodan search queries from input
// Each filter is run as a separate query since Shodan uses AND for combined filters
func (p *ShodanPlugin) buildQueries(input plugins.Input) []shodanQuery {
	var queries []shodanQuery

	// Org name query for broadest results
	if input.OrgName != "" {
		queries = append(queries, shodanQuery{
			kind:  shodanQueryOrg,
			value: input.OrgName,
			query: fmt.Sprintf("org:\"%s\"", input.OrgName),
		})
	}

	// ASN query
	if input.ASN != "" {
		asn := input.ASN
		if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
			asn = "AS" + asn
		}
		queries = append(queries, shodanQuery{
			kind:  shodanQueryASN,
			value: asn,
			query: fmt.Sprintf("asn:%s", asn),
		})
	}

	// CIDR/net query for IP range
	if input.CIDR != "" {
		queries = append(queries, shodanQuery{
			kind:  shodanQueryCIDR,
			value: input.CIDR,
			query: fmt.Sprintf("net:%s", input.CIDR),
		})
	}

	// Hostname query for domain
	if input.Domain != "" {
		queries = append(queries, shodanQuery{
			kind:  shodanQueryHostname,
			value: input.Domain,
			query: fmt.Sprintf("hostname:%s", input.Domain),
		})
	}

	return queries
}

// search performs the Shodan API search
func (p *ShodanPlugin) search(ctx context.Context, apiKey, query string) (*ShodanSearchResponse, error) {
	searchURL := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s",
		p.shodanBase(), apiKey, url.QueryEscape(query))

	body, err := p.client.Get(ctx, searchURL)
	if err != nil {
		return nil, err
	}

	var resp ShodanSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// shodanAggregate accumulates every query that returned one value.
type shodanAggregate struct {
	finding plugins.Finding

	// queries records the distinct queries that returned this value, in the
	// order they were run. Two hosts in one org query both serving the same
	// hostname is one query's answer twice, not two signals. buildQueries emits
	// at most one query per kind, so the kind alone identifies the query.
	queries []shodanQuery
}

// observe records that query returned this value, and builds the evidence entry
// the first time each distinct query does.
func (a *shodanAggregate) observe(query shodanQuery, justification string) {
	if slices.ContainsFunc(a.queries, func(seen shodanQuery) bool { return seen.kind == query.kind }) {
		return
	}
	a.queries = append(a.queries, query)

	plugins.AddConfidence(&a.finding, query.kind.score(), justification)
}

// processResults converts Shodan observations to findings, aggregating by value
// so that each distinct query contributes one evidence entry.
//
// Two queries returning the same host are independent: the netblock query and
// the org-name query reach it by unrelated routes, so they add. Fifty hosts
// returned by one org query that all serve the same hostname are not — that is
// one answer to one question, and observe() collapses them.
func (p *ShodanPlugin) processResults(observations []shodanObservation, input plugins.Input) []plugins.Finding {
	var order []string
	aggregates := make(map[string]*shodanAggregate)

	aggregate := func(key string, build func() plugins.Finding) *shodanAggregate {
		existing, ok := aggregates[key]
		if !ok {
			existing = &shodanAggregate{finding: build()}
			aggregates[key] = existing
			order = append(order, key)
		}
		return existing
	}

	for _, observation := range observations {
		match := observation.match

		// Emit IP as CIDR /32
		if match.IPStr != "" {
			key := "cidr\x00" + match.IPStr
			entry := aggregate(key, func() plugins.Finding {
				return plugins.Finding{
					Type:   plugins.FindingCIDR,
					Value:  match.IPStr + "/32",
					Source: p.Name(),
					Data: map[string]any{
						"org":   input.OrgName,
						"port":  match.Port,
						"asn":   match.ASN,
						"isp":   match.ISP,
						"os":    match.OS,
						"cloud": match.Cloud,
					},
				}
			})
			entry.observe(observation.query, fmt.Sprintf("Shodan returned IP %s %s",
				match.IPStr, observation.query.kind.describe(observation.query.value)))
		}

		// Emit hostnames as domains
		for _, hostname := range match.Hostnames {
			hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
			if hostname == "" {
				continue
			}

			key := "domain\x00" + hostname
			entry := aggregate(key, func() plugins.Finding {
				return plugins.Finding{
					Type:   plugins.FindingDomain,
					Value:  hostname,
					Source: p.Name(),
					Data: map[string]any{
						"org":    input.OrgName,
						"ip":     match.IPStr,
						"port":   match.Port,
						"source": "shodan_hostname",
					},
				}
			})
			// The hostname is one step further out than the IP: Shodan saw the
			// host answer to this name. The query that found the host is still
			// what makes the name attributable, so it carries the same weight
			// and the justification names both halves.
			entry.observe(observation.query, fmt.Sprintf("Shodan associated hostname %q with IP %s, returned %s",
				hostname, match.IPStr, observation.query.kind.describe(observation.query.value)))
		}
	}

	// Left nil when nothing was observed: "no results" is the plugin having
	// nothing to contribute, which the runner distinguishes from an empty batch.
	var findings []plugins.Finding
	for _, key := range order {
		entry := aggregates[key]
		entry.finding.Data["query_kinds"] = joinQueryKinds(entry.queries)
		findings = append(findings, entry.finding)
	}
	return findings
}

// joinQueryKinds lists the query kinds that returned a value, for Data.
func joinQueryKinds(queries []shodanQuery) string {
	kinds := make([]string, 0, len(queries))
	for _, q := range queries {
		kinds = append(kinds, string(q.kind))
	}
	return strings.Join(kinds, ",")
}

// ShodanSearchResponse represents the Shodan search API response
type ShodanSearchResponse struct {
	Matches []ShodanMatch `json:"matches"`
	Total   int           `json:"total"`
}

// ShodanMatch represents a single result from Shodan search
type ShodanMatch struct {
	IPStr     string   `json:"ip_str"`
	Port      int      `json:"port"`
	Hostnames []string `json:"hostnames"`
	ASN       string   `json:"asn"`
	ISP       string   `json:"isp"`
	OS        string   `json:"os"`
	Cloud     *struct {
		Provider string `json:"provider"`
		Region   string `json:"region"`
	} `json:"cloud,omitempty"`
}
