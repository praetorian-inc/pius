package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

// httpDoer abstracts HTTP GET operations for testability.
type httpDoer interface {
	Get(ctx context.Context, url string) ([]byte, error)
	GetWithHeaders(ctx context.Context, url string, headers map[string]string) ([]byte, error)
}

const confRDAPHandleNetwork = 85

type rdapCIDR struct {
	value       string
	confidences []plugins.Confidence
}

// rdapConfig holds per-registry configuration for RDAP plugins.
type rdapConfig struct {
	name        string // "arin" or "ripe"
	description string
	baseURL     string // e.g. "https://rdap.arin.net/registry/entity" (no trailing slash)
	metaKey     string // "arin_handles" or "ripe_handles"
	registry    string // "arin" or "ripe" (for Finding.Data)
	mode        string // plugins.ModePassive or plugins.ModeActive
}

// rdapPlugin is a Phase 2 CIDR plugin that resolves RIR org handles
// to CIDR blocks via RDAP entity lookup.
type rdapPlugin struct {
	cfg  rdapConfig
	doer httpDoer
}

// newRDAPPlugin creates an rdapPlugin with the given config and a default HTTP client.
func newRDAPPlugin(cfg rdapConfig) *rdapPlugin {
	return &rdapPlugin{cfg: cfg, doer: client.New()}
}

// rdapConfigs is the per-registry configuration behind both the self-registering
// plugins and NewRDAPPlugin, so an embedder's plugin is the same plugin
// standalone pius runs — only the HTTP client differs.
var rdapConfigs = map[string]rdapConfig{
	"arin": {
		name:        "arin",
		description: "ARIN RDAP: resolves org handles to CIDR blocks",
		baseURL:     "https://rdap.arin.net/registry/entity",
		metaKey:     "arin_handles",
		registry:    "arin",
		mode:        plugins.ModePassive,
	},
	"ripe": {
		name:        "ripe",
		description: "RIPE RDAP: resolves org handles to CIDR blocks",
		baseURL:     "https://rdap.db.ripe.net/entity",
		metaKey:     "ripe_handles",
		registry:    "ripe",
		mode:        plugins.ModePassive,
	},
	"lacnic": {
		name:        "lacnic",
		description: "LACNIC RDAP: resolves org handles to CIDR blocks (Latin America & Caribbean)",
		baseURL:     "https://rdap.lacnic.net/rdap/entity",
		metaKey:     "lacnic_handles",
		registry:    "lacnic",
		mode:        plugins.ModePassive,
	},
}

// NewRDAPPlugin builds the RDAP plugin for one registry around a caller-supplied
// client. It exists for embedders that must route pius egress through their own
// transport — Guard runs every plugin through its HTTP collector so the traffic
// is observable and mockable — rather than the package default. A nil client
// takes the package default, matching the self-registering plugins.
func NewRDAPPlugin(registry string, c *client.Client) (plugins.Plugin, error) {
	cfg, ok := rdapConfigs[registry]
	if !ok {
		return nil, fmt.Errorf("no RDAP registry %q (have %s)", registry,
			strings.Join(slices.Sorted(maps.Keys(rdapConfigs)), ", "))
	}
	if c == nil {
		return newRDAPPlugin(cfg), nil
	}
	return &rdapPlugin{cfg: cfg, doer: c}, nil
}

func (p *rdapPlugin) Name() string        { return p.cfg.name }
func (p *rdapPlugin) Description() string { return p.cfg.description }
func (p *rdapPlugin) Category() string    { return "cidr" }
func (p *rdapPlugin) Phase() int          { return 2 }
func (p *rdapPlugin) Mode() string        { return p.cfg.mode }

func (p *rdapPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta[p.cfg.metaKey] != ""
}

func (p *rdapPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	handles := splitHandles(input.Meta[p.cfg.metaKey])
	var findings []plugins.Finding
	for _, handle := range handles {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		results, err := p.fetchCIDRs(ctx, handle)
		if err != nil {
			// Log but don't fail all handles
			continue
		}
		for _, result := range results {
			finding := plugins.Finding{
				Type:   plugins.FindingCIDR,
				Value:  result.value,
				Source: p.Name(),
				Data: map[string]any{
					"handle":   handle,
					"org":      input.OrgName,
					"registry": p.cfg.registry,
				},
			}
			for _, confidence := range result.confidences {
				plugins.AddConfidence(&finding, confidence.Score, confidence.Justification)
			}
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (p *rdapPlugin) fetchCIDRs(ctx context.Context, handle string) ([]rdapCIDR, error) {
	reqURL := fmt.Sprintf("%s/%s", p.cfg.baseURL, url.PathEscape(handle))
	body, err := p.doer.GetWithHeaders(ctx, reqURL, map[string]string{
		"Accept": "application/rdap+json",
	})
	if err != nil {
		return nil, err
	}

	var resp rdapEntityResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("%s: parse response: %w", p.cfg.name, err)
	}

	var cidrs []rdapCIDR
	for _, network := range resp.Networks {
		for _, cidr0 := range network.Cidr0Cidrs {
			if cidr0.V4Prefix != "" && cidr0.Length > 0 {
				cidrs = append(cidrs, p.newRDAPCIDR(handle, fmt.Sprintf("%s/%d", cidr0.V4Prefix, cidr0.Length)))
			}
			if cidr0.V6Prefix != "" && cidr0.Length > 0 {
				cidrs = append(cidrs, p.newRDAPCIDR(handle, fmt.Sprintf("%s/%d", cidr0.V6Prefix, cidr0.Length)))
			}
		}
	}
	return cidrs, nil
}

func (p *rdapPlugin) newRDAPCIDR(handle, value string) rdapCIDR {
	return rdapCIDR{
		value: value,
		confidences: []plugins.Confidence{{
			Score: confRDAPHandleNetwork,
			Justification: fmt.Sprintf("%s RDAP records CIDR %q under organization handle %q",
				strings.ToUpper(p.Name()), value, handle),
		}},
	}
}

// splitHandles splits a comma-separated handle string, trims whitespace,
// and returns only non-empty handles. Used by both RDAP and RPSL plugins.
func splitHandles(csv string) []string {
	parts := strings.Split(csv, ",")
	var result []string
	for _, h := range parts {
		h = strings.TrimSpace(h)
		if h != "" {
			result = append(result, h)
		}
	}
	return result
}

// rdapEntityResponse represents RDAP entity response structure.
type rdapEntityResponse struct {
	Handle   string        `json:"handle"`
	Networks []rdapNetwork `json:"networks"`
}

type rdapNetwork struct {
	Handle     string     `json:"handle"`
	Cidr0Cidrs []rdapCidr `json:"cidr0_cidrs"`
}

type rdapCidr struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}
