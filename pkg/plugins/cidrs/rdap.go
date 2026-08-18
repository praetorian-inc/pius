package cidrs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

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
	cfg rdapConfig
	c   *client.Client
}

// newRDAPPlugin creates an rdapPlugin with the given config and a default HTTP client.
func newRDAPPlugin(cfg rdapConfig, c *client.Client) *rdapPlugin {
	if c == nil {
		c = client.New()
	}
	return &rdapPlugin{cfg: cfg, c: c}
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
				if confidence.Reference == nil {
					plugins.AddConfidence(&finding, confidence.Score, confidence.Justification, nil)
					continue
				}
				plugins.AddConfidence(&finding, confidence.Score,
					confidence.Justification, confidence.Reference)
			}
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (p *rdapPlugin) fetchCIDRs(ctx context.Context, handle string) ([]rdapCIDR, error) {
	reqURL := fmt.Sprintf("%s/%s", p.cfg.baseURL, url.PathEscape(handle))
	body, err := p.c.GetWithHeaders(ctx, reqURL, map[string]string{
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
				cidrs = append(cidrs, p.newRDAPCIDR(handle,
					fmt.Sprintf("%s/%d", cidr0.V4Prefix, cidr0.Length), reqURL, body))
			}
			if cidr0.V6Prefix != "" && cidr0.Length > 0 {
				cidrs = append(cidrs, p.newRDAPCIDR(handle,
					fmt.Sprintf("%s/%d", cidr0.V6Prefix, cidr0.Length), reqURL, body))
			}
		}
	}
	return cidrs, nil
}

func (p *rdapPlugin) newRDAPCIDR(handle, value, reqURL string, response json.RawMessage) rdapCIDR {
	return rdapCIDR{
		value: value,
		confidences: []plugins.Confidence{{
			Score: confRDAPHandleNetwork,
			Justification: fmt.Sprintf("%s RDAP records CIDR %q under organization handle %q",
				strings.ToUpper(p.Name()), value, handle),
			Reference: &plugins.Reference{
				Label: "RDAP entity response",
				Type:  plugins.ReferenceTypeRDAP,
				Data: plugins.HTTPExchangeReference{
					Request:  plugins.HTTPRequestReference{Method: "GET", URL: reqURL},
					Response: response,
				},
			},
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
