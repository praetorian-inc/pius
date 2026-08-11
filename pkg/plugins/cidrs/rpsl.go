package cidrs

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/cidr"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const confRPSLHandleInetnum = 85

// rpslConfig holds per-registry configuration for RPSL plugins.
type rpslConfig struct {
	name        string // "apnic" or "afrinic"
	description string
	cacheURL    string // cache.APNICInetURL or cache.AFRINICAllURL
	metaKey     string // "apnic_handles" or "afrinic_handles"
	registry    string // "apnic" or "afrinic"
	mode        string // plugins.ModePassive or plugins.ModeActive
}

// rpslPlugin is a Phase 2 CIDR plugin that resolves RIR org handles
// to CIDR blocks by downloading and parsing RPSL inetnum databases.
type rpslPlugin struct {
	cfg   rpslConfig
	cache *cache.Cache
}

// newRPSLPlugin creates an rpslPlugin with the given config and cache.
// If cache is nil (init failed), the plugin self-disables via Accepts().
func newRPSLPlugin(cfg rpslConfig, c *cache.Cache) *rpslPlugin {
	return &rpslPlugin{cfg: cfg, cache: c}
}

func (p *rpslPlugin) Name() string        { return p.cfg.name }
func (p *rpslPlugin) Description() string { return p.cfg.description }
func (p *rpslPlugin) Category() string    { return "cidr" }
func (p *rpslPlugin) Phase() int          { return 2 }
func (p *rpslPlugin) Mode() string        { return p.cfg.mode }

func (p *rpslPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta[p.cfg.metaKey] != "" && p.cache != nil
}

func (p *rpslPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	handles := splitHandles(input.Meta[p.cfg.metaKey])

	// Download RPSL database
	dbFile, err := p.cache.GetOrDownload(ctx, p.cfg.cacheURL)
	if err != nil {
		return nil, err
	}

	// Parse RPSL file for inetnum records matching our handles
	ranges, err := parseRPSLInetnums(dbFile, handles)
	if err != nil {
		return nil, err
	}

	// Convert IP ranges to CIDRs and create findings
	var findings []plugins.Finding
	for handle, inetnums := range ranges {
		for _, inetnum := range inetnums {
			cidrs, err := cidr.ConvertIPv4RangeToCIDR(inetnum.start, inetnum.end)
			if err != nil {
				continue
			}
			for _, c := range cidrs {
				rangeText := inetnum.start + " - " + inetnum.end
				justification := fmt.Sprintf("%s RPSL records range %q under organization handle %q", strings.ToUpper(p.Name()), rangeText, handle)
				if inetnum.netname != "" {
					justification += fmt.Sprintf(" with netname %q", inetnum.netname)
				}
				justification += fmt.Sprintf("; the range contains CIDR %q", c)
				finding := plugins.Finding{
					Type:   plugins.FindingCIDR,
					Value:  c,
					Source: p.Name(),
					Data: map[string]any{
						"handle":   handle,
						"org":      input.OrgName,
						"registry": p.cfg.registry,
						"netname":  inetnum.netname,
					},
				}
				plugins.AddConfidence(&finding, confRPSLHandleInetnum, justification)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// parseRPSLInetnums parses an RPSL database file and returns IP ranges for the given handles.
// Used by both APNIC and AFRINIC plugins.
func parseRPSLInetnums(filePath string, handles []string) (map[string][]rpslInetnum, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Normalize handles for matching
	handleSet := make(map[string]bool)
	for _, h := range handles {
		handleSet[strings.TrimSpace(strings.ToUpper(h))] = true
	}

	results := make(map[string][]rpslInetnum)
	scanner := bufio.NewScanner(f)

	var currentInetnum, currentOrg, currentNetname string
	var inetnumStart, inetnumEnd string

	for scanner.Scan() {
		line := scanner.Text()

		// RPSL records are separated by blank lines
		if strings.TrimSpace(line) == "" {
			// End of record - check if it matches our handles
			if currentOrg != "" && handleSet[strings.ToUpper(currentOrg)] && inetnumStart != "" && inetnumEnd != "" {
				results[currentOrg] = append(results[currentOrg], rpslInetnum{
					start:   inetnumStart,
					end:     inetnumEnd,
					netname: currentNetname,
				})
			}
			// Reset for next record
			currentOrg, currentNetname = "", ""
			inetnumStart, inetnumEnd = "", ""
			continue
		}

		// Parse RPSL fields
		if strings.HasPrefix(line, "inetnum:") {
			currentInetnum = strings.TrimSpace(strings.TrimPrefix(line, "inetnum:"))
			// Parse range "192.168.0.0 - 192.168.255.255"
			parts := strings.Split(currentInetnum, "-")
			if len(parts) == 2 {
				inetnumStart = strings.TrimSpace(parts[0])
				inetnumEnd = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "org:") {
			currentOrg = strings.TrimSpace(strings.TrimPrefix(line, "org:"))
		} else if strings.HasPrefix(line, "netname:") {
			currentNetname = strings.TrimSpace(strings.TrimPrefix(line, "netname:"))
		}
	}

	return results, scanner.Err()
}

// rpslInetnum represents an IP address range from an RPSL inetnum record.
type rpslInetnum struct {
	start   string
	end     string
	netname string
}
