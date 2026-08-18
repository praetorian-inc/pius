package cidrs

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/cidr"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const confRPSLHandleInetnum = 85

// rpslConfig holds per-registry configuration for RPSL plugins.
type rpslConfig struct {
	name                    string // "apnic" or "afrinic"
	description             string
	cacheURL                string // cache.APNICInetURL or cache.AFRINICAllURL
	metaKey                 string // "apnic_handles" or "afrinic_handles"
	registry                string // "apnic" or "afrinic"
	networkReferenceBaseURL string
	mode                    string // plugins.ModePassive or plugins.ModeActive
}

// rpslPlugin is a Phase 2 CIDR plugin that resolves RIR org handles to CIDR
// blocks by parsing RPSL inetnum/inet6num databases.
//
// The database comes from one of two places. cache downloads and refreshes the
// registry's published dump; dbPaths are files the caller already has on disk.
// When paths are supplied they take precedence over the cache, because an
// embedder that supplies paths is telling us not to reach the network. A missing
// supplied file therefore returns an error instead of falling back to a
// several-hundred-megabyte download.
type rpslPlugin struct {
	cfg     rpslConfig
	cache   *cache.Cache
	dbPaths []string
}

// newRPSLPlugin creates a plugin backed by either local database paths or a
// download cache. Local paths take precedence when both are provided. With
// neither source configured, the plugin self-disables via Accepts(), while a
// direct Run reports the missing database source.
func newRPSLPlugin(cfg rpslConfig, c *cache.Cache, databasePaths ...string) *rpslPlugin {
	paths := make([]string, 0, len(databasePaths))
	for _, path := range databasePaths {
		if strings.TrimSpace(path) != "" {
			paths = append(paths, path)
		}
	}

	return &rpslPlugin{cfg: cfg, cache: c, dbPaths: paths}
}

func (p *rpslPlugin) Name() string        { return p.cfg.name }
func (p *rpslPlugin) Description() string { return p.cfg.description }
func (p *rpslPlugin) Category() string    { return "cidr" }
func (p *rpslPlugin) Phase() int          { return 2 }
func (p *rpslPlugin) Mode() string        { return p.cfg.mode }

func (p *rpslPlugin) Accepts(input plugins.Input) bool {
	if input.Meta == nil || input.Meta[p.cfg.metaKey] == "" {
		return false
	}
	// Cache init failing is how the standalone plugin self-disables; a plugin
	// built over local paths has no cache and is unaffected.
	return p.cache != nil || len(p.dbPaths) > 0
}

func (p *rpslPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	handles := splitHandles(input.Meta[p.cfg.metaKey])

	dbFiles, err := p.databases(ctx)
	if err != nil {
		return nil, err
	}

	var findings []plugins.Finding
	for _, dbFile := range dbFiles {
		netblocks, err := parseRPSLNetblocks(dbFile, handles, input.OrgName)
		if err != nil {
			return nil, fmt.Errorf("%s: read RPSL database: %w", p.cfg.name, err)
		}
		findings = append(findings, p.findings(input, netblocks)...)
	}
	return findings, nil
}

// databases resolves where this run reads its RPSL records from. Injected paths
// win outright and never fall back to the cache: the caller supplied them
// precisely so that no run downloads a dump, so a missing file must surface as
// an error rather than quietly become a several-hundred-megabyte fetch.
func (p *rpslPlugin) databases(ctx context.Context) ([]string, error) {
	if len(p.dbPaths) > 0 {
		return p.dbPaths, nil
	}
	if p.cache == nil {
		return nil, fmt.Errorf("%s: no database paths and no download cache", p.cfg.name)
	}
	dbFile, err := p.cache.GetOrDownload(ctx, p.cfg.cacheURL)
	if err != nil {
		return nil, err
	}
	return []string{dbFile}, nil
}

func (p *rpslPlugin) findings(input plugins.Input, netblocks []rpslNetblock) []plugins.Finding {
	var findings []plugins.Finding
	for _, netblock := range netblocks {
		cidrs, err := netblock.cidrs()
		if err != nil {
			continue
		}
		for _, c := range cidrs {
			justification := fmt.Sprintf("%s RPSL records %s %q",
				strings.ToUpper(p.Name()), netblock.kind(), netblock.source())
			if netblock.handle != "" {
				justification += fmt.Sprintf(" under organization handle %q", netblock.handle)
			} else {
				justification += fmt.Sprintf(" with descr %q matching organization name %q",
					netblock.description, input.OrgName)
			}
			if netblock.netname != "" {
				justification += fmt.Sprintf(" with netname %q", netblock.netname)
			}
			justification += fmt.Sprintf("; the %s contains CIDR %q", netblock.kind(), c)

			finding := plugins.Finding{
				Type:   plugins.FindingCIDR,
				Value:  c,
				Source: p.Name(),
				Data: map[string]any{
					"handle":      netblock.handle,
					"org":         input.OrgName,
					"registry":    p.cfg.registry,
					"netname":     netblock.netname,
					"description": netblock.description,
				},
			}
			plugins.AddConfidenceWithReference(&finding, confRPSLHandleInetnum, justification, plugins.Reference{
				Label: strings.ToUpper(p.Name()) + " RPSL netblock",
				Type:  plugins.ReferenceTypeRPSL,
				Data: plugins.RPSLReferenceData{
					Record:     strings.TrimSpace(netblock.record),
					NetworkURL: p.networkReferenceURL(c),
				},
			})
			findings = append(findings, finding)
		}
	}
	return findings
}

func (p *rpslPlugin) networkReferenceURL(cidr string) string {
	if p.cfg.networkReferenceBaseURL == "" {
		return ""
	}
	return p.cfg.networkReferenceBaseURL + cidr
}

// rpslNetblock is one matched inetnum or inet6num record. A match carries either
// its org handle or the descr line that matched the requested organization name.
// inetnum states an inclusive IPv4 range; inet6num states an IPv6 prefix. Which
// form the record uses decides how it converts to CIDRs.
type rpslNetblock struct {
	handle string

	// start and end are set for an inetnum record.
	start string
	end   string

	// prefix is set for an inet6num record.
	prefix string

	netname      string
	description  string
	descriptions []string
	record       string
}

func (n rpslNetblock) isPrefix() bool { return n.prefix != "" }

// kind names the record type for a human-readable justification.
func (n rpslNetblock) kind() string {
	if n.isPrefix() {
		return "prefix"
	}
	return "range"
}

// source is the record as the database wrote it, so a justification cites what a
// reviewer would find by grepping the dump.
func (n rpslNetblock) source() string {
	if n.isPrefix() {
		return n.prefix
	}
	return n.start + " - " + n.end
}

// cidrs converts the record to CIDR notation. An inet6num prefix is already a
// CIDR, so it is only validated and canonicalized — a record written with host
// bits set would otherwise reach Guard as an asset key no other source produces.
func (n rpslNetblock) cidrs() ([]string, error) {
	if n.isPrefix() {
		_, network, err := net.ParseCIDR(n.prefix)
		if err != nil {
			return nil, err
		}
		return []string{network.String()}, nil
	}
	return cidr.ConvertIPv4RangeToCIDR(n.start, n.end)
}

// parseRPSLNetblocks scans an RPSL database and returns inetnum and inet6num
// records linked either to a requested handle through org or to the organization
// name through descr, in file order.
func parseRPSLNetblocks(filePath string, handles []string, organizationName string) ([]rpslNetblock, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Handles are matched case-insensitively: registries are inconsistent about
	// the case they publish an org handle in versus the case it is referenced in.
	handleSet := make(map[string]bool, len(handles))
	for _, h := range handles {
		handleSet[strings.TrimSpace(strings.ToUpper(h))] = true
	}

	var results []rpslNetblock
	var current rpslNetblock

	keep := func() {
		hasNetblock := current.prefix != "" || (current.start != "" && current.end != "")
		hasMatchingHandle := current.handle != "" && handleSet[strings.ToUpper(current.handle)]
		matchingDescription := findMatchingDescription(current.descriptions, organizationName)
		if hasNetblock && (hasMatchingHandle || matchingDescription != "") {
			if !hasMatchingHandle {
				current.handle = ""
				current.description = matchingDescription
			}
			results = append(results, current)
		}
		current = rpslNetblock{}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// RPSL records are separated by blank lines.
		if strings.TrimSpace(line) == "" {
			keep()
			continue
		}
		current.record += line + "\n"

		switch {
		case strings.HasPrefix(line, "inetnum:"):
			// "192.168.0.0 - 192.168.255.255"
			value := strings.TrimSpace(strings.TrimPrefix(line, "inetnum:"))
			if start, end, ok := strings.Cut(value, "-"); ok {
				current.start = strings.TrimSpace(start)
				current.end = strings.TrimSpace(end)
			}
		case strings.HasPrefix(line, "inet6num:"):
			// "2001:db8::/32"
			current.prefix = strings.TrimSpace(strings.TrimPrefix(line, "inet6num:"))
		case strings.HasPrefix(line, "org:"):
			current.handle = strings.TrimSpace(strings.TrimPrefix(line, "org:"))
		case strings.HasPrefix(line, "descr:"):
			current.descriptions = append(current.descriptions,
				strings.TrimSpace(strings.TrimPrefix(line, "descr:")))
		case strings.HasPrefix(line, "netname:"):
			current.netname = strings.TrimSpace(strings.TrimPrefix(line, "netname:"))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// A dump whose last record is not followed by a blank line still ends a
	// record at EOF; without this the final netblock in the file is dropped.
	keep()
	return results, nil
}

func findMatchingDescription(descriptions []string, organizationName string) string {
	organizationName = strings.ToLower(strings.TrimSpace(organizationName))
	if organizationName == "" {
		return ""
	}
	for _, description := range descriptions {
		if strings.HasPrefix(strings.ToLower(description), organizationName) {
			return description
		}
	}
	return ""
}
