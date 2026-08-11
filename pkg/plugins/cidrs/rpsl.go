package cidrs

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
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
	// cacheURL6 names a second RPSL file carrying the registry's inet6num
	// records. It is "" for a registry that ships one combined dump already
	// containing them (AFRINIC), and non-empty for one that splits them into
	// their own download (APNIC).
	cacheURL6 string
	metaKey   string // "apnic_handles" or "afrinic_handles"
	registry  string // "apnic" or "afrinic"
	mode      string // plugins.ModePassive or plugins.ModeActive
}

// RPSLPlugin is a Phase 2 CIDR plugin that resolves RIR org handles
// to CIDR blocks by downloading and parsing RPSL inetnum databases.
type RPSLPlugin struct {
	cfg   rpslConfig
	cache *cache.Cache
}

// newRPSLPlugin creates an RPSLPlugin with the given config and cache.
// If cache is nil (init failed), the plugin self-disables via Accepts() and
// Run() reports the missing cache as an error.
func newRPSLPlugin(cfg rpslConfig, c *cache.Cache) *RPSLPlugin {
	return &RPSLPlugin{cfg: cfg, cache: c}
}

func (p *RPSLPlugin) Name() string        { return p.cfg.name }
func (p *RPSLPlugin) Description() string { return p.cfg.description }
func (p *RPSLPlugin) Category() string    { return "cidr" }
func (p *RPSLPlugin) Phase() int          { return 2 }
func (p *RPSLPlugin) Mode() string        { return p.cfg.mode }

func (p *RPSLPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta[p.cfg.metaKey] != "" && p.cache != nil
}

func (p *RPSLPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	// Guard's Runner interface exposes only Run, so its adapter never calls
	// Accepts(): the Accepts()-based self-disable cannot protect this path, and a
	// cache that failed to construct would nil-dereference inside GetOrDownload.
	if p.cache == nil {
		return nil, fmt.Errorf("%s: RPSL cache unavailable", p.cfg.name)
	}

	handles := splitHandles(input.Meta[p.cfg.metaKey])

	// Accepts() gates on a non-empty handle list too, and that gate is just as
	// unreachable from an embedder that only calls Run. Zero handles can match
	// zero records, so every byte of a multi-hundred-megabyte registry dump
	// downloaded in this state is spent to match nothing. Having nothing to
	// resolve is not an error.
	if len(handles) == 0 {
		return nil, nil
	}

	// The primary file is not best-effort: losing it means the run found nothing,
	// which must not read as "this org owns no space in this registry".
	records, err := p.recordsFrom(ctx, p.cfg.cacheURL, handles)
	if err != nil {
		return nil, err
	}

	// The inet6num file, where the registry ships one, is a second download and
	// IS best-effort: losing it costs IPv6 recall but must not discard the IPv4
	// records already in hand.
	if p.cfg.cacheURL6 != "" {
		v6Records, err := p.recordsFrom(ctx, p.cfg.cacheURL6, handles)
		switch {
		case err == nil:
			for handle, recs := range v6Records {
				records[handle] = append(records[handle], recs...)
			}
		case ctx.Err() != nil:
			// Best-effort ends where the run itself ends. A torn-down run's IPv4
			// records are a partial result, and returning them with a nil error
			// would report it as a complete one.
			//
			// Classified on ctx.Err(), never on the error's identity: a
			// transport's own timeout carries a context-shaped error
			// nondeterministically, so matching context.Canceled or
			// DeadlineExceeded would misread an unresponsive mirror as a
			// cancellation. ctx.Err() is monotone and read immediately after the
			// failing call, so an ancestor cancel landing mid-fetch is visible
			// here.
			return nil, err
		default:
			slog.Warn("RPSL inet6num file unavailable, continuing with IPv4 records only",
				"plugin", p.cfg.name, "url", p.cfg.cacheURL6, "error", err)
		}
	}

	var findings []plugins.Finding
	for handle, inetnums := range records {
		for _, inetnum := range inetnums {
			findings = append(findings, p.findingsFor(handle, inetnum, input.OrgName)...)
		}
	}

	return findings, nil
}

// recordsFrom resolves one RPSL file through the cache and parses the records
// belonging to handles out of it.
func (p *RPSLPlugin) recordsFrom(ctx context.Context, url string, handles []string) (map[string][]rpslInetnum, error) {
	dbFile, err := p.cache.GetOrDownload(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseRPSLInetnums(dbFile, handles)
}

// findingsFor renders one RPSL record as findings.
//
// An inet6num record carries a prefix directly, so the prefix IS the finding
// value, with no conversion. Parse and emit differ on canonicalisation, though:
// the parsed record keeps the registry's bytes verbatim, while the value emitted
// here is canonical. An inetnum record carries a start-end range, which expands
// to one finding per covering IPv4 CIDR.
func (p *RPSLPlugin) findingsFor(handle string, rec rpslInetnum, orgName string) []plugins.Finding {
	registry := strings.ToUpper(p.Name())

	if rec.prefix != "" {
		// netip.ParsePrefix accepts uppercase hex and set host bits, so the raw
		// spelling would let "2001:DB8::1/32" and "2001:db8::/32" land as two
		// distinct assets for one network. The parser already gated this prefix,
		// so the error arm cannot fire; it emits the raw string anyway, because
		// canonicalising must never cost a finding. Justification and value share
		// the canonical form so the evidence cannot contradict what it explains.
		value := rec.prefix
		if prefix, err := netip.ParsePrefix(rec.prefix); err == nil {
			value = prefix.Masked().String()
		}
		justification := rpslJustification(registry, "prefix", value, handle, rec.netname)
		return []plugins.Finding{p.newFinding(value, handle, orgName, rec.netname, justification)}
	}

	cidrs, err := cidr.ConvertIPv4RangeToCIDR(rec.start, rec.end)
	if err != nil {
		// Dropping the record is the right call, but doing it silently makes a
		// malformed range indistinguishable from a registry that listed nothing.
		slog.Warn("RPSL inetnum range could not be converted to CIDRs, skipping record",
			"registry", p.cfg.registry, "handle", handle,
			"start", rec.start, "end", rec.end, "error", err)
		return nil
	}
	rangeText := rec.start + " - " + rec.end
	findings := make([]plugins.Finding, 0, len(cidrs))
	for _, c := range cidrs {
		justification := rpslJustification(registry, "range", rangeText, handle, rec.netname) +
			fmt.Sprintf("; the range contains CIDR %q", c)
		findings = append(findings, p.newFinding(c, handle, orgName, rec.netname, justification))
	}
	return findings
}

// newFinding builds the CIDR finding shared by both record kinds. netname is
// always set, empty string included, so a v6 finding carries the same Data keys
// as a v4 one.
func (p *RPSLPlugin) newFinding(value, handle, orgName, netname, justification string) plugins.Finding {
	finding := plugins.Finding{
		Type:   plugins.FindingCIDR,
		Value:  value,
		Source: p.Name(),
		Data: map[string]any{
			"handle":   handle,
			"org":      orgName,
			"registry": p.cfg.registry,
			"netname":  netname,
		},
	}
	plugins.AddConfidence(&finding, confRPSLHandleInetnum, justification)
	return finding
}

// rpslJustification renders the evidence sentence shared by both record kinds.
// kind is "range" for an inetnum record and "prefix" for an inet6num one: an
// inet6num record has no range, so claiming one would be false.
func rpslJustification(registry, kind, subject, handle, netname string) string {
	justification := fmt.Sprintf("%s RPSL records %s %q under organization handle %q",
		registry, kind, subject, handle)
	if netname != "" {
		justification += fmt.Sprintf(" with netname %q", netname)
	}
	return justification
}

// parseRPSLInetnums parses an RPSL database file and returns the inetnum and
// inet6num records belonging to the given handles. Used by both APNIC and
// AFRINIC plugins.
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
	var currentPrefix string

	// commitRecord files the record accumulated so far, if it matches a handle,
	// and then clears the accumulator. Both callers depend on that reset: the
	// blank-line branch so the next record starts clean, and the post-loop flush
	// so a file that DID end with a blank line does not commit its last record a
	// second time.
	commitRecord := func() {
		if currentOrg != "" && handleSet[strings.ToUpper(currentOrg)] {
			switch {
			case currentPrefix != "":
				// RPSL is downloaded third-party text, so a prefix net/netip
				// rejects is skipped rather than propagated: malformed lines are
				// expected and must not abort the rest of the file.
				if _, err := netip.ParsePrefix(currentPrefix); err == nil {
					results[currentOrg] = append(results[currentOrg], rpslInetnum{
						prefix:  currentPrefix,
						netname: currentNetname,
					})
				}
			case inetnumStart != "" && inetnumEnd != "":
				results[currentOrg] = append(results[currentOrg], rpslInetnum{
					start:   inetnumStart,
					end:     inetnumEnd,
					netname: currentNetname,
				})
			}
		}
		// Reset for next record
		currentOrg, currentNetname = "", ""
		inetnumStart, inetnumEnd = "", ""
		currentPrefix = ""
	}

	for scanner.Scan() {
		line := scanner.Text()

		// RPSL records are separated by blank lines
		if strings.TrimSpace(line) == "" {
			// End of record - check if it matches our handles
			commitRecord()
			continue
		}

		// Parse RPSL fields
		if strings.HasPrefix(line, "inet6num:") {
			// An inet6num line carries a prefix ("2001:db8::/32"), never a
			// start-end range. The parsed record keeps it verbatim: normalising it
			// in the parser would rewrite what the registry actually published,
			// and the record is what reports that. Canonicalisation belongs at the
			// emit boundary instead, and lives in findingsFor.
			currentPrefix = strings.TrimSpace(strings.TrimPrefix(line, "inet6num:"))
		} else if strings.HasPrefix(line, "inetnum:") {
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

	// A file whose last record has no trailing blank line never reaches the
	// branch above, so that record would be dropped with no error and no log
	// line: indistinguishable from "this org owns nothing here". Flushing it here
	// is a no-op for a file that does end with a blank line, because committing
	// resets the accumulator.
	commitRecord()

	return results, scanner.Err()
}

// rpslInetnum represents one RPSL address record: either an inetnum range
// (start/end set, prefix empty) or an inet6num prefix (prefix set, start/end
// empty). The two are mutually exclusive, and prefix holds the registry's
// original bytes.
type rpslInetnum struct {
	start   string
	end     string
	prefix  string
	netname string
}
