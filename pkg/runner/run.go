package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/plugins/domains"
)

func newRunCmd() *cobra.Command {
	var (
		org               string
		domain            string
		asn               string
		cidr              string
		pluginsList       string
		disableList       string
		concurrency       int
		output            string
		mode              string
		dohWordlist       string
		dohServers        string
		dohGateways       string
		dohDeployGateways bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Discover assets for an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate mode flag
			switch mode {
			case "passive", "active", "all":
				// valid
			default:
				return fmt.Errorf("invalid --mode value %q: must be passive, active, or all", mode)
			}

			input := plugins.Input{
				OrgName: org,
				Domain:  domain,
				ASN:     asn,
				CIDR:    cidr,
				Meta:    make(map[string]string),
			}

			// Populate DoH enumeration options into Meta
			if dohWordlist != "" {
				input.Meta["doh_wordlist"] = dohWordlist
			}
			if dohServers != "" {
				input.Meta["doh_servers"] = dohServers
			}
			if dohGateways != "" {
				input.Meta["doh_gateways"] = dohGateways
			}
			if dohDeployGateways {
				input.Meta["doh_deploy_gateways"] = "true"
			}

			// Build plugin list (apply whitelist/blacklist/mode)
			selected := selectPlugins(pluginsList, disableList, mode)

			if len(selected) == 0 {
				fmt.Fprintf(os.Stderr, "No plugins selected for mode %q.\n", mode)
				return nil
			}
			fmt.Fprintf(os.Stderr, "Running %d plugin(s) in %q mode...\n", len(selected), mode)

			// Run the two-phase pipeline
			findings, err := runPipeline(cmd.Context(), input, selected, concurrency)
			if err != nil {
				return err
			}

			// Output results
			return printFindings(findings, output)
		},
	}

	cmd.Flags().StringVar(&org, "org", "", "Organization name to search (required)")
	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Known domain hint (optional)")
	cmd.Flags().StringVar(&asn, "asn", "", "Known ASN hint, e.g. AS12345 (optional)")
	cmd.Flags().StringVar(&cidr, "cidr", "", "Known CIDR range, e.g. 192.0.2.0/24 (optional)")
	cmd.Flags().StringVar(&pluginsList, "plugins", "", "Comma-separated plugin whitelist (default: all)")
	cmd.Flags().StringVar(&disableList, "disable", "", "Comma-separated plugin blacklist")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "Max concurrent plugins")
	cmd.Flags().StringVarP(&output, "output", "o", "terminal", "Output format: terminal|json|ndjson")
	cmd.Flags().StringVar(&mode, "mode", "passive", "Plugin mode filter: passive|active|all")
	cmd.Flags().StringVar(&dohWordlist, "doh-wordlist", "", "Path to subdomain wordlist for DoH enumeration (default: embedded)")
	cmd.Flags().StringVar(&dohServers, "doh-servers", "", "Comma-separated DoH server URLs")
	cmd.Flags().StringVar(&dohGateways, "doh-gateways", "", "Comma-separated AWS API Gateway URLs for DoH")
	cmd.Flags().BoolVar(&dohDeployGateways, "doh-deploy-gateways", false, "Auto-deploy AWS API Gateways pointing to DoH servers")
	_ = cmd.MarkFlagRequired("org")

	return cmd
}

// colorEnabled reports whether terminal color/decoration output is active.
// It respects the NO_COLOR convention (https://no-color.org) and checks
// whether stdout is a character device (TTY).
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// selectPlugins applies --plugins whitelist, --disable blacklist, and --mode filter to return active plugins.
func selectPlugins(whitelist, blacklist, mode string) []plugins.Plugin {
	var result []plugins.Plugin

	if whitelist != "" {
		names := strings.Split(whitelist, ",")
		result = plugins.Filter(trimAll(names))
	} else {
		result = plugins.All()
		if blacklist != "" {
			disabled := make(map[string]bool)
			for _, name := range strings.Split(blacklist, ",") {
				disabled[strings.TrimSpace(name)] = true
			}
			filtered := make([]plugins.Plugin, 0, len(result))
			for _, p := range result {
				if !disabled[p.Name()] {
					filtered = append(filtered, p)
				}
			}
			result = filtered
		}
	}

	// Apply mode filter
	if mode != "all" {
		filtered := make([]plugins.Plugin, 0, len(result))
		for _, p := range result {
			if p.Mode() == mode {
				filtered = append(filtered, p)
			}
		}
		result = filtered
	}

	return result
}

const (
	DefaultPipelineTimeout = 30 * time.Minute
	// maxFindings caps results to prevent OOM on extremely broad scans.
	// Tuned based on typical org discovery yielding 10-50k findings.
	maxFindings = 100_000
)

// findingsCollector provides thread-safe collection of findings with a cap.
type findingsCollector struct {
	mu       sync.Mutex
	findings []plugins.Finding
	cap      int
}

func newFindingsCollector(cap int) *findingsCollector {
	return &findingsCollector{cap: cap}
}

func (c *findingsCollector) add(findings []plugins.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.findings) >= c.cap {
		slog.Warn("findings cap reached, dropping additional results", "cap", c.cap)
		return
	}
	remaining := c.cap - len(c.findings)
	if len(findings) > remaining {
		findings = findings[:remaining]
	}
	c.findings = append(c.findings, findings...)
}

func (c *findingsCollector) all() []plugins.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.findings
}

// phasedPlugins holds plugins grouped by execution phase.
type phasedPlugins struct {
	independent []plugins.Plugin // Phase 0: no dependencies
	phase1      []plugins.Plugin // Phase 1: discover RIR handles
	phase2      []plugins.Plugin // Phase 2: resolve handles to CIDRs
	phase3      []plugins.Plugin // Phase 3: consume discovered CIDRs/domains
}

// partitionByPhase separates plugins into execution phases.
func partitionByPhase(selected []plugins.Plugin) phasedPlugins {
	var p phasedPlugins
	for _, plugin := range selected {
		switch plugin.Phase() {
		case 1:
			p.phase1 = append(p.phase1, plugin)
		case 2:
			p.phase2 = append(p.phase2, plugin)
		case 3:
			p.phase3 = append(p.phase3, plugin)
		default:
			p.independent = append(p.independent, plugin)
		}
	}
	return p
}

// runPipeline executes the multi-phase discovery pipeline.
//
// Phase 0 (parallel with all): independent plugins (no dependencies)
// Phase 1 (parallel): plugins with Phase()==1 discover RIR org handles
// Phase 2 (parallel): plugins with Phase()==2 resolve handles to CIDRs (uses enriched Input.Meta)
// Phase 3 (parallel): plugins with Phase()==3 consume discovered CIDRs via Meta["cidrs"]
//
//	and/or discovered domains via Meta["discovered_domains"]
func runPipeline(ctx context.Context, input plugins.Input, selected []plugins.Plugin, concurrency int) ([]plugins.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultPipelineTimeout)
	defer cancel()

	collector := newFindingsCollector(maxFindings)
	phased := partitionByPhase(selected)

	// Start independent plugins concurrently (no deps).
	// These run in parallel with Phase 1 and 2 for efficiency.
	independentDone := runPluginsAsync(ctx, phased.independent, input, concurrency, collector)

	// Phase 1: discover RIR handles
	handleFindings := runPhaseWithResults(ctx, phased.phase1, input, concurrency)
	enrichedInput := enrichWithHandles(input, handleFindings)

	// Phase 2: resolve handles to CIDRs
	phase2Findings := runPhaseWithResults(ctx, phased.phase2, enrichedInput, concurrency)
	collector.add(phase2Findings)

	// Wait for independent plugins (must complete before Phase 3 for domain enrichment)
	<-independentDone

	// Phase 3: consume discovered CIDRs and domains
	if len(phased.phase3) > 0 {
		phase3Input := enrichWithCIDRs(enrichedInput, phase2Findings)
		phase3Input = enrichWithDomains(phase3Input, collector.all())
		runPlugins(ctx, phased.phase3, phase3Input, concurrency, collector)
	}

	// Filter out internal cidr-handle findings (not user-facing)
	filtered := filterOutput(collector.all())

	// Filter out domain findings under wildcard DNS zones. For each unique
	// parent domain among the findings, probe once for wildcard DNS and drop
	// all findings under wildcard parents. This catches passive plugins
	// (crt-sh, passive-dns) that have no wildcard awareness.
	filtered = domains.FilterWildcardDomains(ctx, filtered)

	return filtered, nil
}

// runPluginsAsync starts plugins concurrently and returns a channel that closes when done.
// This allows the caller to continue with other work while plugins run.
func runPluginsAsync(ctx context.Context, pluginList []plugins.Plugin, input plugins.Input, concurrency int, collector *findingsCollector) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPlugins(ctx, pluginList, input, concurrency, collector)
	}()
	return done
}

// runPlugins executes plugins concurrently and collects findings.
// Plugin errors are logged but don't fail the pipeline, ensuring partial success:
// if 20 plugins run and 3 fail, we return results from the 17 successful plugins.
func runPlugins(ctx context.Context, pluginList []plugins.Plugin, input plugins.Input, concurrency int, collector *findingsCollector) {
	var group errgroup.Group
	group.SetLimit(concurrency)

	for _, p := range pluginList {
		p := p // capture loop variable
		if !p.Accepts(input) {
			continue
		}
		group.Go(func() error {
			findings, err := p.Run(ctx, input)
			if err != nil {
				slog.Warn("plugin error", "plugin", p.Name(), "error", err)
				return nil // continue with other plugins
			}
			collector.add(findings)
			return nil
		})
	}

	// Wait() always returns nil because plugin errors are logged but return nil.
	// This ensures partial success - one failing plugin doesn't break the pipeline.
	_ = group.Wait()
}

// runPhaseWithResults executes plugins and returns their combined findings.
// Used for phases that need to pass results to subsequent phases.
func runPhaseWithResults(ctx context.Context, pluginList []plugins.Plugin, input plugins.Input, concurrency int) []plugins.Finding {
	var (
		mu       sync.Mutex
		findings []plugins.Finding
	)

	var group errgroup.Group
	group.SetLimit(concurrency)

	for _, p := range pluginList {
		p := p // capture loop variable
		if !p.Accepts(input) {
			continue
		}
		group.Go(func() error {
			f, err := p.Run(ctx, input)
			if err != nil {
				slog.Warn("plugin error", "plugin", p.Name(), "error", err)
				return nil
			}
			mu.Lock()
			findings = append(findings, f...)
			mu.Unlock()
			return nil
		})
	}

	_ = group.Wait()
	return findings
}

// enrichWithHandles groups cidr-handle findings by registry and injects them into Input.Meta.
func enrichWithHandles(input plugins.Input, findings []plugins.Finding) plugins.Input {
	enriched := input
	enriched.Meta = make(map[string]string, len(input.Meta))
	for k, v := range input.Meta {
		enriched.Meta[k] = v
	}

	groups := make(map[string][]string)
	for _, f := range findings {
		if f.Type != plugins.FindingCIDRHandle {
			continue
		}
		reg, _ := f.Data["registry"].(string)
		if reg == "" {
			for _, r := range []string{"arin", "ripe", "apnic", "afrinic"} {
				groups[r] = append(groups[r], f.Value)
			}
			continue
		}
		groups[reg] = append(groups[reg], f.Value)
	}

	for reg, handles := range groups {
		key := reg + "_handles"
		existing := enriched.Meta[key]
		if existing != "" {
			enriched.Meta[key] = existing + "," + strings.Join(handles, ",")
		} else {
			enriched.Meta[key] = strings.Join(handles, ",")
		}
	}
	return enriched
}

// enrichWithCIDRs extracts CIDR findings and injects them into Input.Meta["cidrs"].
func enrichWithCIDRs(input plugins.Input, findings []plugins.Finding) plugins.Input {
	enriched := input
	enriched.Meta = make(map[string]string, len(input.Meta))
	for k, v := range input.Meta {
		enriched.Meta[k] = v
	}

	var cidrs []string
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.Type != plugins.FindingCIDR {
			continue
		}
		if !seen[f.Value] {
			seen[f.Value] = true
			cidrs = append(cidrs, f.Value)
		}
	}

	if len(cidrs) > 0 {
		enriched.Meta["cidrs"] = strings.Join(cidrs, ",")
	}
	return enriched
}

// enrichWithDomains collects FindingDomain values from findings and injects them
// into Input.Meta["discovered_domains"] as a comma-separated list for Phase 3 plugins.
func enrichWithDomains(input plugins.Input, findings []plugins.Finding) plugins.Input {
	enriched := input
	enriched.Meta = make(map[string]string, len(input.Meta))
	for k, v := range input.Meta {
		enriched.Meta[k] = v
	}

	seen := make(map[string]bool)
	var domains []string
	for _, f := range findings {
		if f.Type != plugins.FindingDomain {
			continue
		}
		d := strings.ToLower(strings.TrimSpace(f.Value))
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}

	if len(domains) > 0 {
		enriched.Meta["discovered_domains"] = strings.Join(domains, ",")
	}
	return enriched
}

// filterOutput removes internal FindingCIDRHandle findings from final output.
func filterOutput(findings []plugins.Finding) []plugins.Finding {
	result := make([]plugins.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Type != plugins.FindingCIDRHandle {
			result = append(result, f)
		}
	}
	return result
}

// printFindings outputs findings in the requested format.
func printFindings(findings []plugins.Finding, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	case "ndjson":
		enc := json.NewEncoder(os.Stdout)
		for _, f := range findings {
			if err := enc.Encode(f); err != nil {
				return err
			}
		}
		return nil
	default: // terminal
		if len(findings) == 0 {
			fmt.Println("No assets found.")
			return nil
		}
		for _, f := range findings {
			line := fmt.Sprintf("[%s] %s (%s)", f.Type, f.Value, f.Source)
			// Surface review flag and confidence for borderline findings
			if plugins.NeedsReview(f) {
				if colorEnabled() {
					line += fmt.Sprintf(" ⚠ needs-review [confidence:%.2f]", plugins.Confidence(f))
				} else {
					line += fmt.Sprintf(" [needs-review confidence:%.2f]", plugins.Confidence(f))
				}
			}
			fmt.Println(line)
		}
		return nil
	}
}

func trimAll(ss []string) []string {
	result := make([]string, len(ss))
	for i, s := range ss {
		result[i] = strings.TrimSpace(s)
	}
	return result
}
