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
)

func newRunCmd() *cobra.Command {
	var (
		org               string
		domain            string
		asn               string
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
	maxFindings            = 100_000
)

// runPipeline executes the two-phase discovery pipeline.
//
// Phase 1 (parallel): plugins with Phase()==1 discover RIR org handles
// Phase 2 (parallel): plugins with Phase()==2 resolve handles to CIDRs (uses enriched Input.Meta)
// Independent (parallel with all phases): plugins with Phase()==0
func runPipeline(ctx context.Context, input plugins.Input, selected []plugins.Plugin, concurrency int) ([]plugins.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultPipelineTimeout)
	defer cancel()

	var (
		mu          sync.Mutex
		allFindings []plugins.Finding
	)

	collect := func(findings []plugins.Finding) {
		mu.Lock()
		defer mu.Unlock()
		if len(allFindings) >= maxFindings {
			slog.Warn("findings cap reached, dropping additional results", "cap", maxFindings)
			return
		}
		remaining := maxFindings - len(allFindings)
		if len(findings) > remaining {
			findings = findings[:remaining]
		}
		allFindings = append(allFindings, findings...)
	}

	// Separate plugins by phase
	var phase1, phase2, independent []plugins.Plugin
	for _, p := range selected {
		switch p.Phase() {
		case 1:
			phase1 = append(phase1, p)
		case 2:
			phase2 = append(phase2, p)
		default:
			independent = append(independent, p)
		}
	}

	// Start independent plugins concurrently (no deps)
	var indepG errgroup.Group
	indepG.SetLimit(concurrency)
	for _, p := range independent {
		p := p
		if !p.Accepts(input) {
			continue
		}
		indepG.Go(func() error {
			f, err := p.Run(ctx, input)
			if err != nil {
				slog.Warn("plugin error", "plugin", p.Name(), "error", err)
				return nil
			}
			collect(f)
			return nil
		})
	}

	// Phase 1: discover handles
	var handleFindings []plugins.Finding
	var handleMu sync.Mutex

	var p1G errgroup.Group
	p1G.SetLimit(concurrency)
	for _, p := range phase1 {
		p := p
		if !p.Accepts(input) {
			continue
		}
		p1G.Go(func() error {
			f, err := p.Run(ctx, input)
			if err != nil {
				slog.Warn("plugin error", "plugin", p.Name(), "error", err)
				return nil
			}
			handleMu.Lock()
			defer handleMu.Unlock()
			handleFindings = append(handleFindings, f...)
			return nil
		})
	}
	// Plugin errors are logged within goroutines and return nil;
	// Wait() always returns nil under this pattern.
	_ = p1G.Wait()

	// Enrich input with discovered handles
	enrichedInput := enrichWithHandles(input, handleFindings)

	// Phase 2: resolve handles to CIDRs
	var p2G errgroup.Group
	p2G.SetLimit(concurrency)
	for _, p := range phase2 {
		p := p
		if !p.Accepts(enrichedInput) {
			continue
		}
		p2G.Go(func() error {
			f, err := p.Run(ctx, enrichedInput)
			if err != nil {
				slog.Warn("plugin error", "plugin", p.Name(), "error", err)
				return nil
			}
			collect(f)
			return nil
		})
	}
	// Plugin errors are logged within goroutines and return nil;
	// Wait() always returns nil under this pattern.
	_ = p2G.Wait()

	// Wait for independent plugins
	// Plugin errors are logged within goroutines and return nil;
	// Wait() always returns nil under this pattern.
	_ = indepG.Wait()

	// Filter out internal cidr-handle findings (not user-facing)
	return filterOutput(allFindings), nil
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
