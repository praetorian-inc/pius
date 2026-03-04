package plugins

import "context"

// FindingType categorizes what was discovered
type FindingType string

const (
	// FindingCIDRHandle is an internal finding type (not emitted to output).
	// Phase 1 plugins emit this to pass RIR org handles to Phase 2 plugins.
	FindingCIDRHandle FindingType = "cidr-handle"

	// FindingCIDR is a discovered CIDR block (e.g., "192.168.1.0/24")
	FindingCIDR FindingType = "cidr"

	// FindingDomain is a discovered domain name (e.g., "example.com")
	FindingDomain FindingType = "domain"
)

// Mode constants for plugin classification.
const (
	// ModePassive indicates read-only OSINT plugins (e.g., crt.sh, WHOIS).
	ModePassive = "passive"

	// ModeActive indicates plugins that send probes to targets (e.g., DNS brute-force, zone transfer).
	ModeActive = "active"
)

// Input is the discovery request passed to each plugin.
type Input struct {
	// OrgName is the primary organization name to search for. Required.
	OrgName string

	// Domain is an optional known domain associated with the org.
	Domain string

	// Email is an optional registrant email hint.
	Email string

	// ASN is an optional known Autonomous System Number (e.g., "AS12345").
	ASN string

	// Meta carries phase enrichment data between pipeline phases.
	// Phase 1 plugins populate Meta["arin_handles"], Meta["ripe_handles"],
	// Meta["apnic_handles"], Meta["afrinic_handles"] with comma-separated handles.
	// Phase 2 plugins read from Meta to know which handles to look up.
	Meta map[string]string
}

// Finding represents a single discovered asset or intermediate result.
type Finding struct {
	// Type classifies what was found.
	Type FindingType

	// Value is the primary discovered value (CIDR block, domain name, or RIR handle).
	Value string

	// Source is the name of the plugin that produced this finding.
	Source string

	// Data contains source-specific metadata.
	Data map[string]any
}

// Plugin is the interface that all Pius data source plugins must implement.
// Each plugin is self-contained and self-registering via Go init() functions.
type Plugin interface {
	// Name returns the unique identifier for this plugin (e.g., "arin", "crt-sh").
	Name() string

	// Description returns a short human-readable description of what this plugin does.
	Description() string

	// Category returns the type of assets this plugin discovers: "cidr" or "domain".
	Category() string

	// Phase returns the pipeline phase this plugin belongs to:
	//   1 = Phase 1 (discovers RIR org handles, emits FindingCIDRHandle)
	//   2 = Phase 2 (resolves handles to CIDRs, requires Meta enrichment from Phase 1)
	//   0 = Independent (no dependencies, runs concurrently with all phases)
	Phase() int

	// Mode returns the execution mode: "passive" (read-only OSINT) or "active" (sends probes to targets).
	Mode() string

	// Accepts returns true if this plugin can process the given input.
	// Use this for pre-filtering: check required fields, API key env vars, etc.
	// Plugins requiring missing API keys must return false here.
	Accepts(input Input) bool

	// Run executes the plugin and returns discovered findings.
	// Implementations must respect context cancellation.
	// On partial success (some results found, some failed), return what was found with nil error.
	// Return (nil, nil) if the plugin has nothing to contribute (not an error condition).
	Run(ctx context.Context, input Input) ([]Finding, error)
}
