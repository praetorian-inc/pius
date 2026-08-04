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

	// FindingPreseed is a discovered organizational seed (company name, email, person name).
	// Data["preseed_type"] carries the preseed classification (e.g., "whois+company").
	// Data["preseed_title"] carries a human-readable label (often the same as Value).
	FindingPreseed FindingType = "preseed"
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

	// CIDR is an optional known IP range (e.g., "192.0.2.0/24").
	CIDR string

	// Meta carries phase enrichment data between pipeline phases.
	// Phase 1 plugins populate Meta["arin_handles"], Meta["ripe_handles"],
	// Meta["apnic_handles"], Meta["afrinic_handles"] with comma-separated handles.
	// Phase 2 plugins read from Meta to know which handles to look up.
	Meta map[string]string
}

// Confidence is a single piece of scored, explained evidence supporting a
// finding. Entries are additive: a finding's total confidence is the sum of its
// entry scores, capped at 1.0 (see TotalConfidence).
type Confidence struct {
	// Score is this evidence's contribution to the total confidence.
	Score float64 `json:"score"`

	// Justification explains, in human-readable terms, why this evidence
	// supports the finding.
	Justification string `json:"justification"`
}

// Finding represents a single discovered asset or intermediate result.
type Finding struct {
	// Type classifies what was found.
	Type FindingType

	// Value is the primary discovered value (CIDR block, domain name, or RIR handle).
	Value string

	// Source is the name of the plugin that produced this finding.
	Source string

	// Confidences is the scored, justified evidence supporting this finding.
	// An empty slice means the finding was never scored, which is distinct from
	// a finding carrying an explicit zero-score entry. Append through
	// AddConfidence; read the aggregate through TotalConfidence.
	Confidences []Confidence

	// Data contains source-specific metadata. It must never carry confidence
	// state — that lives in Confidences.
	Data map[string]any
}

// Descriptor identifies and describes a plugin.
type Descriptor interface {
	// Name returns the unique identifier for this plugin (e.g., "arin", "crt-sh").
	Name() string

	// Description returns a short human-readable description of what this plugin does.
	Description() string

	// Category returns the type of assets this plugin discovers: "cidr" or "domain".
	Category() string
}

// Classifier routes a plugin through the two-phase pipeline.
type Classifier interface {
	// Phase returns the pipeline phase this plugin belongs to:
	//   1 = Phase 1 (discovers RIR org handles, emits FindingCIDRHandle)
	//   2 = Phase 2 (resolves handles to CIDRs, requires Meta enrichment from Phase 1)
	//   0 = Independent (no dependencies, runs concurrently with all phases)
	Phase() int

	// Mode returns the execution mode: "passive" (read-only OSINT) or "active" (sends probes to targets).
	Mode() string
}

// Runner executes plugin logic against a given input.
type Runner interface {
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

// Plugin composes Descriptor, Classifier, and Runner into the full plugin contract.
// Each plugin is self-contained and self-registering via Go init() functions.
type Plugin interface {
	Descriptor
	Classifier
	Runner
}

// FindingSet collects findings, deduplicating by (Type, Value) so that
// e.g. FindingDomain and FindingPreseed with the same Value are both kept.
type FindingSet struct {
	seen     map[string]bool
	Findings []Finding
}

func NewFindingSet() *FindingSet {
	return &FindingSet{seen: make(map[string]bool)}
}

func (fs *FindingSet) Add(f Finding) {
	if f.Value == "" {
		return
	}
	key := string(f.Type) + "|" + f.Value
	if !fs.seen[key] {
		fs.seen[key] = true
		fs.Findings = append(fs.Findings, f)
	}
}
