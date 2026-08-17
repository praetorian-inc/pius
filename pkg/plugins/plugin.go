package plugins

import (
	"context"
	"encoding/json"
)

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

	// FindingWhoisResult carries structured WHOIS/RDAP registration data for a domain.
	// Value is the domain name; Data includes registration dates, contacts, and source metadata.
	FindingWhoisResult FindingType = "whois-result"

	// FindingIPWhoisResult carries structured WHOIS/RDAP allocation data for an IP or CIDR.
	FindingIPWhoisResult FindingType = "ip-whois-result"
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
	// OrgName is a company/organization name to search for.
	OrgName string

	// PersonName is a registrant person name to search for.
	// Whoxy and similar APIs distinguish person names from company names;
	// callers should populate the appropriate field based on the data source.
	PersonName string

	// Domain is an optional known domain associated with the org.
	Domain string

	// Email is an optional registrant email hint.
	Email string

	// ASN is an optional known Autonomous System Number (e.g., "AS12345").
	ASN string

	// IP is an optional known IP address.
	IP string

	// CIDR is an optional known IP range (e.g., "192.0.2.0/24").
	CIDR string

	// Meta carries phase enrichment data between pipeline phases.
	// Phase 1 plugins populate Meta["arin_handles"], Meta["ripe_handles"],
	// Meta["apnic_handles"], Meta["afrinic_handles"] with comma-separated handles.
	// Phase 2 plugins read from Meta to know which handles to look up.
	Meta map[string]string
}

// Reference is display-only source data supporting confidence evidence. Type
// tells consumers how to render Data without requiring every plugin to share a
// source-specific schema.
type Reference struct {
	Label string `json:"label"`
	Type  string `json:"type"`
	Data  any    `json:"data"`

	// URL is accepted while source plugins migrate to typed Data. It is
	// normalized into URLReferenceData before a confidence is emitted.
	URL string `json:"-"`
}

const (
	ReferenceTypeURL          = "url"
	ReferenceTypeJSON         = "json"
	ReferenceTypeReferences   = "references"
	ReferenceTypeHTTPExchange = "http_exchange"
	ReferenceTypeRDAP         = "rdap"
	ReferenceTypeRPSL         = "rpsl"
	ReferenceTypeTLS          = "tls_certificate"
	ReferenceTypeWHOIS        = "whois"
)

type URLReferenceData struct {
	URL string `json:"url"`
}

type HTTPRequestReference struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Body   any    `json:"body,omitempty"`
}

type HTTPExchangeReference struct {
	Request  HTTPRequestReference `json:"request"`
	Response any                  `json:"response"`
}

// URLReference constructs a reference to a public source record.
func URLReference(label, url string) Reference {
	return Reference{Label: label, Type: ReferenceTypeURL, Data: URLReferenceData{URL: url}}
}

// HTTPReference constructs a credential-free request/response reference.
func HTTPReference(label, method, url string, requestBody, response any) Reference {
	return Reference{
		Label: label,
		Type:  ReferenceTypeHTTPExchange,
		Data: HTTPExchangeReference{
			Request:  HTTPRequestReference{Method: method, URL: url, Body: requestBody},
			Response: response,
		},
	}
}

// Confidence is a single piece of scored, explained evidence supporting a
// finding. Entries are additive: a finding's total confidence is the sum of its
// entry scores, capped at 100 (see TotalConfidence).
type Confidence struct {
	// Score is this evidence's contribution to the total confidence.
	Score int `json:"score"`

	// Justification explains, in human-readable terms, why this evidence
	// supports the finding.
	Justification string `json:"justification"`

	// Reference contains the source material a user can inspect to verify the
	// justification. Evidence without useful source material leaves this nil.
	Reference *Reference `json:"reference,omitempty"`

	// References is a plugin-internal migration field. AddConfidence folds it
	// into the singular Reference before findings leave Pius.
	References []Reference `json:"-"`
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

// FindingData converts a typed result into Finding.Data.
func FindingData(value any) map[string]any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal(encoded, &data); err != nil {
		return nil
	}
	return data
}

// findingFields aliases Finding so MarshalJSON can encode the plain struct
// without re-entering itself. A defined type does not inherit Finding's
// methods, which is exactly what breaks the recursion.
type findingFields Finding

// MarshalJSON emits a Finding's stored fields plus its two derived confidence
// values, so a reader of `--output json` or `--output ndjson` can see the
// aggregate and the review verdict without summing the entries by hand.
//
// TotalConfidence and NeedsReview are output-only: Confidences remains the sole
// source of truth, so both are recomputed on demand and simply ignored when
// findings are read back (the plugin caches round-trip through this encoding).
// Nothing should ever populate them as stored state.
func (f Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		findingFields
		TotalConfidence int
		NeedsReview     bool
	}{
		findingFields:   findingFields(f),
		TotalConfidence: TotalConfidence(f),
		NeedsReview:     NeedsReview(f),
	})
}

// Descriptor identifies and describes a plugin.
type Descriptor interface {
	// Name returns the unique identifier for this plugin (e.g., "arin", "crt-sh").
	Name() string

	// Description returns a short human-readable description of what this plugin does.
	Description() string

	// Category returns the type of assets this plugin discovers: "cidr", "domain", or "ip".
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
