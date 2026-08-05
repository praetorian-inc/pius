package cidrs

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// confRegistryResolution is the weight of the registry lookup leg itself: the
// registry, asked about a handle, answered with this netblock.
//
// It is high but not certain. The mapping is deterministic and authoritative —
// RDAP and the RPSL databases are the registries' own records — so the leg
// contributes no ambiguity of its own. What keeps it below 1.0 is that registry
// data goes stale: a netblock can be transferred or reassigned before the
// object that still lists it is updated.
//
// This is a ceiling, never an addend. A CIDR is only as good as the handle it
// came from, so plugins.Compose takes the minimum of the two legs.
const confRegistryResolution = 0.85

// handleProvenance returns every upstream finding that discovered handle for
// registry.
//
// It narrows plugins.UpstreamFor with the one rule that is local to handles: a
// handle whose registry is unknown matches every registry. That is the EDGAR
// case — a token scraped from a filing carries no registry, so the runner
// broadcasts it to all of plugins.RIRRegistries and whichever one resolves it is
// entitled to say where the handle came from. Requiring an exact registry match
// would silently drop EDGAR's provenance from precisely the findings it led to.
func handleProvenance(input plugins.Input, handle, registry string) []plugins.Finding {
	candidates := plugins.UpstreamFor(input, plugins.FindingCIDRHandle, handle)

	matches := make([]plugins.Finding, 0, len(candidates))
	for _, f := range candidates {
		found, _ := f.Data["registry"].(string)
		if found != "" && found != plugins.RegistryUnknown && !strings.EqualFold(found, registry) {
			continue
		}
		matches = append(matches, f)
	}
	return matches
}

// composeHandleEvidence builds the confidence entries for a netblock the
// registry mapped from a handle.
//
// The two observations are a chain, not corroboration: the registry mapping is
// only meaningful because something identified the handle as the target's in the
// first place, and it says nothing independent about ownership. See
// plugins.Compose for why that is composed rather than summed.
//
// Callers hoist the provenance lookup out of their per-CIDR loop — it depends
// only on the handle — and pass it back in, so a handle that expands to
// thousands of netblocks scans the upstream findings once.
func composeHandleEvidence(provenance []plugins.Finding, mapping registryMapping) []plugins.Confidence {
	return plugins.Compose(provenance, confRegistryResolution, func(upstream *plugins.Finding) string {
		if upstream == nil {
			return mapping.describe()
		}
		return mapping.describe() + ", " + describeHandleOrigin(*upstream)
	})
}

// registryMapping is one registry's answer about one handle: the netblock it
// returned, and whatever the registry called it.
type registryMapping struct {
	// registry is the RIR that answered, lower-case ("arin", "apnic").
	registry string

	// handle is the org handle that was looked up.
	handle string

	// cidr is the netblock the registry returned.
	cidr string

	// netname is the registry's label for the netblock, when the source format
	// carries one. RPSL inetnum objects do; RDAP's cidr0 blocks do not.
	netname string
}

// describe renders the mapping leg of the justification.
func (m registryMapping) describe() string {
	described := fmt.Sprintf("%s maps CIDR %q to handle %q",
		strings.ToUpper(m.registry), m.cidr, m.handle)
	if m.netname != "" {
		described += fmt.Sprintf(" (netname %s)", m.netname)
	}
	return described
}

// describeHandleOrigin renders the upstream leg: who found the handle, and what
// they were looking for when they did.
func describeHandleOrigin(upstream plugins.Finding) string {
	source := upstream.Source
	if source == "" {
		source = "an earlier phase"
	}

	if org, _ := upstream.Data["org"].(string); org != "" {
		return fmt.Sprintf("which %s identified while searching for %q", source, org)
	}
	return fmt.Sprintf("which %s identified", source)
}
