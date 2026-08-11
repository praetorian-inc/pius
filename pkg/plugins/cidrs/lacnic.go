package cidrs

import (
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("lacnic", func() plugins.Plugin {
		return newRDAPPlugin(lacnicConfig())
	})
}

// NewLACNICPlugin builds the LACNIC RDAP plugin over an injected HTTP client, so
// callers outside this repo can supply their own transport. A nil client falls
// back to the package default — see doerOrDefault for the rule.
func NewLACNICPlugin(c *client.Client) *RDAPPlugin {
	return newRDAPPluginWithDoer(lacnicConfig(), doerOrDefault(c))
}

// lacnicConfig is the single source of truth for the LACNIC registry's RDAP
// configuration. Both init() and NewLACNICPlugin read it, so the registered
// plugin and the injected one cannot drift apart.
func lacnicConfig() rdapConfig {
	return rdapConfig{
		name:        "lacnic",
		description: "LACNIC RDAP: resolves org handles to CIDR blocks (Latin America & Caribbean)",
		baseURL:     "https://rdap.lacnic.net/rdap/entity",
		metaKey:     "lacnic_handles",
		registry:    "lacnic",
		mode:        plugins.ModePassive,
	}
}
