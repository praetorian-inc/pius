package cidrs

import (
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("arin", func() plugins.Plugin {
		return newRDAPPlugin(arinConfig())
	})
}

// NewARINPlugin builds the ARIN RDAP plugin over an injected HTTP client, so
// callers outside this repo can supply their own transport. A nil client falls
// back to the package default — see doerOrDefault for the rule.
func NewARINPlugin(c *client.Client) *RDAPPlugin {
	return newRDAPPluginWithDoer(arinConfig(), doerOrDefault(c))
}

// arinConfig is the single source of truth for the ARIN registry's RDAP
// configuration. Both init() and NewARINPlugin read it, so the registered
// plugin and the injected one cannot drift apart.
func arinConfig() rdapConfig {
	return rdapConfig{
		name:        "arin",
		description: "ARIN RDAP: resolves org handles to CIDR blocks",
		baseURL:     "https://rdap.arin.net/registry/entity",
		metaKey:     "arin_handles",
		registry:    "arin",
		mode:        plugins.ModePassive,
	}
}
