package cidrs

import (
	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("ripe", func() plugins.Plugin {
		return newRDAPPlugin(ripeConfig())
	})
}

// NewRIPEPlugin builds the RIPE RDAP plugin over an injected HTTP client, so
// callers outside this repo can supply their own transport. A nil client falls
// back to the package default — see doerOrDefault for the rule.
func NewRIPEPlugin(c *client.Client) *RDAPPlugin {
	return newRDAPPluginWithDoer(ripeConfig(), doerOrDefault(c))
}

// ripeConfig is the single source of truth for the RIPE registry's RDAP
// configuration. Both init() and NewRIPEPlugin read it, so the registered
// plugin and the injected one cannot drift apart.
func ripeConfig() rdapConfig {
	return rdapConfig{
		name:        "ripe",
		description: "RIPE RDAP: resolves org handles to CIDR blocks",
		baseURL:     "https://rdap.db.ripe.net/entity",
		metaKey:     "ripe_handles",
		registry:    "ripe",
		mode:        plugins.ModePassive,
	}
}
