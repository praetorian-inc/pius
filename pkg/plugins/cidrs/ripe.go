package cidrs

import "github.com/praetorian-inc/pius/pkg/plugins"

func init() {
	plugins.Register("ripe", func() plugins.Plugin {
		return newRDAPPlugin(rdapConfig{
			name:        "ripe",
			description: "RIPE RDAP: resolves org handles to CIDR blocks",
			baseURL:     "https://rdap.db.ripe.net/entity",
			metaKey:     "ripe_handles",
			registry:    "ripe",
			mode:        plugins.ModePassive,
		})
	})
}
