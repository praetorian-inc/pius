package cidrs

import "github.com/praetorian-inc/pius/pkg/plugins"

func init() {
	plugins.Register("lacnic", func() plugins.Plugin {
		return newRDAPPlugin(rdapConfig{
			name:        "lacnic",
			description: "LACNIC RDAP: resolves org handles to CIDR blocks (Latin America & Caribbean)",
			baseURL:     "https://rdap.lacnic.net/rdap/entity",
			metaKey:     "lacnic_handles",
			registry:    "lacnic",
			mode:        plugins.ModePassive,
		})
	})
}
