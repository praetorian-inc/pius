package cidrs

import "github.com/praetorian-inc/pius/pkg/plugins"

func init() {
	plugins.Register("arin", func() plugins.Plugin {
		return newRDAPPlugin(rdapConfig{
			name:        "arin",
			description: "ARIN RDAP: resolves org handles to CIDR blocks",
			baseURL:     "https://rdap.arin.net/registry/entity",
			metaKey:     "arin_handles",
			registry:    "arin",
		})
	})
}
