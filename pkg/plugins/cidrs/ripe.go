package cidrs

import "github.com/praetorian-inc/pius/pkg/plugins"

func init() {
	plugins.Register("ripe", func() plugins.Plugin {
		return newRDAPPlugin(rdapConfigs["ripe"])
	})
}
