package cidrs

import "github.com/praetorian-inc/pius/pkg/plugins"

func init() {
	plugins.Register("arin", func() plugins.Plugin {
		return newRDAPPlugin(rdapConfigs["arin"])
	})
}
