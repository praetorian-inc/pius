package cidrs

import "github.com/praetorian-inc/pius/pkg/plugins"

func init() {
	plugins.Register("lacnic", func() plugins.Plugin {
		return newRDAPPlugin(RDAPConfigs["lacnic"])
	})
}
