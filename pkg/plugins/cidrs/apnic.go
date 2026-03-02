package cidrs

import (
	"log"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("apnic", func() plugins.Plugin {
		c, err := cache.New()
		if err != nil {
			log.Printf("[apnic] cache init failed: %v (plugin will be disabled)", err)
		}
		return newRPSLPlugin(rpslConfig{
			name:        "apnic",
			description: "APNIC RPSL: resolves org handles to CIDR blocks",
			cacheURL:    cache.APNICInetURL,
			metaKey:     "apnic_handles",
			registry:    "apnic",
		}, c)
	})
}
