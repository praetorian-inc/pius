package cidrs

import (
	"log"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("afrinic", func() plugins.Plugin {
		c, err := cache.New()
		if err != nil {
			log.Printf("[afrinic] cache init failed: %v (plugin will be disabled)", err)
		}
		return newRPSLPlugin(rpslConfig{
			name:        "afrinic",
			description: "AFRINIC RPSL: resolves org handles to CIDR blocks",
			cacheURL:    cache.AFRINICAllURL,
			metaKey:     "afrinic_handles",
			registry:    "afrinic",
		}, c)
	})
}
