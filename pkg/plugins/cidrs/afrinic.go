package cidrs

import (
	"log/slog"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("afrinic", func() plugins.Plugin {
		c, err := cache.New()
		if err != nil {
			slog.Warn("cache init failed, plugin will be disabled", "plugin", "afrinic", "error", err)
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
