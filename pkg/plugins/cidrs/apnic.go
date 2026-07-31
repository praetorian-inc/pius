package cidrs

import (
	"log/slog"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("apnic", func() plugins.Plugin {
		c, err := cache.New()
		if err != nil {
			slog.Warn("cache init failed, plugin will be disabled", "plugin", "apnic", "error", err)
		}
		return newRPSLPlugin(rpslConfig{
			name:        "apnic",
			description: "APNIC RPSL: resolves org handles to CIDR blocks",
			cacheURL:    cache.APNICInetURL,
			metaKey:     "apnic_handles",
			registry:    "apnic",
			mode:        plugins.ModePassive,
		}, c)
	})
}
