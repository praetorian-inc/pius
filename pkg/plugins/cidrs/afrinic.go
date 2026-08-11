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
		return newRPSLPlugin(rpslConfigs["afrinic"], c)
	})
}
