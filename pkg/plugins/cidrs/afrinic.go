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

		return NewAFRINICPlugin(c)
	})
}

// NewAFRINICPlugin builds the AFRINIC RPSL plugin. Supplied database paths are
// parsed directly and take precedence over c; without paths, c downloads and
// caches AFRINIC's published database. Passing neither source disables the plugin.
func NewAFRINICPlugin(c *cache.Cache, databases ...string) plugins.Plugin {
	return newRPSLPlugin(rpslConfig{
		name:                    "afrinic",
		description:             "AFRINIC RPSL: resolves org handles to CIDR blocks",
		cacheURL:                cache.AFRINICAllURL,
		metaKey:                 "afrinic_handles",
		registry:                "afrinic",
		networkReferenceBaseURL: "https://rdap.afrinic.net/rdap/ip/",
		mode:                    plugins.ModePassive,
	}, c, databases...)
}
