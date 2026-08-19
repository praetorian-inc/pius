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

		return NewAPNICPlugin(c)
	})
}

// NewAPNICPlugin builds the APNIC RPSL plugin. Supplied database paths are
// parsed directly and take precedence over c; without paths, c downloads and
// caches APNIC's published database. Passing neither source disables the plugin.
func NewAPNICPlugin(c *cache.Cache, databases ...string) plugins.Plugin {
	return newRPSLPlugin(rpslConfig{
		name:                    "apnic",
		description:             "APNIC RPSL: resolves org handles to CIDR blocks",
		cacheURL:                cache.APNICInetURL,
		metaKey:                 "apnic_handles",
		registry:                "apnic",
		networkReferenceBaseURL: "https://rdap.apnic.net/ip/",
		mode:                    plugins.ModePassive,
	}, c, databases...)
}
