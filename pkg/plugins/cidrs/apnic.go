package cidrs

import (
	"log/slog"
	"net/http"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("apnic", func() plugins.Plugin {
		c, err := cache.New()
		if err != nil {
			slog.Warn("cache init failed, plugin will be disabled", "plugin", "apnic", "error", err)
		}
		return newRPSLPlugin(apnicConfig(), c)
	})
}

// NewAPNICPlugin builds the APNIC RPSL plugin over an injected HTTP client, so
// callers outside this repo can supply their own transport. A nil client is
// valid and falls back to the cache's shared package-level client — see
// cache.NewWithHTTPClient for the rule. A cache that cannot be created is
// returned as an error rather than swallowed into a plugin that self-disables.
func NewAPNICPlugin(hc *http.Client) (*RPSLPlugin, error) {
	c, err := cache.NewWithHTTPClient(hc)
	if err != nil {
		return nil, err
	}
	return newRPSLPlugin(apnicConfig(), c), nil
}

// apnicConfig is the single source of truth for the APNIC registry's RPSL
// configuration. Both init() and NewAPNICPlugin read it, so the registered
// plugin and the injected one cannot drift apart.
//
// APNIC splits its inet6num records into a second download, which cacheURL6
// names.
func apnicConfig() rpslConfig {
	return rpslConfig{
		name:        "apnic",
		description: "APNIC RPSL: resolves org handles to CIDR blocks",
		cacheURL:    cache.APNICInetURL,
		cacheURL6:   cache.APNICInet6URL,
		metaKey:     "apnic_handles",
		registry:    "apnic",
		mode:        plugins.ModePassive,
	}
}
