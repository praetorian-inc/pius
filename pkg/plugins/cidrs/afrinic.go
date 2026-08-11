package cidrs

import (
	"log/slog"
	"net/http"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

func init() {
	plugins.Register("afrinic", func() plugins.Plugin {
		c, err := cache.New()
		if err != nil {
			slog.Warn("cache init failed, plugin will be disabled", "plugin", "afrinic", "error", err)
		}
		return newRPSLPlugin(afrinicConfig(), c)
	})
}

// NewAFRINICPlugin builds the AFRINIC RPSL plugin over an injected HTTP client,
// so callers outside this repo can supply their own transport. A nil client is
// valid and falls back to the cache's shared package-level client — see
// cache.NewWithHTTPClient for the rule. A cache that cannot be created is
// returned as an error rather than swallowed into a plugin that self-disables.
func NewAFRINICPlugin(hc *http.Client) (*RPSLPlugin, error) {
	c, err := cache.NewWithHTTPClient(hc)
	if err != nil {
		return nil, err
	}
	return newRPSLPlugin(afrinicConfig(), c), nil
}

// afrinicConfig is the single source of truth for the AFRINIC registry's RPSL
// configuration. Both init() and NewAFRINICPlugin read it, so the registered
// plugin and the injected one cannot drift apart.
//
// AFRINIC ships one combined dump that already contains its inet6num records,
// so there is no second file to fetch and cacheURL6 stays empty.
func afrinicConfig() rpslConfig {
	return rpslConfig{
		name:        "afrinic",
		description: "AFRINIC RPSL: resolves org handles to CIDR blocks",
		cacheURL:    cache.AFRINICAllURL,
		metaKey:     "afrinic_handles",
		registry:    "afrinic",
		mode:        plugins.ModePassive,
	}
}
