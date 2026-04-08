//go:build compute

package lib

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/praetorian-inc/pius/pkg/runner"
)

func (d *DomainDiscovery) Invoke(ctx capability.ExecutionContext, input capmodel.Domain, output capability.Emitter) error {
	mode, _ := ctx.Parameters.GetString("mode")
	pluginsParam, _ := ctx.Parameters.GetString("plugins")
	disableParam, _ := ctx.Parameters.GetString("disable")
	concurrency, _ := ctx.Parameters.GetInt("concurrency")

	// Bridge API key parameters to env vars for plugin consumption.
	cleanup := bridgeCredentials(ctx.Parameters)
	defer cleanup()

	cfg := runner.Config{
		Domain:      input.Domain,
		Mode:        mode,
		Concurrency: concurrency,
		Meta:        bridgeMeta(ctx.Parameters),
	}

	if pluginsParam != "" {
		cfg.Plugins = strings.Split(pluginsParam, ",")
	}
	// When no plugins param is set, cfg.Plugins stays empty and the runner
	// uses ALL registered plugins. Each plugin's Accepts() method filters
	// based on whether it can handle a domain-only input.
	if disableParam != "" {
		cfg.Disable = strings.Split(disableParam, ",")
	}

	runCtx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	findings, err := RunFunc(runCtx, cfg)
	if err != nil {
		return fmt.Errorf("%s pipeline for domain %q: %w", CapabilityName, input.Domain, err)
	}

	for _, f := range findings {
		if err := emitFinding(output, f); err != nil {
			return err
		}
	}

	return nil
}
