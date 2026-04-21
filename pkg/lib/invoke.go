//go:build compute

package lib

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/runner"
)

// RunFunc is the function used to execute the pius pipeline.
// It defaults to runner.Run but can be overridden in tests.
var RunFunc = runner.Run

func (d *Discovery) Invoke(ctx capability.ExecutionContext, input capmodel.Preseed, output capability.Emitter) error {
	mode, _ := ctx.Parameters.GetString("mode")
	pluginsParam, _ := ctx.Parameters.GetString("plugins")
	disableParam, _ := ctx.Parameters.GetString("disable")
	concurrency, _ := ctx.Parameters.GetInt("concurrency")

	// Bridge API key parameters to env vars for plugin consumption.
	cleanup := bridgeCredentials(ctx.Parameters)
	defer cleanup()

	cfg := runner.Config{
		Org:         input.Value,
		Mode:        mode,
		Concurrency: concurrency,
		Meta:        bridgeMeta(ctx.Parameters),
	}
	if pluginsParam != "" {
		cfg.Plugins = strings.Split(pluginsParam, ",")
	}
	if disableParam != "" {
		cfg.Disable = strings.Split(disableParam, ",")
	}

	// capability.ExecutionContext carries no context.Context, so we create one here.
	runCtx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	findings, err := RunFunc(runCtx, cfg)
	if err != nil {
		return fmt.Errorf("%s pipeline for %q: %w", CapabilityName, input.Value, err)
	}

	for _, f := range findings {
		if err := emitFinding(output, f); err != nil {
			return err
		}
	}

	return nil
}

// emitFinding converts a pius Finding to a capmodel type and emits it.
func emitFinding(output capability.Emitter, f plugins.Finding) error {
	var assetCapability []string
	var preseedCapability string
	if f.Source != "" {
		assetCapability = []string{fmt.Sprintf("pius_%s", f.Source)}
		preseedCapability = fmt.Sprintf("pius_%s", f.Source)
	}

	confidence, needsReview := extractConfidence(f)

	switch f.Type {
	case plugins.FindingDomain:
		return output.Emit(capmodel.Asset{
			DNS:         f.Value,
			Name:        f.Value,
			Capability:  assetCapability,
			Confidence:  confidence,
			NeedsReview: needsReview,
		})
	case plugins.FindingCIDR:
		return output.Emit(capmodel.Asset{
			DNS:        f.Value,
			Name:       f.Value,
			Capability: assetCapability,
 			Confidence:  confidence,
			NeedsReview: needsReview,
		})
	case plugins.FindingPreseed:
		preseedType, _ := f.Data["preseed_type"].(string)
		title, _ := f.Data["preseed_title"].(string)
		if preseedType == "" {
			return nil
		}
		return output.Emit(capmodel.Preseed{
			Type:        preseedType,
			Value:       f.Value,
			Title:       title,
			Capability:  preseedCapability,
			Confidence:  confidence,
			NeedsReview: needsReview,
		})
	default:
		// Skip internal finding types (e.g., cidr-handle)
		return nil
	}
}

// extractConfidence returns pointers to the confidence and needs_review values
// from a Finding's Data map, or nils if the finding was not scored.
func extractConfidence(f plugins.Finding) (*float64, *bool) {
	c, ok := f.Data["confidence"].(float64)
	if !ok {
		return nil, nil
	}
	nr, _ := f.Data["needs_review"].(bool)
	return &c, &nr
}

// piusCredentialMapping maps capability parameter names to the environment
// variable names that Pius plugins read via os.Getenv(). This bridging is
// necessary because plugins are not modified — they expect env vars — but
// the SDK transport is programmatic via job.Config → Parameters.
var piusCredentialMapping = map[string]string{
	"shodan_api_key":         "SHODAN_API_KEY",
	"dnsdb_api_key":          "DNSDB_API_KEY",
	"crunchbase_api_key":     "CRUNCHBASE_API_KEY",
	"opencorporates_api_key": "OPENCORPORATES_API_KEY",
	"proxycurl_api_key":      "PROXYCURL_API_KEY",
	"diffbot_api_key":        "DIFFBOT_API_KEY",
	"securitytrails_api_key": "SECURITYTRAILS_API_KEY",
	"virustotal_api_key":     "VIRUSTOTAL_API_KEY",
	"binaryedge_api_key":     "BINARYEDGE_API_KEY",
	"apollo_api_key":         "APOLLO_API_KEY",
	"censys_api_key":         "CENSYS_API_KEY",
	"censys_org_id":          "CENSYS_ORG_ID",
	"viewdns_api_key":        "VIEWDNS_API_KEY",
	"github_token":           "GITHUB_TOKEN",
}

// bridgeCredentials reads API key parameters from the execution context and
// sets them as environment variables so that Pius plugins (which use os.Getenv)
// can access them. Returns a cleanup function that unsets all injected vars.
func bridgeCredentials(params capability.Parameters) func() {
	var injected []string
	for paramName, envName := range piusCredentialMapping {
		if v, ok := params.GetString(paramName); ok && v != "" {
			os.Setenv(envName, v)
			injected = append(injected, envName)
		}
	}
	return func() {
		for _, k := range injected {
			os.Unsetenv(k)
		}
	}
}

// pluginMetaKeys lists capability parameter names that should be forwarded
// to runner.Config.Meta so individual plugins can read them via input.Meta.
var pluginMetaKeys = []string{
	"doh_servers",
	"doh_gateways",
	"doh_deploy_gateways",
	"dns_brute_concurrency",
	"google_dorks_max_subsidiaries",
}

// bridgeMeta reads plugin-specific parameters from the execution context
// and returns them as a map suitable for runner.Config.Meta.
func bridgeMeta(params capability.Parameters) map[string]string {
	meta := make(map[string]string)
	for _, key := range pluginMetaKeys {
		if v, ok := params.GetString(key); ok && v != "" {
			meta[key] = v
		}
	}
	// Also try int params (they come as strings from the SDK).
	for _, key := range pluginMetaKeys {
		if _, exists := meta[key]; exists {
			continue
		}
		if v, ok := params.GetInt(key); ok && v != 0 {
			meta[key] = fmt.Sprintf("%d", v)
		}
	}
	return meta
}
