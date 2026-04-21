//go:build compute

package lib

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainInvoke_SetsDomainField(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		assert.Equal(t, "example.com", cfg.Domain, "domain variant must set cfg.Domain")
		assert.Empty(t, cfg.Org, "domain variant must NOT set cfg.Org")
		return nil, nil
	})
	defer restore()

	d := &DomainDiscovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Domain{Domain: "example.com"},
		emitter,
	)
	require.NoError(t, err)
}

func TestDomainInvoke_DefaultsToAllPlugins(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		// When no plugins param is set, cfg.Plugins is empty so the runner uses ALL registered plugins
		assert.Empty(t, cfg.Plugins, "empty plugins param must leave cfg.Plugins empty (runner uses all)")
		return nil, nil
	})
	defer restore()

	d := &DomainDiscovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Domain{Domain: "example.com"},
		emitter,
	)
	require.NoError(t, err)
}

func TestDomainInvoke_ExplicitPluginsOverrideDefault(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		assert.Equal(t, []string{"crt-sh"}, cfg.Plugins, "explicit plugins param must be passed through")
		return nil, nil
	})
	defer restore()

	d := &DomainDiscovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })

	err := d.Invoke(
		capability.ExecutionContext{
			Parameters: capability.Parameters{
				{Name: "plugins", Value: "crt-sh"},
			},
		},
		capmodel.Domain{Domain: "example.com"},
		emitter,
	)
	require.NoError(t, err)
}

func TestDomainInvoke_EmitsDomains(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "sub.example.com", Source: "crt-sh"},
		}, nil
	})
	defer restore()

	d := &DomainDiscovery{}
	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Domain{Domain: "example.com"},
		emitter,
	)
	require.NoError(t, err)
	require.Len(t, emitted, 1)

	asset := emitted[0].(capmodel.Asset)
	assert.Equal(t, "sub.example.com", asset.DNS)
	assert.Equal(t, "sub.example.com", asset.Name)
}

func TestDomainInvoke_EmitsCIDRs(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingCIDR, Value: "198.51.100.0/24", Source: "arin"},
		}, nil
	})
	defer restore()

	d := &DomainDiscovery{}
	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Domain{Domain: "example.com"},
		emitter,
	)
	require.NoError(t, err)
	require.Len(t, emitted, 1)

	asset := emitted[0].(capmodel.Asset)
	assert.Equal(t, "198.51.100.0/24", asset.DNS)
	assert.Equal(t, "198.51.100.0/24", asset.Name)
	assert.Equal(t, []string{"pius_arin"}, asset.Capability)
}

func TestDomainInvoke_FiltersCIDRHandles(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "sub.example.com", Source: "crt-sh"},
			{Type: plugins.FindingCIDRHandle, Value: "ACME-1", Source: "whois"},
			{Type: plugins.FindingCIDR, Value: "10.0.0.0/8", Source: "arin"},
		}, nil
	})
	defer restore()

	d := &DomainDiscovery{}
	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Domain{Domain: "example.com"},
		emitter,
	)
	require.NoError(t, err)
	require.Len(t, emitted, 2, "cidr-handle must be filtered out")

	// Both domain and CIDR are emitted as capmodel.Asset
	domainAsset := emitted[0].(capmodel.Asset)
	assert.Equal(t, "sub.example.com", domainAsset.DNS)

	cidrAsset := emitted[1].(capmodel.Asset)
	assert.Equal(t, "10.0.0.0/8", cidrAsset.DNS)
	assert.Equal(t, "10.0.0.0/8", cidrAsset.Name)
	assert.Equal(t, []string{"pius_arin"}, cidrAsset.Capability)
}

func TestDomainInvoke_PipelineError(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return nil, errors.New("dns resolution failed")
	})
	defer restore()

	d := &DomainDiscovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Domain{Domain: "example.com"},
		emitter,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dns resolution failed")
	assert.Contains(t, err.Error(), "example.com")
}

func TestDomainInvoke_ParameterPassthrough(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		assert.Equal(t, "active", cfg.Mode)
		assert.Equal(t, 3, cfg.Concurrency)
		assert.Equal(t, []string{"dns-brute", "dns-zone-transfer"}, cfg.Plugins)
		assert.Equal(t, []string{"crt-sh"}, cfg.Disable)
		return nil, nil
	})
	defer restore()

	d := &DomainDiscovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })

	err := d.Invoke(
		capability.ExecutionContext{
			Parameters: capability.Parameters{
				{Name: "mode", Value: "active"},
				{Name: "concurrency", Value: "3"},
				{Name: "plugins", Value: "dns-brute,dns-zone-transfer"},
				{Name: "disable", Value: "crt-sh"},
			},
		},
		capmodel.Domain{Domain: "example.com"},
		emitter,
	)
	require.NoError(t, err)
}

func TestDomainInvoke_EmitterError(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "sub.example.com", Source: "crt-sh"},
		}, nil
	})
	defer restore()

	d := &DomainDiscovery{}
	emitter := capability.EmitterFunc(func(models ...any) error {
		return errors.New("emitter failed")
	})

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Domain{Domain: "example.com"},
		emitter,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "emitter failed")
}
