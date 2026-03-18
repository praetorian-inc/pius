//go:build compute

package lib

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/praetorian-inc/pius/pkg/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withMockRunner(fn func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error)) func() {
	original := RunFunc
	RunFunc = fn
	return func() { RunFunc = original }
}

func TestInvoke_EmitsDomains(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		assert.Equal(t, "Acme Corp", cfg.Org)
		return []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "acme.com", Source: "crt-sh"},
			{Type: plugins.FindingDomain, Value: "api.acme.com", Source: "crt-sh"},
		}, nil
	})
	defer restore()

	d := &Discovery{}
	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	err := d.Invoke(
		capability.ExecutionContext{
			Parameters: capability.Parameters{
				{Name: "mode", Value: "passive"},
				{Name: "concurrency", Value: "5"},
			},
		},
		capmodel.Preseed{Type: "whois+company", Title: "Acme Corp", Value: "Acme Corp"},
		emitter,
	)
	require.NoError(t, err)
	require.Len(t, emitted, 2)

	asset1 := emitted[0].(capmodel.Asset)
	assert.Equal(t, "acme.com", asset1.DNS)
	assert.Equal(t, "acme.com", asset1.Name)

	asset2 := emitted[1].(capmodel.Asset)
	assert.Equal(t, "api.acme.com", asset2.DNS)
}

func TestInvoke_EmitsCIDRs(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingCIDR, Value: "203.0.113.0/24", Source: "arin"},
		}, nil
	})
	defer restore()

	d := &Discovery{}
	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Preseed{Type: "whois+company", Title: "Acme Corp", Value: "Acme Corp"},
		emitter,
	)
	require.NoError(t, err)
	require.Len(t, emitted, 1)

	asset := emitted[0].(capmodel.Asset)
	assert.Equal(t, "203.0.113.0/24", asset.DNS)
}

func TestInvoke_MixedFindings(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "acme.com", Source: "crt-sh"},
			{Type: plugins.FindingCIDR, Value: "10.0.0.0/24", Source: "arin"},
			{Type: plugins.FindingCIDRHandle, Value: "ACME-1", Source: "whois"}, // internal, should be skipped
		}, nil
	})
	defer restore()

	d := &Discovery{}
	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Preseed{Type: "whois+company", Title: "Acme Corp", Value: "Acme Corp"},
		emitter,
	)
	require.NoError(t, err)
	assert.Len(t, emitted, 2) // cidr-handle should be filtered
}

func TestInvoke_NoFindings(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return nil, nil
	})
	defer restore()

	d := &Discovery{}
	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Preseed{Type: "whois+company", Title: "Acme Corp", Value: "Acme Corp"},
		emitter,
	)
	require.NoError(t, err)
	assert.Empty(t, emitted)
}

func TestInvoke_PipelineError(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return nil, errors.New("network timeout")
	})
	defer restore()

	d := &Discovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Preseed{Type: "whois+company", Title: "Acme Corp", Value: "Acme Corp"},
		emitter,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network timeout")
}

func TestInvoke_EmitterError(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "acme.com", Source: "crt-sh"},
		}, nil
	})
	defer restore()

	d := &Discovery{}
	emitter := capability.EmitterFunc(func(models ...any) error {
		return errors.New("emitter failed")
	})

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Preseed{Type: "whois+company", Title: "Acme Corp", Value: "Acme Corp"},
		emitter,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "emitter failed")
}

func TestInvoke_ParameterPassthrough(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		assert.Equal(t, "active", cfg.Mode)
		assert.Equal(t, 10, cfg.Concurrency)
		assert.Equal(t, []string{"crt-sh", "arin"}, cfg.Plugins)
		assert.Equal(t, []string{"edgar"}, cfg.Disable)
		return nil, nil
	})
	defer restore()

	d := &Discovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })

	err := d.Invoke(
		capability.ExecutionContext{
			Parameters: capability.Parameters{
				{Name: "mode", Value: "active"},
				{Name: "concurrency", Value: "10"},
				{Name: "plugins", Value: "crt-sh,arin"},
				{Name: "disable", Value: "edgar"},
			},
		},
		capmodel.Preseed{Type: "whois+company", Title: "Acme Corp", Value: "Acme Corp"},
		emitter,
	)
	require.NoError(t, err)
}

// --- Credential bridging tests ---

func TestPiusCredentialMapping_CoversAllPlugins(t *testing.T) {
	expectedParams := []string{
		"shodan_api_key", "dnsdb_api_key", "crunchbase_api_key",
		"opencorporates_api_key", "proxycurl_api_key", "diffbot_api_key",
		"securitytrails_api_key", "virustotal_api_key", "binaryedge_api_key",
		"apollo_api_key", "censys_api_key", "viewdns_api_key",
	}

	assert.Len(t, piusCredentialMapping, len(expectedParams))

	for _, param := range expectedParams {
		_, ok := piusCredentialMapping[param]
		assert.True(t, ok, "piusCredentialMapping missing key %q", param)
	}
}

func TestPiusCredentialMapping_AllValuesNonEmpty(t *testing.T) {
	for param, envVar := range piusCredentialMapping {
		assert.NotEmpty(t, envVar, "piusCredentialMapping[%q] has empty env var name", param)
	}
}

func TestBridgeCredentials_SetsAndCleansEnvVars(t *testing.T) {
	params := capability.Parameters{
		{Name: "shodan_api_key", Value: "test-shodan-key"},
		{Name: "apollo_api_key", Value: "test-apollo-key"},
	}

	cleanup := bridgeCredentials(params)

	// Verify env vars are set
	assert.Equal(t, "test-shodan-key", os.Getenv("SHODAN_API_KEY"))
	assert.Equal(t, "test-apollo-key", os.Getenv("APOLLO_API_KEY"))
	// Verify unset keys are not set
	assert.Empty(t, os.Getenv("DNSDB_API_KEY"))

	cleanup()

	// Verify env vars are cleaned up
	assert.Empty(t, os.Getenv("SHODAN_API_KEY"))
	assert.Empty(t, os.Getenv("APOLLO_API_KEY"))
}

func TestBridgeCredentials_EmptyParams_NoOp(t *testing.T) {
	params := capability.Parameters{}

	cleanup := bridgeCredentials(params)
	defer cleanup()

	for _, envName := range piusCredentialMapping {
		assert.Empty(t, os.Getenv(envName), "%s should not be set", envName)
	}
}

func TestInvoke_BridgesCredentialsDuringExecution(t *testing.T) {
	var capturedShodanKey string
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		capturedShodanKey = os.Getenv("SHODAN_API_KEY")
		return nil, nil
	})
	defer restore()

	d := &Discovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })

	err := d.Invoke(
		capability.ExecutionContext{
			Parameters: capability.Parameters{
				{Name: "mode", Value: "passive"},
				{Name: "shodan_api_key", Value: "test-key-123"},
			},
		},
		capmodel.Preseed{Type: "whois+company", Title: "Acme Corp", Value: "Acme Corp"},
		emitter,
	)
	require.NoError(t, err)

	// Verify env var was set during RunFunc
	assert.Equal(t, "test-key-123", capturedShodanKey)

	// Verify env var is cleaned up after Invoke returns
	assert.Empty(t, os.Getenv("SHODAN_API_KEY"))
}
