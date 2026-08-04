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
	assert.Equal(t, []string{"pius_crt-sh"}, asset1.Capability)

	asset2 := emitted[1].(capmodel.Asset)
	assert.Equal(t, "api.acme.com", asset2.DNS)
	assert.Equal(t, []string{"pius_crt-sh"}, asset2.Capability)
}

func TestInvoke_EmitsCIDRs(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingCIDR, Value: "203.0.113.0/24", Source: "arin", Data: map[string]any{"org": "Acme Corp"}},
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
	assert.Equal(t, "203.0.113.0/24", asset.Name)
	assert.Equal(t, []string{"pius_arin"}, asset.Capability)
}

func TestInvoke_EmptySource_OmitsOrigins(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "acme.com", Source: ""},
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
	assert.Equal(t, "acme.com", asset.DNS)
	assert.Nil(t, asset.Capability)
}

func TestInvoke_WildcardDomainsDropped(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "*.acme.com", Source: "crt-sh"},
			{Type: plugins.FindingDomain, Value: "*.dev.acme.com", Source: "crt-sh"},
			{Type: plugins.FindingDomain, Value: "*", Source: "crt-sh"},
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
		capability.ExecutionContext{},
		capmodel.Preseed{Type: "whois+company", Title: "Acme Corp", Value: "Acme Corp"},
		emitter,
	)
	require.NoError(t, err)
	require.Len(t, emitted, 1)

	asset := emitted[0].(capmodel.Asset)
	assert.Equal(t, "api.acme.com", asset.DNS)
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
	require.Len(t, emitted, 2) // cidr-handle should be filtered

	// Both domain and CIDR are emitted as capmodel.Asset
	domainAsset := emitted[0].(capmodel.Asset)
	assert.Equal(t, "acme.com", domainAsset.DNS)
	assert.Equal(t, []string{"pius_crt-sh"}, domainAsset.Capability)

	cidrAsset := emitted[1].(capmodel.Asset)
	assert.Equal(t, "10.0.0.0/24", cidrAsset.DNS)
	assert.Equal(t, "10.0.0.0/24", cidrAsset.Name)
	assert.Equal(t, []string{"pius_arin"}, cidrAsset.Capability)
}

func TestInvoke_CIDREmptySource_OmitsCapability(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingCIDR, Value: "198.51.100.0/16", Source: ""},
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
	assert.Equal(t, "198.51.100.0/16", asset.DNS)
	assert.Equal(t, "198.51.100.0/16", asset.Name)
	assert.Nil(t, asset.Capability)
}

func TestInvoke_MultipleCIDRsFromDifferentSources(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingCIDR, Value: "203.0.113.0/24", Source: "arin"},
			{Type: plugins.FindingCIDR, Value: "192.0.2.0/24", Source: "shodan"},
			{Type: plugins.FindingCIDR, Value: "2001:db8::/32", Source: "rdap"},
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
	require.Len(t, emitted, 3)

	for i, expected := range []struct {
		dns        string
		capability string
	}{
		{"203.0.113.0/24", "pius_arin"},
		{"192.0.2.0/24", "pius_shodan"},
		{"2001:db8::/32", "pius_rdap"},
	} {
		asset := emitted[i].(capmodel.Asset)
		assert.Equal(t, expected.dns, asset.DNS, "emission %d DNS", i)
		assert.Equal(t, expected.dns, asset.Name, "emission %d Name", i)
		assert.Equal(t, []string{expected.capability}, asset.Capability, "emission %d Capability", i)
	}
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
		"apollo_api_key", "censys_api_key", "censys_api_token", "censys_org_id", "viewdns_api_key",
		"github_token",
		"whoxy_api_key", "builtwith_api_key",
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

// --- Confidence transport tests ---

func TestConfidenceFields_Scored(t *testing.T) {
	var f plugins.Finding
	plugins.AddConfidence(&f, 0.60, "blog URL matches the known domain")
	plugins.AddConfidence(&f, 0.02, "organization name partially matches")

	confidences, total, needsReview := confidenceFields(f)

	require.Len(t, confidences, 2)
	assert.Equal(t, capmodel.Confidence{Score: 0.60, Justification: "blog URL matches the known domain"}, confidences[0])
	assert.Equal(t, capmodel.Confidence{Score: 0.02, Justification: "organization name partially matches"}, confidences[1])

	require.NotNil(t, total)
	require.NotNil(t, needsReview)
	assert.InDelta(t, 0.62, *total, 0.001)
	assert.True(t, *needsReview, "0.62 falls short of ConfidenceHigh")
}

func TestConfidenceFields_HighConfidence(t *testing.T) {
	var f plugins.Finding
	plugins.AddConfidence(&f, 0.90, "registered direct parent")

	_, total, needsReview := confidenceFields(f)

	require.NotNil(t, total)
	require.NotNil(t, needsReview)
	assert.InDelta(t, 0.90, *total, 0.001)
	assert.False(t, *needsReview)
}

func TestConfidenceFields_CapsAggregate(t *testing.T) {
	var f plugins.Finding
	plugins.AddConfidence(&f, 0.60, "first")
	plugins.AddConfidence(&f, 0.60, "second")

	confidences, total, _ := confidenceFields(f)

	assert.Len(t, confidences, 2, "both entries survive uncapped")
	require.NotNil(t, total)
	assert.InDelta(t, 1.0, *total, 0.001, "only the aggregate is capped")
}

// TestConfidenceFields_Unscored is the fallback contract: no evidence means no
// claim, so Guard sees nil and may apply its own historical default.
func TestConfidenceFields_Unscored(t *testing.T) {
	f := plugins.Finding{Data: map[string]any{"org": "Acme"}}

	confidences, total, needsReview := confidenceFields(f)

	assert.Nil(t, confidences)
	assert.Nil(t, total)
	assert.Nil(t, needsReview)
}

// TestConfidenceFields_ExplicitZero is the other half of that contract: a
// producer that scored the finding and got zero DID make a claim, so the 0.0 is
// materialized and blocks the fallback.
func TestConfidenceFields_ExplicitZero(t *testing.T) {
	var f plugins.Finding
	plugins.AddConfidence(&f, 0.0, "nothing substantiated this candidate")

	confidences, total, needsReview := confidenceFields(f)

	require.Len(t, confidences, 1)
	require.NotNil(t, total)
	require.NotNil(t, needsReview)
	assert.InDelta(t, 0.0, *total, 0.001)
	assert.True(t, *needsReview)
}

func TestConfidenceFields_NilFinding(t *testing.T) {
	confidences, total, needsReview := confidenceFields(plugins.Finding{})
	assert.Nil(t, confidences)
	assert.Nil(t, total)
	assert.Nil(t, needsReview)
}

func TestInvoke_DomainWithConfidence(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		f := plugins.Finding{Type: plugins.FindingDomain, Value: "acme.com", Source: "github-org"}
		plugins.AddConfidence(&f, 0.30, "GitHub organization blog URL matches the known domain")
		plugins.AddConfidence(&f, 0.25, "GitHub organization name matches the target organization")
		return []plugins.Finding{f}, nil
	})
	defer restore()

	emitted := invokeAndCollect(t)
	require.Len(t, emitted, 1)

	asset := emitted[0].(capmodel.Asset)
	require.Len(t, asset.Confidences, 2, "every entry survives transport")
	assert.Equal(t, "GitHub organization blog URL matches the known domain", asset.Confidences[0].Justification)
	assert.Equal(t, "GitHub organization name matches the target organization", asset.Confidences[1].Justification)
	assert.InDelta(t, 0.30, asset.Confidences[0].Score, 0.001)

	require.NotNil(t, asset.Confidence)
	require.NotNil(t, asset.NeedsReview)
	assert.InDelta(t, 0.55, *asset.Confidence, 0.001)
	assert.True(t, *asset.NeedsReview)
}

func TestInvoke_DomainWithoutConfidence(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return []plugins.Finding{
			{Type: plugins.FindingDomain, Value: "acme.com", Source: "crt-sh"},
		}, nil
	})
	defer restore()

	emitted := invokeAndCollect(t)
	require.Len(t, emitted, 1)

	asset := emitted[0].(capmodel.Asset)
	assert.Nil(t, asset.Confidences)
	assert.Nil(t, asset.Confidence)
	assert.Nil(t, asset.NeedsReview)
}

// TestInvoke_DomainWithExplicitZeroConfidence proves the explicit-zero case
// survives the whole emitter, not just confidenceFields.
func TestInvoke_DomainWithExplicitZeroConfidence(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		f := plugins.Finding{Type: plugins.FindingDomain, Value: "acme.com", Source: "github-org"}
		plugins.AddConfidence(&f, 0.0, "no signal supported this candidate")
		return []plugins.Finding{f}, nil
	})
	defer restore()

	emitted := invokeAndCollect(t)
	require.Len(t, emitted, 1)

	asset := emitted[0].(capmodel.Asset)
	require.Len(t, asset.Confidences, 1)
	require.NotNil(t, asset.Confidence)
	assert.InDelta(t, 0.0, *asset.Confidence, 0.001, "an explicit zero is materialized, not dropped")
	require.NotNil(t, asset.NeedsReview)
	assert.True(t, *asset.NeedsReview)
}

func TestInvoke_CIDRWithConfidence(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		f := plugins.Finding{
			Type: plugins.FindingCIDR, Value: "203.0.113.0/24", Source: "arin",
			Data: map[string]any{"org": "Acme Corp"},
		}
		plugins.AddConfidence(&f, 0.25, "netblock is registered to the queried organization")
		plugins.AddConfidence(&f, 0.15, "registrant country matches the target")
		return []plugins.Finding{f}, nil
	})
	defer restore()

	emitted := invokeAndCollect(t)
	require.Len(t, emitted, 1)

	asset := emitted[0].(capmodel.Asset)
	require.Len(t, asset.Confidences, 2)
	assert.Equal(t, "netblock is registered to the queried organization", asset.Confidences[0].Justification)
	require.NotNil(t, asset.Confidence)
	require.NotNil(t, asset.NeedsReview)
	assert.InDelta(t, 0.40, *asset.Confidence, 0.001)
	assert.True(t, *asset.NeedsReview)
}

func TestInvoke_PreseedWithConfidence(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		f := plugins.Finding{
			Type: plugins.FindingPreseed, Value: "sub.acme.com", Source: "gleif",
			Data: map[string]any{"preseed_type": "whois", "preseed_title": "subsidiary"},
		}
		plugins.AddConfidence(&f, 0.65, "GLEIF records this entity as a registered direct subsidiary")
		return []plugins.Finding{f}, nil
	})
	defer restore()

	emitted := invokeAndCollect(t)
	require.Len(t, emitted, 1)

	preseed := emitted[0].(capmodel.Preseed)
	require.Len(t, preseed.Confidences, 1)
	assert.Equal(t, "GLEIF records this entity as a registered direct subsidiary", preseed.Confidences[0].Justification)
	require.NotNil(t, preseed.Confidence)
	require.NotNil(t, preseed.NeedsReview)
	assert.InDelta(t, 0.65, *preseed.Confidence, 0.001)
	assert.False(t, *preseed.NeedsReview)
}

// invokeAndCollect runs Discovery.Invoke against the currently-installed mock
// runner and returns everything it emitted.
func invokeAndCollect(t *testing.T) []any {
	t.Helper()

	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	err := (&Discovery{}).Invoke(capability.ExecutionContext{}, capmodel.Preseed{Value: "Acme Corp"}, emitter)
	require.NoError(t, err)
	return emitted
}

// --- Task 6: whois+email preseed routing tests ---

func TestInvoke_EmailPreseed_RoutesToEmail(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		assert.Equal(t, "admin@acme.com", cfg.Email)
		assert.Empty(t, cfg.Org, "email seed must NOT populate Org")
		return nil, nil
	})
	defer restore()
	d := &Discovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })
	err := d.Invoke(capability.ExecutionContext{},
		capmodel.Preseed{Type: "whois+email", Title: "admin@acme.com", Value: "admin@acme.com"},
		emitter)
	require.NoError(t, err)
}

func TestInvoke_CompanyPreseed_StillRoutesToOrg(t *testing.T) {
	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		assert.Equal(t, "Acme Corp", cfg.Org)
		assert.Empty(t, cfg.Email)
		return nil, nil
	})
	defer restore()
	d := &Discovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })
	err := d.Invoke(capability.ExecutionContext{},
		capmodel.Preseed{Type: "whois+company", Value: "Acme Corp"}, emitter)
	require.NoError(t, err)
}

// TestInvoke_EmailPreseed_ErrorOmitsRawEmail proves that when the pipeline
// returns an error for a whois+email preseed, the raw registrant email address
// is NOT embedded in the returned error string (PII leak prevention).
//
// RED: today invoke.go:56 does
//
//	return fmt.Errorf("%s pipeline for %q: %w", CapabilityName, input.Value, err)
//
// which embeds the raw email. The planned fix uses input.Type instead.
func TestInvoke_EmailPreseed_ErrorOmitsRawEmail(t *testing.T) {
	const sensitiveEmail = "admin@secret-corp.com"

	restore := withMockRunner(func(ctx context.Context, cfg runner.Config) ([]plugins.Finding, error) {
		return nil, errors.New("boom")
	})
	defer restore()

	d := &Discovery{}
	emitter := capability.EmitterFunc(func(models ...any) error { return nil })

	err := d.Invoke(
		capability.ExecutionContext{},
		capmodel.Preseed{Type: "whois+email", Value: sensitiveEmail},
		emitter,
	)

	require.Error(t, err, "Invoke must return an error when RunFunc fails")

	// The raw email MUST NOT appear in the error string — this is the PII-leak guard.
	// Against current code this assertion FAILS because line 56 of invoke.go embeds input.Value.
	assert.NotContains(t, err.Error(), sensitiveEmail,
		"error message must not contain the raw registrant email (PII leak); got: %q", err.Error())

	// The error should still contain useful context — the preseed TYPE not the value.
	assert.Contains(t, err.Error(), "whois+email",
		"error message should mention the preseed type for debuggability")
}
