package runner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun_DefaultConfig(t *testing.T) {
	cfg := Config{
		Org: "Nonexistent-Corp-Test-12345",
	}

	// Run with a very short timeout to avoid real network calls
	ctx, cancel := context.WithTimeout(context.Background(), 1)
	defer cancel()

	// Should return empty findings or context error, but not panic
	findings, _ := Run(ctx, cfg)
	// With a 1ns timeout, we expect either nil findings or a timeout error
	_ = findings
}

func TestRun_EmptyOrg(t *testing.T) {
	cfg := Config{}

	ctx, cancel := context.WithTimeout(context.Background(), 1)
	defer cancel()

	findings, _ := Run(ctx, cfg)
	// Empty org should still not panic
	_ = findings
}

func TestRun_ModeDefault(t *testing.T) {
	cfg := Config{
		Org: "Test Corp",
	}

	// Verify defaults are applied without panicking
	ctx, cancel := context.WithTimeout(context.Background(), 1)
	defer cancel()

	_, _ = Run(ctx, cfg)
}

func TestSelectPlugins_AllPassive(t *testing.T) {
	selected := selectPlugins("", "", "passive")
	for _, p := range selected {
		assert.Equal(t, "passive", p.Mode())
	}
}

func TestSelectPlugins_AllActive(t *testing.T) {
	selected := selectPlugins("", "", "active")
	for _, p := range selected {
		assert.Equal(t, "active", p.Mode())
	}
}

func TestSelectPlugins_AllMode(t *testing.T) {
	selected := selectPlugins("", "", "all")
	assert.Greater(t, len(selected), 0)
}
