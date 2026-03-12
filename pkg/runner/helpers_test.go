package runner

import (
	"context"
	"errors"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// mockPlugin is a configurable test double for plugins.Plugin.
type mockPlugin struct {
	name     string
	phase    int
	mode     string
	accepts  bool
	findings []plugins.Finding
	err      error
}

func (m *mockPlugin) Name() string        { return m.name }
func (m *mockPlugin) Description() string { return "mock" }
func (m *mockPlugin) Category() string    { return "test" }
func (m *mockPlugin) Phase() int          { return m.phase }
func (m *mockPlugin) Mode() string {
	if m.mode == "" {
		return plugins.ModePassive
	}
	return m.mode
}
func (m *mockPlugin) Accepts(plugins.Input) bool {
	return m.accepts
}
func (m *mockPlugin) Run(_ context.Context, _ plugins.Input) ([]plugins.Finding, error) {
	return m.findings, m.err
}

// capturingPlugin records the Input it receives for later inspection.
type capturingPlugin struct {
	name          string
	phase         int
	capturedInput plugins.Input
	findings      []plugins.Finding
}

func (m *capturingPlugin) Name() string        { return m.name }
func (m *capturingPlugin) Description() string { return "capturing mock" }
func (m *capturingPlugin) Category() string    { return "test" }
func (m *capturingPlugin) Phase() int          { return m.phase }
func (m *capturingPlugin) Mode() string        { return plugins.ModePassive }
func (m *capturingPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta["arin_handles"] != ""
}
func (m *capturingPlugin) Run(_ context.Context, input plugins.Input) ([]plugins.Finding, error) {
	m.capturedInput = input
	return m.findings, nil
}

// errorPlugin always returns an error.
var _ plugins.Plugin = (*errorPlugin)(nil)

type errorPlugin struct{ name string }

func (e *errorPlugin) Name() string        { return e.name }
func (e *errorPlugin) Description() string { return "error mock" }
func (e *errorPlugin) Category() string    { return "test" }
func (e *errorPlugin) Phase() int          { return 0 }
func (e *errorPlugin) Mode() string        { return plugins.ModePassive }
func (e *errorPlugin) Accepts(plugins.Input) bool { return true }
func (e *errorPlugin) Run(_ context.Context, _ plugins.Input) ([]plugins.Finding, error) {
	return nil, errors.New("intentional test error")
}

// phase3CapturingPlugin records the Input it receives for Phase 3 inspection.
type phase3CapturingPlugin struct {
	name          string
	phase         int
	capturedInput plugins.Input
	findings      []plugins.Finding
}

func (m *phase3CapturingPlugin) Name() string        { return m.name }
func (m *phase3CapturingPlugin) Description() string { return "phase3 capturing mock" }
func (m *phase3CapturingPlugin) Category() string    { return "domain" }
func (m *phase3CapturingPlugin) Phase() int          { return m.phase }
func (m *phase3CapturingPlugin) Mode() string        { return plugins.ModeActive }
func (m *phase3CapturingPlugin) Accepts(input plugins.Input) bool {
	return input.Meta != nil && input.Meta["discovered_domains"] != ""
}
func (m *phase3CapturingPlugin) Run(_ context.Context, input plugins.Input) ([]plugins.Finding, error) {
	m.capturedInput = input
	return m.findings, nil
}
