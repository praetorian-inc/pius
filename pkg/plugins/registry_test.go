package plugins_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPlugin is a test helper for registry tests
type mockPlugin struct {
	name     string
	phase    int
	category string
	accepts  bool
}

func (m *mockPlugin) Name() string                                       { return m.name }
func (m *mockPlugin) Description() string                                { return "mock plugin" }
func (m *mockPlugin) Category() string                                   { return m.category }
func (m *mockPlugin) Phase() int                                         { return m.phase }
func (m *mockPlugin) Mode() string                                       { return plugins.ModePassive }
func (m *mockPlugin) Accepts(input plugins.Input) bool                   { return m.accepts }
func (m *mockPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	return nil, nil
}

func TestRegister_PanicsOnDuplicate(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	factory := func() plugins.Plugin { return &mockPlugin{name: "test"} }
	plugins.Register("test", factory)

	// Attempt to register same name again should panic
	assert.Panics(t, func() {
		plugins.Register("test", factory)
	}, "should panic when registering duplicate plugin name")
}

func TestRegister_AllowsDifferentNames(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	factory1 := func() plugins.Plugin { return &mockPlugin{name: "plugin1"} }
	factory2 := func() plugins.Plugin { return &mockPlugin{name: "plugin2"} }

	// Should not panic for different names
	assert.NotPanics(t, func() {
		plugins.Register("plugin1", factory1)
		plugins.Register("plugin2", factory2)
	})
}

func TestAll_ReturnsNewInstances(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	var callCount int
	plugins.Register("counted", func() plugins.Plugin {
		callCount++
		return &mockPlugin{name: "counted"}
	})

	// First call to All() should invoke factory
	first := plugins.All()
	firstCallCount := callCount

	// Second call to All() should invoke factory again (new instance)
	second := plugins.All()
	secondCallCount := callCount

	assert.Len(t, first, 1, "first call should return 1 plugin")
	assert.Len(t, second, 1, "second call should return 1 plugin")
	assert.Equal(t, 2, secondCallCount, "factory should be called twice (once per All() call)")
	assert.NotEqual(t, firstCallCount, secondCallCount, "each All() call should increment call count")
}

func TestGet_ReturnsNewInstanceEachCall(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	var callCount int
	plugins.Register("test", func() plugins.Plugin {
		callCount++
		return &mockPlugin{name: "test"}
	})

	// Get same plugin twice
	p1, ok1 := plugins.Get("test")
	p2, ok2 := plugins.Get("test")

	assert.True(t, ok1, "first Get should find plugin")
	assert.True(t, ok2, "second Get should find plugin")
	assert.NotNil(t, p1)
	assert.NotNil(t, p2)
	assert.Equal(t, 2, callCount, "factory should be called once per Get()")
}

func TestGet_ReturnsFalseForUnknown(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	plugins.Register("known", func() plugins.Plugin { return &mockPlugin{name: "known"} })

	p, ok := plugins.Get("unknown")

	assert.False(t, ok, "should return false for unknown plugin")
	assert.Nil(t, p, "should return nil plugin for unknown name")
}

func TestFilter_ReturnsMatchingPlugins(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	plugins.Register("arin", func() plugins.Plugin { return &mockPlugin{name: "arin"} })
	plugins.Register("ripe", func() plugins.Plugin { return &mockPlugin{name: "ripe"} })
	plugins.Register("crt-sh", func() plugins.Plugin { return &mockPlugin{name: "crt-sh"} })

	result := plugins.Filter([]string{"arin", "crt-sh"})

	require.Len(t, result, 2, "should return 2 plugins")

	names := make(map[string]bool)
	for _, p := range result {
		names[p.Name()] = true
	}

	assert.True(t, names["arin"], "should include arin")
	assert.True(t, names["crt-sh"], "should include crt-sh")
	assert.False(t, names["ripe"], "should not include ripe")
}

func TestFilter_SkipsUnknownNames(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	plugins.Register("arin", func() plugins.Plugin { return &mockPlugin{name: "arin"} })

	// Request mix of known and unknown plugins
	result := plugins.Filter([]string{"arin", "unknown1", "unknown2"})

	require.Len(t, result, 1, "should only return known plugins")
	assert.Equal(t, "arin", result[0].Name())
}

func TestFilter_EmptyListReturnsEmpty(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	plugins.Register("arin", func() plugins.Plugin { return &mockPlugin{name: "arin"} })

	result := plugins.Filter([]string{})

	assert.Empty(t, result, "empty filter list should return empty result")
}

func TestList_ReturnsSortedNames(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	// Register in non-alphabetical order
	plugins.Register("whois", func() plugins.Plugin { return &mockPlugin{name: "whois"} })
	plugins.Register("arin", func() plugins.Plugin { return &mockPlugin{name: "arin"} })
	plugins.Register("crt-sh", func() plugins.Plugin { return &mockPlugin{name: "crt-sh"} })
	plugins.Register("ripe", func() plugins.Plugin { return &mockPlugin{name: "ripe"} })

	result := plugins.List()

	// Should be sorted alphabetically
	expected := []string{"arin", "crt-sh", "ripe", "whois"}
	assert.Equal(t, expected, result, "plugin names should be sorted alphabetically")
}

func TestList_EmptyRegistryReturnsEmpty(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	result := plugins.List()

	assert.Empty(t, result, "empty registry should return empty list")
}

func TestReset_ClearsRegistry(t *testing.T) {
	plugins.Reset()
	defer plugins.Reset()

	plugins.Register("test1", func() plugins.Plugin { return &mockPlugin{name: "test1"} })
	plugins.Register("test2", func() plugins.Plugin { return &mockPlugin{name: "test2"} })

	// Verify plugins registered
	assert.Len(t, plugins.All(), 2)

	// Reset
	plugins.Reset()

	// Verify empty
	assert.Empty(t, plugins.All(), "registry should be empty after Reset()")
	assert.Empty(t, plugins.List(), "List() should be empty after Reset()")

	_, ok := plugins.Get("test1")
	assert.False(t, ok, "Get() should return false after Reset()")
}
