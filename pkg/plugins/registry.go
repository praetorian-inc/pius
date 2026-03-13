package plugins

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
)

// PluginFactory creates a new Plugin instance.
// Using a factory (rather than storing Plugin instances) ensures each caller
// gets a fresh, independent instance safe for concurrent use.
type PluginFactory func() Plugin

var (
	mu       sync.RWMutex
	registry = make(map[string]PluginFactory)
)

// Register registers a plugin factory under the given name.
// Panics if the name is already registered (catches init() conflicts at startup).
// Called from plugin init() functions.
func Register(name string, factory PluginFactory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("pius: plugin %q already registered", name))
	}
	registry[name] = factory
}

// Get returns a new instance of the named plugin, or false if not found.
func Get(name string) (Plugin, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := registry[name]
	if !ok {
		return nil, false
	}
	return f(), true
}

// All returns a new instance of every registered plugin.
func All() []Plugin {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Plugin, 0, len(registry))
	for _, f := range registry {
		result = append(result, f())
	}
	return result
}

// List returns the names of all registered plugins, sorted alphabetically.
func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Filter returns new plugin instances for the given names.
// Names not found in the registry are logged as warnings.
func Filter(names []string) []Plugin {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Plugin, 0, len(names))
	for _, name := range names {
		if f, ok := registry[name]; ok {
			result = append(result, f())
		} else {
			slog.Warn("unknown plugin name, skipping", "plugin", name)
		}
	}
	return result
}

// Reset clears the registry. For testing only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	registry = make(map[string]PluginFactory)
}
