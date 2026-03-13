package cache

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── isStale (Cache) ───────────────────────────────────────────────────────────

func TestCache_IsStale_WhenFileMissing(t *testing.T) {
	c := &Cache{dir: t.TempDir(), ttl: DefaultTTL}
	assert.True(t, c.isStale("/nonexistent/path/file.rpsl"))
}

func TestCache_IsStale_WhenFileOld(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.rpsl")
	require.NoError(t, err)
	f.Close()

	// Backdate mtime by 2×TTL
	old := time.Now().Add(-2 * DefaultTTL)
	require.NoError(t, os.Chtimes(f.Name(), old, old))

	c := &Cache{dir: t.TempDir(), ttl: DefaultTTL}
	assert.True(t, c.isStale(f.Name()), "file older than TTL should be stale")
}

func TestCache_IsStale_WhenFileFresh(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.rpsl")
	require.NoError(t, err)
	f.Close()
	// File was just created — mtime is now, well within TTL

	c := &Cache{dir: t.TempDir(), ttl: DefaultTTL}
	assert.False(t, c.isStale(f.Name()), "newly created file should not be stale")
}

// ── APICache internal ─────────────────────────────────────────────────────────

func TestAPICache_CorruptCacheTreatedAsMiss(t *testing.T) {
	dir := t.TempDir()
	c := &APICache{dir: dir, ttl: DefaultTTL, prefix: "test"}

	// Write a valid entry, then corrupt the underlying file
	c.Set("key", "value")
	filePath := c.path("key")
	require.NoError(t, os.WriteFile(filePath, []byte("not valid json {{{{"), 0644))

	var v string
	assert.False(t, c.Get("key", &v), "corrupt cache file should be treated as miss")
}

func TestAPICache_PathDeterministic(t *testing.T) {
	c := &APICache{dir: "/tmp", ttl: DefaultTTL, prefix: "apollo"}
	// Same key always produces same path
	p1 := c.path("praetorian|praetorian.com")
	p2 := c.path("praetorian|praetorian.com")
	assert.Equal(t, p1, p2)
	// Different keys produce different paths
	p3 := c.path("acme|acme.com")
	assert.NotEqual(t, p1, p3)
}
