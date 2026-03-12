package cache_test

import (
	"testing"
	"time"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPICache_SetAndGet_RoundTrip(t *testing.T) {
	c, err := cache.NewAPI(t.TempDir(), "test")
	require.NoError(t, err)

	type payload struct {
		Name  string   `json:"name"`
		Items []string `json:"items"`
	}
	in := payload{Name: "acme", Items: []string{"a", "b", "c"}}
	c.Set("key1", in)

	var out payload
	assert.True(t, c.Get("key1", &out))
	assert.Equal(t, in.Name, out.Name)
	assert.Equal(t, in.Items, out.Items)
}

func TestAPICache_MissForUnknownKey(t *testing.T) {
	c, err := cache.NewAPI(t.TempDir(), "test")
	require.NoError(t, err)

	var v map[string]any
	assert.False(t, c.Get("nonexistent-key", &v))
}

func TestAPICache_DifferentKeysDontCollide(t *testing.T) {
	c, err := cache.NewAPI(t.TempDir(), "test")
	require.NoError(t, err)

	c.Set("org1|domain1", []string{"a.com"})
	c.Set("org2|domain2", []string{"b.com"})

	var v1, v2 []string
	require.True(t, c.Get("org1|domain1", &v1))
	require.True(t, c.Get("org2|domain2", &v2))
	assert.Equal(t, []string{"a.com"}, v1)
	assert.Equal(t, []string{"b.com"}, v2)
}

func TestAPICache_PrefixIsolation(t *testing.T) {
	// Two caches sharing the same dir but different prefixes must not
	// collide on the same logical key.
	dir := t.TempDir()
	c1, err := cache.NewAPI(dir, "apollo")
	require.NoError(t, err)
	c2, err := cache.NewAPI(dir, "github-org")
	require.NoError(t, err)

	c1.Set("same-key", []string{"apollo-result"})
	c2.Set("same-key", []string{"github-result"})

	var v1, v2 []string
	require.True(t, c1.Get("same-key", &v1))
	require.True(t, c2.Get("same-key", &v2))
	assert.Equal(t, []string{"apollo-result"}, v1)
	assert.Equal(t, []string{"github-result"}, v2)
}

func TestAPICache_StaleAfterTTL(t *testing.T) {
	c, err := cache.NewAPIWithTTL(t.TempDir(), "test", 1*time.Millisecond)
	require.NoError(t, err)

	c.Set("key", "value")
	time.Sleep(10 * time.Millisecond) // ensure TTL expires

	var v string
	assert.False(t, c.Get("key", &v), "cache should be stale after TTL")
}

func TestAPICache_EmptySliceCachedCorrectly(t *testing.T) {
	c, err := cache.NewAPI(t.TempDir(), "test")
	require.NoError(t, err)

	c.Set("empty", []string{})

	var v []string
	assert.True(t, c.Get("empty", &v), "empty slice should be a cache hit, not a miss")
	assert.Empty(t, v)
}
