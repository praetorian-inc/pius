package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// APICache caches arbitrary JSON API responses keyed by a string.
//
// Unlike Cache (which downloads and decompresses large gzip RPSL databases),
// APICache stores small JSON payloads for API responses where each distinct
// org/domain combination is a separate cache entry.
//
// Files are stored in ~/.pius/cache/ alongside RPSL files, sharing the same
// cache directory but using a JSON format with distinct filename prefixes.
type APICache struct {
	dir    string
	ttl    time.Duration
	prefix string // filename prefix to distinguish from RPSL files
}

// NewAPI creates an APICache storing files in ~/.pius/cache/.
// If dir is empty, uses the default cache directory ($HOME/.pius/cache).
// prefix distinguishes cache files from different callers (e.g., "apollo").
func NewAPI(dir, prefix string) (*APICache, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home dir: %w", err)
		}
		dir = filepath.Join(home, CacheDirName)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create cache dir %s: %w", dir, err)
	}
	if prefix == "" {
		prefix = "api"
	}
	return &APICache{dir: dir, ttl: DefaultTTL, prefix: prefix}, nil
}

// Get reads a cached value into v. Returns true if cache hit (fresh, valid JSON).
// Returns false if the entry is missing, expired, or corrupt.
func (c *APICache) Get(key string, v any) bool {
	path := c.path(key)
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > c.ttl {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if err := json.Unmarshal(data, v); err != nil {
		// Corrupt cache — treat as miss
		_ = os.Remove(path)
		return false
	}
	return true
}

// Set writes v as JSON to the cache for key.
// Uses atomic write (temp file + rename) to prevent partial writes.
// Errors are logged but not returned — a failed cache write is not fatal.
func (c *APICache) Set(key string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("[apicache] marshal error for key %q: %v", key, err)
		return
	}
	path := c.path(key)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("[apicache] write error for key %q: %v", key, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[apicache] rename error for key %q: %v", key, err)
		os.Remove(tmp)
	}
}

// path returns the file path for a given cache key.
// Uses an 8-byte SHA256 prefix — sufficient collision resistance for OSINT caching.
func (c *APICache) path(key string) string {
	h := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, fmt.Sprintf("%s-%x.json", c.prefix, h[:8]))
}
