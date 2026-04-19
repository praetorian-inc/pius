package cache_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/pius/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache_Download_DecompressesGzip(t *testing.T) {
	// Create gzip content
	content := "This is test RPSL data\nwith multiple lines\n"
	var gzipBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzipBuf)
	_, err := gzw.Write([]byte(content))
	require.NoError(t, err)
	err = gzw.Close()
	require.NoError(t, err)

	// Start test server serving gzipped content
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzipBuf.Bytes())
	}))
	defer server.Close()

	// Create cache and download
	c, err := cache.New()
	require.NoError(t, err)

	ctx := context.Background()
	localPath, err := c.GetOrDownload(ctx, server.URL)
	require.NoError(t, err)
	defer func() { _ = os.Remove(localPath) }()

	// Verify decompressed content
	got, err := os.ReadFile(localPath)
	require.NoError(t, err)
	assert.Equal(t, content, string(got), "should decompress gzip correctly")
}

func TestCache_Download_FallbackToStaleOnError(t *testing.T) {
	// Create server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c, err := cache.New()
	require.NoError(t, err)

	// First, create a stale cache file by downloading successfully
	successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gzw := gzip.NewWriter(w)
		_, _ = gzw.Write([]byte("stale but valid data"))
		_ = gzw.Close()
	}))

	// Download to create cache file
	localPath, err := c.GetOrDownload(context.Background(), successServer.URL)
	require.NoError(t, err)
	defer func() { _ = os.Remove(localPath) }()
	successServer.Close()

	// Make the file stale (>24h old)
	oldTime := time.Now().Add(-25 * time.Hour)
	err = os.Chtimes(localPath, oldTime, oldTime)
	require.NoError(t, err)

	// Now try to refresh with the error server
	// GetOrDownload should:
	// 1. See file is stale
	// 2. Attempt download
	// 3. Download fails
	// 4. Fall back to stale cache

	got, err := c.GetOrDownload(context.Background(), successServer.URL)
	require.NoError(t, err, "should fall back to stale cache on download error")

	content, err := os.ReadFile(got)
	require.NoError(t, err)
	assert.Equal(t, "stale but valid data", string(content), "should return stale cache content")
}

func TestCache_GetOrDownload_SkipsDownloadWhenFresh(t *testing.T) {
	// Start server that tracks request count
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Serve gzipped content
		gzw := gzip.NewWriter(w)
		_, _ = gzw.Write([]byte("fresh data"))
		_ = gzw.Close()
	}))
	defer server.Close()

	c, err := cache.New()
	require.NoError(t, err)

	ctx := context.Background()

	// First call: should download
	path1, err := c.GetOrDownload(ctx, server.URL)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path1) }()
	assert.Equal(t, 1, requestCount, "should make HTTP request on first call")

	// Second call: file is fresh (<24h), should NOT download
	path2, err := c.GetOrDownload(ctx, server.URL)
	require.NoError(t, err)
	assert.Equal(t, path1, path2, "should return same path")
	assert.Equal(t, 1, requestCount, "should NOT make HTTP request when cache is fresh")
}

func TestCache_GetOrDownload_RefreshesStaleCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gzw := gzip.NewWriter(w)
		_, _ = gzw.Write([]byte("refreshed data"))
		_ = gzw.Close()
	}))
	defer server.Close()

	c, err := cache.New()
	require.NoError(t, err)

	ctx := context.Background()

	// Download initial file
	path, err := c.GetOrDownload(ctx, server.URL)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path) }()

	// Make file stale
	oldTime := time.Now().Add(-25 * time.Hour)
	err = os.Chtimes(path, oldTime, oldTime)
	require.NoError(t, err)

	// Second call should refresh
	path2, err := c.GetOrDownload(ctx, server.URL)
	require.NoError(t, err)
	assert.Equal(t, path, path2, "should use same path")

	// Verify content refreshed
	content, err := os.ReadFile(path2)
	require.NoError(t, err)
	assert.Equal(t, "refreshed data", string(content), "should have refreshed content")

	// Verify file is now fresh
	info, err := os.Stat(path2)
	require.NoError(t, err)
	assert.True(t, time.Since(info.ModTime()) < 1*time.Minute, "file should have fresh mtime")
}

func TestCache_CacheFilename_ConsistentHash(t *testing.T) {
	// cacheFilename is unexported, testing via behavior:
	// Same URL should produce same local filename

	c, err := cache.New()
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gzw := gzip.NewWriter(w)
		_, _ = gzw.Write([]byte("data"))
		_ = gzw.Close()
	}))
	defer server.Close()

	ctx := context.Background()

	// Download twice with same URL
	path1, err := c.GetOrDownload(ctx, server.URL)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path1) }()

	// Clear file to force re-download
	_ = os.Remove(path1)

	path2, err := c.GetOrDownload(ctx, server.URL)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path2) }()

	assert.Equal(t, path1, path2, "same URL should produce same local path")
}

func TestCache_AtomicWrite_NoPartialFiles(t *testing.T) {
	// Verify atomic write via .tmp file (implementation detail, but important)
	// If download fails mid-stream, no corrupt cache file left behind

	c, err := cache.New()
	require.NoError(t, err)

	// Server that closes connection mid-response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gzw := gzip.NewWriter(w)
		_, _ = gzw.Write([]byte("partial"))
		// Close without finishing gzip stream
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}
	}))
	defer server.Close()

	ctx := context.Background()

	// This should fail
	_, err = c.GetOrDownload(ctx, server.URL)
	assert.Error(t, err, "should fail on incomplete download")

	// Verify no .tmp file left behind (cleaned up on error)
	// Using home dir cache location since Dir() is not exported
	home, _ := os.UserHomeDir()
	cacheDir := filepath.Join(home, cache.CacheDirName)
	tmpFiles, _ := filepath.Glob(filepath.Join(cacheDir, "*.tmp"))
	assert.Empty(t, tmpFiles, "should not leave .tmp files after failed download")
}
