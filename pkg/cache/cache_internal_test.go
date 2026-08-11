package cache

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
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
	_ = f.Close()

	// Backdate mtime by 2×TTL
	old := time.Now().Add(-2 * DefaultTTL)
	require.NoError(t, os.Chtimes(f.Name(), old, old))

	c := &Cache{dir: t.TempDir(), ttl: DefaultTTL}
	assert.True(t, c.isStale(f.Name()), "file older than TTL should be stale")
}

func TestCache_IsStale_WhenFileFresh(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.rpsl")
	require.NoError(t, err)
	_ = f.Close()
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

// ── injected HTTP client seam (NewWithHTTPClient) ─────────────────────────────

// testRPSLURL deliberately uses the reserved .invalid TLD. Every test below
// serves its body from an in-process RoundTripper, and a host that can never
// resolve means a regression in the injection seam fails loudly instead of
// silently egressing to a real RIR mirror.
const testRPSLURL = "https://rpsl.invalid/apnic.db.inet6num.gz"

// countingTransport is an http.RoundTripper that serves a fixed body and counts
// invocations. It never dials, so no test using it can reach the network.
type countingTransport struct {
	mu    sync.Mutex
	calls int
	body  []byte
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.calls++
	t.mu.Unlock()
	return &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(t.body)),
		Request:    req,
	}, nil
}

func (t *countingTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

// gzipped returns payload as a gzip stream so download's decompress path is
// genuinely exercised.
func gzipped(t *testing.T, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte(payload))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func TestCache_NewWithHTTPClient_ColdCacheUsesInjectedTransport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	const payload = "inet6num:  2001:db8::/32\nnetname:   EXAMPLE-V6\n"
	tr := &countingTransport{body: gzipped(t, payload)}

	c, err := NewWithHTTPClient(&http.Client{Transport: tr})
	require.NoError(t, err)
	require.NotNil(t, c)

	// t.Setenv("HOME", ...) IS the directory seam: the cache dir must land under
	// the temp home. This is the evidence that no dir parameter is needed.
	require.Equal(t, filepath.Join(home, CacheDirName), c.dir)
	require.DirExists(t, c.dir)

	// The cache MUST be cold. GetOrDownload returns early when the local file is
	// not stale, before the HTTP client is ever consulted, so a warm cache would
	// let this test pass with the seam completely unwired.
	localPath := filepath.Join(c.dir, cacheFilename(testRPSLURL))
	_, statErr := os.Stat(localPath)
	require.True(t, os.IsNotExist(statErr), "cache must be cold for the client to be reached")

	got, err := c.GetOrDownload(context.Background(), testRPSLURL)
	require.NoError(t, err)
	require.Equal(t, localPath, got)

	assert.NotZero(t, tr.count(), "injected transport must actually be invoked, not merely accepted")

	content, err := os.ReadFile(got)
	require.NoError(t, err)
	assert.Equal(t, payload, string(content), "gzip body must round-trip decompressed to disk")
}

func TestCache_Constructors_NilClientFallsBackToPackageClient(t *testing.T) {
	tests := []struct {
		name string
		ctor func() (*Cache, error)
	}{
		{name: "New", ctor: New},
		{name: "NewWithHTTPClient(nil)", ctor: func() (*Cache, error) { return NewWithHTTPClient(nil) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)

			const payload = "organisation: ORG-EXAMPLE\n"
			tr := &countingTransport{body: gzipped(t, payload)}

			// Point the package-level fallback client at the stub for this subtest
			// only. No test in this package runs in parallel and the original
			// transport is restored, so this stays hermetic — and it keeps the
			// fallback path off the network while still proving it is taken.
			orig := downloadClient.Transport
			t.Cleanup(func() { downloadClient.Transport = orig })
			downloadClient.Transport = tr

			c, err := tt.ctor() // must not panic on a nil client
			require.NoError(t, err)
			require.NotNil(t, c)

			assert.Equal(t, filepath.Join(home, CacheDirName), c.dir)
			assert.Nil(t, c.client, "no client injected, so the per-cache client stays nil")

			// Same cold-cache precondition as the injected-transport test: a warm
			// cache short-circuits GetOrDownload before any client is consulted,
			// so the fallback assertion below would be vacuous.
			localPath := filepath.Join(c.dir, cacheFilename(testRPSLURL))
			_, statErr := os.Stat(localPath)
			require.True(t, os.IsNotExist(statErr), "cache must be cold for the client to be reached")

			got, err := c.GetOrDownload(context.Background(), testRPSLURL)
			require.NoError(t, err)
			assert.NotZero(t, tr.count(), "a nil per-cache client must fall back to the package-level downloadClient")

			content, err := os.ReadFile(got)
			require.NoError(t, err)
			assert.Equal(t, payload, string(content))
		})
	}
}
