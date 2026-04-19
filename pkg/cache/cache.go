package cache

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	APNICOrgURL          = "https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz"
	APNICInetURL         = "https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz"
	AFRINICAllURL        = "https://ftp.afrinic.net/dbase/afrinic.db.gz"
	DefaultTTL           = 24 * time.Hour
	CacheDirName         = ".pius/cache"
	maxDecompressedSize  = 2 << 30 // 2GB
)

var downloadClient = &http.Client{
	Timeout: 10 * time.Minute,
}

// Cache manages locally-cached RPSL database files with TTL.
type Cache struct {
	dir string
	ttl time.Duration
}

// New creates a Cache storing files in $HOME/.pius/cache/.
func New() (*Cache, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, CacheDirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &Cache{dir: dir, ttl: DefaultTTL}, nil
}

// GetOrDownload returns the path to a locally cached (and decompressed) RPSL file.
// If the file is missing or older than TTL, downloads and decompresses it.
func (c *Cache) GetOrDownload(ctx context.Context, url string) (string, error) {
	localPath := filepath.Join(c.dir, cacheFilename(url))

	if !c.isStale(localPath) {
		return localPath, nil
	}

	if err := c.download(ctx, url, localPath); err != nil {
		// Fall back to stale cache if download fails
		if _, statErr := os.Stat(localPath); statErr == nil {
			return localPath, nil
		}
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	return localPath, nil
}

// isStale returns true if the file doesn't exist or is older than TTL.
func (c *Cache) isStale(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) > c.ttl
}

// download fetches the gzip URL and saves decompressed content to localPath atomically.
func (c *Cache) download(ctx context.Context, url, localPath string) error {
	dlCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "pius/1.0")

	resp, err := downloadClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Decompress gzip
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()

	// Write atomically via temp file
	tmp := localPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // Guaranteed cleanup regardless of exit path

	n, err := io.Copy(f, io.LimitReader(gz, maxDecompressedSize+1))
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if n > maxDecompressedSize {
		_ = os.Remove(tmp)
		return fmt.Errorf("decompressed RPSL file exceeds %d bytes", maxDecompressedSize)
	}

	// Explicitly close before rename to ensure data is flushed
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp file: %w", err)
	}

	return os.Rename(tmp, localPath)
}

// cacheFilename computes a stable local filename from a URL.
func cacheFilename(url string) string {
	h := sha256.Sum256([]byte(url))
	return fmt.Sprintf("%x.rpsl", h[:8])
}
