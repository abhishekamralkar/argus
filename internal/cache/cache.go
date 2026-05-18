package cache

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const maxFeedBytes int64 = 512 << 20 // 512 MB hard limit per feed

// Cache stores downloaded zip archives on disk and uses conditional HTTP
// requests (ETag / Last-Modified) to avoid re-downloading unchanged feeds.
type Cache struct {
	dir string
}

type meta struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	CachedAt     time.Time `json:"cached_at"`
}

// New returns a Cache backed by the XDG cache directory
// ($XDG_CACHE_HOME/argus/feeds or ~/.cache/argus/feeds).
// The directory is created if it does not exist.
func New() (*Cache, error) {
	dir, err := defaultDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &Cache{dir: dir}, nil
}

// Dir returns the directory where cached files are stored.
func (c *Cache) Dir() string { return c.dir }

// Size returns the total byte size of all files in the cache directory.
func (c *Cache) Size() (int64, error) {
	var total int64
	err := filepath.WalkDir(c.dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// DownloadZip fetches url, returning a cached copy when the server returns
// HTTP 304 (Not Modified). Falls back to the on-disk cache on network errors.
func (c *Cache) DownloadZip(ctx context.Context, url string) (*zip.Reader, error) {
	key := urlKey(url)
	zipPath := filepath.Join(c.dir, key+".zip")
	metaPath := filepath.Join(c.dir, key+".json")

	var m meta
	if raw, err := os.ReadFile(metaPath); err == nil {
		_ = json.Unmarshal(raw, &m)
	}

	// 10-minute deadline covers the full download of large feeds (OSV zips can be 300MB+).
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	if m.ETag != "" {
		req.Header.Set("If-None-Match", m.ETag)
	} else if m.LastModified != "" {
		req.Header.Set("If-Modified-Since", m.LastModified)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Fall back to cached copy on network error.
		if zr, readErr := readCachedZip(zipPath); readErr == nil {
			return zr, nil
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return readCachedZip(zipPath)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	// Stream the response directly to a temp file, then atomically rename it
	// to the cache path. This avoids holding the entire compressed zip in memory
	// during the download (previously up to 512 MB as a []byte).
	tmp, err := os.CreateTemp(filepath.Dir(zipPath), ".dl-*.zip")
	if err != nil {
		return nil, fmt.Errorf("download %s: create temp: %w", url, err)
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		_ = tmp.Close()
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: read body: %w", url, err)
	}
	if n > maxFeedBytes {
		return nil, fmt.Errorf("download %s: response exceeds 512 MB size limit", url)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("download %s: flush: %w", url, err)
	}

	// Atomic rename to the cache path (best-effort).
	if renameErr := os.Rename(tmpName, zipPath); renameErr == nil {
		renamed = true
		m = meta{
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
			CachedAt:     time.Now().UTC(),
		}
		if b, jsonErr := json.Marshal(m); jsonErr == nil {
			_ = os.WriteFile(metaPath, b, 0o600)
		}
	}

	// Read from the cache file (or the still-present temp file if rename failed).
	target := zipPath
	if !renamed {
		target = tmpName
	}
	return readCachedZip(target)
}

// DownloadBytes fetches url and returns the raw response body, using
// ETag/Last-Modified caching just like DownloadZip. Falls back to the
// on-disk cache on network errors.
func (c *Cache) DownloadBytes(ctx context.Context, url string) ([]byte, error) {
	key := urlKey(url)
	dataPath := filepath.Join(c.dir, key+".dat")
	metaPath := filepath.Join(c.dir, key+".json")

	var m meta
	if raw, err := os.ReadFile(metaPath); err == nil {
		_ = json.Unmarshal(raw, &m)
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	if m.ETag != "" {
		req.Header.Set("If-None-Match", m.ETag)
	} else if m.LastModified != "" {
		req.Header.Set("If-Modified-Since", m.LastModified)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return os.ReadFile(dataPath)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return os.ReadFile(dataPath)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: read body: %w", url, err)
	}
	if int64(len(data)) > maxFeedBytes {
		return nil, fmt.Errorf("download %s: response exceeds 512 MB size limit", url)
	}

	if writeErr := os.WriteFile(dataPath, data, 0o600); writeErr == nil {
		m = meta{
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
			CachedAt:     time.Now().UTC(),
		}
		if b, jsonErr := json.Marshal(m); jsonErr == nil {
			_ = os.WriteFile(metaPath, b, 0o600)
		}
	}
	return data, nil
}

func readCachedZip(path string) (*zip.Reader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return zip.NewReader(bytes.NewReader(data), int64(len(data)))
}

// urlKey returns a stable, filesystem-safe identifier for a URL.
func urlKey(url string) string {
	h := sha256.Sum256([]byte(url))
	return hex.EncodeToString(h[:16])
}

func defaultDir() (string, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "argus", "feeds"), nil
}
