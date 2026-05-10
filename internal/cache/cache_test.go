package cache_test

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/abhishekamralkar/argus/internal/cache"
)

func makeZipBytes(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newCache(t *testing.T) *cache.Cache {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	return c
}

func TestDownloadZip_FreshDownload(t *testing.T) {
	zb := makeZipBytes(t, "test.json", `{"id":"CVE-2024-1234"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zb)
	}))
	defer srv.Close()

	c := newCache(t)
	zr, err := c.DownloadZip(srv.URL)
	if err != nil {
		t.Fatalf("DownloadZip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Errorf("expected 1 zip entry, got %d", len(zr.File))
	}
}

func TestDownloadZip_304NotModified(t *testing.T) {
	zb := makeZipBytes(t, "test.json", `{}`)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-None-Match") == `"etag1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"etag1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zb)
	}))
	defer srv.Close()

	c := newCache(t)
	// First request — download and cache.
	if _, err := c.DownloadZip(srv.URL); err != nil {
		t.Fatalf("first download: %v", err)
	}
	// Second request — server returns 304; must serve from disk.
	zr, err := c.DownloadZip(srv.URL)
	if err != nil {
		t.Fatalf("second download: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 HTTP calls, got %d", calls)
	}
	if len(zr.File) != 1 {
		t.Errorf("expected 1 zip entry from cache, got %d", len(zr.File))
	}
}

func TestDownloadZip_NetworkErrorFallback(t *testing.T) {
	zb := makeZipBytes(t, "fallback.json", `{}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zb)
	}))
	c := newCache(t)
	// Seed the cache.
	if _, err := c.DownloadZip(srv.URL); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv.Close() // take server offline

	// Must fall back to on-disk cache.
	zr, err := c.DownloadZip(srv.URL)
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if len(zr.File) != 1 {
		t.Errorf("expected 1 zip entry from fallback cache, got %d", len(zr.File))
	}
}

func TestDownloadZip_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newCache(t)
	_, err := c.DownloadZip(srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestCache_Size(t *testing.T) {
	zb := makeZipBytes(t, "x.json", `{}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zb)
	}))
	defer srv.Close()

	c := newCache(t)
	if _, err := c.DownloadZip(srv.URL); err != nil {
		t.Fatal(err)
	}
	size, err := c.Size()
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size <= 0 {
		t.Errorf("expected non-zero cache size, got %d", size)
	}
}

func TestCache_Dir(t *testing.T) {
	c := newCache(t)
	if c.Dir() == "" {
		t.Error("Dir() returned empty string")
	}
	if _, err := os.Stat(c.Dir()); err != nil {
		t.Errorf("Dir() path does not exist: %v", err)
	}
}

func TestNew_CreatesDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "nonexistent"))
	c, err := cache.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := os.Stat(c.Dir()); err != nil {
		t.Errorf("New did not create directory: %v", err)
	}
}

func TestDownloadZip_LastModifiedConditional(t *testing.T) {
	zb := makeZipBytes(t, "lm.json", `{}`)
	const lmVal = "Tue, 01 Jan 2025 00:00:00 GMT"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-Modified-Since") == lmVal {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", lmVal)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zb)
	}))
	defer srv.Close()

	c := newCache(t)
	if _, err := c.DownloadZip(srv.URL); err != nil {
		t.Fatalf("first: %v", err)
	}
	zr, err := c.DownloadZip(srv.URL)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 HTTP calls, got %d", calls)
	}
	if len(zr.File) != 1 {
		t.Errorf("expected 1 file, got %d", len(zr.File))
	}
}
