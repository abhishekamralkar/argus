package ingest

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/abhishekamralkar/argus/internal/cache"
)

// loadFromZip downloads a zip from url and calls fn for each file whose name
// passes match. Pass a non-nil cache to enable ETag/Last-Modified caching.
// Errors opening or reading individual entries are logged and skipped; fn
// returning a non-nil error stops iteration and is returned.
func loadFromZip(ctx context.Context, url string, c *cache.Cache, match func(string) bool, fn func(name string, data []byte) error) error {
	zr, err := fetchZip(ctx, url, c)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if !match(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: open: %v\n", f.Name, err)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, 10<<20))
		_ = rc.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: read: %v\n", f.Name, err)
			continue
		}
		if err := fn(f.Name, data); err != nil {
			return err
		}
	}
	return nil
}
