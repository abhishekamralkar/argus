package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

func downloadZip(url string) (*zip.Reader, error) {
	// 10-minute deadline covers the full download of large feeds (OSV zips can be 300MB+).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	const maxBytes = 512 << 20 // 512 MB hard cap
	lr := io.LimitReader(resp.Body, maxBytes+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("download %s: read body: %w", url, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("download %s: response exceeds 512 MB size limit", url)
	}
	return zip.NewReader(bytes.NewReader(data), int64(len(data)))
}
