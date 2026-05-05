package ingest

import "io"

// loadFromZip downloads a zip from url and calls fn for each file whose name
// passes match. Errors opening or reading individual entries are silently
// skipped; fn returning a non-nil error stops iteration and is returned.
func loadFromZip(url string, match func(string) bool, fn func(name string, data []byte) error) error {
	zr, err := downloadZip(url)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if !match(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			continue
		}
		if err := fn(f.Name, data); err != nil {
			return err
		}
	}
	return nil
}
