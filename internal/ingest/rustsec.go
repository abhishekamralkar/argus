package ingest

import (
	"io"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/abhishekamralkar/argus/internal/store"
)

type rustSecAdvisory struct {
	Advisory struct {
		ID          string    `toml:"id"`
		Package     string    `toml:"package"`
		Date        string    `toml:"date"`
		URL         string    `toml:"url"`
		Title       string    `toml:"title"`
		Description string    `toml:"description"`
		Keywords    []string  `toml:"keywords"`
		Aliases     []string  `toml:"aliases"`
		PatchedVers []string  `toml:"patched_versions"`
		Severity    string    `toml:"severity"`
		_           time.Time // unused but keeps struct non-empty
	} `toml:"advisory"`
}

// LoadRustSec downloads the RustSec advisory DB and calls fn per advisory.
func LoadRustSec(fn func(*store.Vulnerability) error) error {
	zr, err := downloadZip("https://github.com/rustsec/advisory-db/archive/refs/heads/main.zip")
	if err != nil {
		return err
	}

	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".toml") {
			continue
		}
		// Only crate advisories: advisory-db-main/crates/<name>/<id>.toml
		parts := strings.Split(f.Name, "/")
		if len(parts) < 4 || parts[1] != "crates" {
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

		var adv rustSecAdvisory
		if _, err := toml.Decode(string(data), &adv); err != nil {
			continue
		}
		a := adv.Advisory
		if a.ID == "" || a.Package == "" {
			continue
		}

		fixedIn := ""
		if len(a.PatchedVers) > 0 {
			fixedIn = strings.TrimPrefix(a.PatchedVers[0], ">=")
		}

		published, _ := time.Parse("2006-01-02", a.Date)

		v := &store.Vulnerability{
			ID:        a.ID,
			Ecosystem: "rust",
			Package:   a.Package,
			Aliases:   a.Aliases,
			Summary:   a.Title,
			Details:   a.Description,
			Severity:  normalizeSeverity(a.Severity),
			FixedIn:   strings.TrimSpace(fixedIn),
			Published: published,
		}
		if err := fn(v); err != nil {
			return err
		}
	}
	return nil
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return ""
	}
}
