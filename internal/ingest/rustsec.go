package ingest

import (
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/abhishekamralkar/argus/internal/cache"
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
// Pass a non-nil cache to enable ETag/Last-Modified caching.
func LoadRustSec(c *cache.Cache, fn func(*store.Vulnerability) error) error {
	return loadFromZip(
		"https://github.com/rustsec/advisory-db/archive/refs/heads/main.zip", c,
		func(name string) bool {
			if !strings.HasSuffix(name, ".toml") {
				return false
			}
			// Only crate advisories: advisory-db-main/crates/<name>/<id>.toml
			parts := strings.Split(name, "/")
			return len(parts) >= 4 && parts[1] == "crates"
		},
		func(name string, data []byte) error {
			var adv rustSecAdvisory
			if _, err := toml.Decode(string(data), &adv); err != nil {
				return nil
			}
			a := adv.Advisory
			if a.ID == "" || a.Package == "" {
				return nil
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
			return fn(v)
		},
	)
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
