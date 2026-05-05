package ingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/abhishekamralkar/argus/internal/store"
)

type goVulnRecord struct {
	ID        string    `json:"id"`
	Published time.Time `json:"published"`
	Aliases   []string  `json:"aliases"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Affected  []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// LoadGoVulnDB downloads the Go vulnerability database zip and calls fn per entry.
func LoadGoVulnDB(fn func(*store.Vulnerability) error) error {
	return loadFromZip(
		"https://vuln.go.dev/index/db.zip",
		func(name string) bool {
			return strings.HasSuffix(name, ".json") && !strings.Contains(name, "index")
		},
		func(name string, data []byte) error {
			var rec goVulnRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				return nil
			}

			pkg := ""
			fixedIn := ""
			if len(rec.Affected) > 0 {
				pkg = rec.Affected[0].Package.Name
				for _, rng := range rec.Affected[0].Ranges {
					for _, ev := range rng.Events {
						if ev.Fixed != "" {
							fixedIn = ev.Fixed
							break
						}
					}
				}
			}
			if pkg == "" {
				return nil
			}

			v := &store.Vulnerability{
				ID:        rec.ID,
				Ecosystem: "go",
				Package:   pkg,
				Aliases:   rec.Aliases,
				Summary:   rec.Summary,
				Details:   rec.Details,
				FixedIn:   fixedIn,
				Published: rec.Published,
			}
			return fn(v)
		},
	)
}
