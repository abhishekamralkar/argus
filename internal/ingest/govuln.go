package ingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/abhishekamralkar/argus/internal/cache"
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
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// LoadGoVulnDB downloads the Go vulnerability database zip and calls fn per entry.
// Pass a non-nil cache to enable ETag/Last-Modified caching.
func LoadGoVulnDB(c *cache.Cache, fn func(*store.Vulnerability) error) error {
	return loadFromZip(
		"https://vuln.go.dev/index/db.zip", c,
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

			cvssScore, cvssVector := cvssFromGoVuln(&rec)
			v := &store.Vulnerability{
				ID:         rec.ID,
				Ecosystem:  "go",
				Package:    pkg,
				Aliases:    rec.Aliases,
				Summary:    rec.Summary,
				Details:    rec.Details,
				Severity:   severityFromGoVuln(&rec),
				FixedIn:    fixedIn,
				Published:  rec.Published,
				CVSSScore:  cvssScore,
				CVSSVector: cvssVector,
			}
			return fn(v)
		},
	)
}

// cvssFromGoVuln returns the highest CVSS v3/v4 numeric score and its vector
// string from a GoVulnDB record. Returns (0, "") when no CVSS data is present.
func cvssFromGoVuln(rec *goVulnRecord) (score float64, vector string) {
	var best float64
	var vec string
	for _, s := range rec.Severity {
		if sc, ok := parseCVSSScore(s.Score); ok && sc > best {
			best = sc
			vec = s.Score
		}
	}
	return best, vec
}

// severityFromGoVuln extracts a severity label from a GoVulnDB record.
// It first checks the pre-computed database_specific.severity string, then
// falls back to computing the CVSS base score from the severity vector.
// Returns "" when no severity data is present so the caller can decide.
func severityFromGoVuln(rec *goVulnRecord) string {
	if s := normalizeSeverity(rec.DatabaseSpecific.Severity); s != "" {
		return s
	}
	for _, s := range rec.Severity {
		if score, ok := parseCVSSScore(s.Score); ok {
			return cvssScoreToSeverity(score)
		}
	}
	return ""
}
