package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/abhishekamralkar/argus/internal/store"
)

// OSV ecosystem → our canonical name
var osvEcosystems = map[string]string{
	"Go":        "go",
	"PyPI":      "python",
	"crates.io": "rust",
}

// OSV download URLs per ecosystem
var osvURLs = map[string]string{
	"Go":        "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
	"PyPI":      "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
	"crates.io": "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
}

type osvRecord struct {
	ID        string    `json:"id"`
	Published time.Time `json:"published"`
	Modified  time.Time `json:"modified"`
	Aliases   []string  `json:"aliases"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
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
}

func (r *osvRecord) toVuln(ecosystem string) *store.Vulnerability {
	pkg := ""
	fixedIn := ""
	for _, a := range r.Affected {
		if osvEcosystems[a.Package.Ecosystem] == ecosystem {
			pkg = a.Package.Name
			for _, rng := range a.Ranges {
				for _, ev := range rng.Events {
					if ev.Fixed != "" {
						fixedIn = ev.Fixed
						break
					}
				}
			}
			break
		}
	}
	if pkg == "" && len(r.Affected) > 0 {
		pkg = r.Affected[0].Package.Name
	}

	severity := ""
	for _, s := range r.Severity {
		if strings.HasPrefix(s.Score, "CRITICAL") {
			severity = "CRITICAL"
			break
		} else if strings.HasPrefix(s.Score, "HIGH") && severity != "CRITICAL" {
			severity = "HIGH"
		} else if strings.HasPrefix(s.Score, "MEDIUM") && severity == "" {
			severity = "MEDIUM"
		} else if strings.HasPrefix(s.Score, "LOW") && severity == "" {
			severity = "LOW"
		}
	}

	return &store.Vulnerability{
		ID:        r.ID,
		Ecosystem: ecosystem,
		Package:   pkg,
		Aliases:   r.Aliases,
		Summary:   r.Summary,
		Details:   r.Details,
		Severity:  severity,
		FixedIn:   fixedIn,
		Published: r.Published,
	}
}

// LoadOSV downloads the OSV zip for the given ecosystem (e.g. "Go", "PyPI", "crates.io")
// and calls fn for each parsed vulnerability.
func LoadOSV(osvEco string, fn func(*store.Vulnerability) error) error {
	eco, ok := osvEcosystems[osvEco]
	if !ok {
		return fmt.Errorf("unknown OSV ecosystem: %s", osvEco)
	}
	url, ok := osvURLs[osvEco]
	if !ok {
		return fmt.Errorf("no URL for OSV ecosystem: %s", osvEco)
	}

	return loadFromZip(
		url,
		func(name string) bool {
			return strings.HasSuffix(name, ".json")
		},
		func(name string, data []byte) error {
			var rec osvRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				return nil
			}
			v := rec.toVuln(eco)
			if v.Package == "" {
				return nil
			}
			return fn(v)
		},
	)
}
