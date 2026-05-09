package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/abhishekamralkar/argus/internal/store"
)

var osvSeverityRank = map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

// OSV ecosystem → our canonical name
var osvEcosystems = map[string]string{
	"Go":        "go",
	"PyPI":      "python",
	"crates.io": "rust",
	"npm":       "npm",
	"Maven":     "maven",
	"NuGet":     "nuget",
}

// OSV download URLs per ecosystem
var osvURLs = map[string]string{
	"Go":        "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
	"PyPI":      "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
	"crates.io": "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
	"npm":       "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
	"Maven":     "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip",
	"NuGet":     "https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip",
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
		var sev string
		// Try plain label first; fall back to CVSS vector computation.
		if norm := normalizeSeverity(s.Score); norm != "" {
			sev = norm
		} else if score, ok := cvssV3BaseScore(s.Score); ok {
			sev = cvssScoreToSeverity(score)
		}
		if osvSeverityRank[sev] > osvSeverityRank[severity] {
			severity = sev
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
