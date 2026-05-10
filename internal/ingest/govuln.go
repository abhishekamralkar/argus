package ingest

import (
	"encoding/json"
	"math"
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

			v := &store.Vulnerability{
				ID:        rec.ID,
				Ecosystem: "go",
				Package:   pkg,
				Aliases:   rec.Aliases,
				Summary:   rec.Summary,
				Details:   rec.Details,
				Severity:  severityFromGoVuln(&rec),
				FixedIn:   fixedIn,
				Published: rec.Published,
			}
			return fn(v)
		},
	)
}

// severityFromGoVuln extracts a severity label from a GoVulnDB record.
// It first checks the pre-computed database_specific.severity string, then
// falls back to computing the CVSS v3 base score from the severity vector.
// Returns "" when no severity data is present so the caller can decide.
func severityFromGoVuln(rec *goVulnRecord) string {
	if s := normalizeSeverity(rec.DatabaseSpecific.Severity); s != "" {
		return s
	}
	for _, s := range rec.Severity {
		if s.Type == "CVSS_V3" && strings.HasPrefix(s.Score, "CVSS:3") {
			if score, ok := cvssV3BaseScore(s.Score); ok {
				return cvssScoreToSeverity(score)
			}
		}
	}
	return ""
}

// cvssScoreToSeverity maps a CVSS v3 numeric base score to a severity label
// using the standard NVD ranges.
func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return ""
	}
}

// cvssV3BaseScore computes the CVSS v3.1 base score from a vector string such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".
// Returns the score and true on success; 0 and false if the vector is malformed.
func cvssV3BaseScore(vector string) (float64, bool) {
	// Strip the "CVSS:3.x/" version prefix.
	_, rest, ok := strings.Cut(vector, "/")
	if !ok {
		return 0, false
	}
	metrics := make(map[string]string, 8)
	for part := range strings.SplitSeq(rest, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			metrics[k] = v
		}
	}

	avWeights := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acWeights := map[string]float64{"L": 0.77, "H": 0.44}
	uiWeights := map[string]float64{"N": 0.85, "R": 0.62}
	ciaWeights := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.00}
	// PR weight differs between Scope Unchanged and Scope Changed.
	prUnchanged := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prChanged := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}

	av, ok1 := avWeights[metrics["AV"]]
	ac, ok2 := acWeights[metrics["AC"]]
	ui, ok3 := uiWeights[metrics["UI"]]
	c, ok4 := ciaWeights[metrics["C"]]
	i, ok5 := ciaWeights[metrics["I"]]
	a, ok6 := ciaWeights[metrics["A"]]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return 0, false
	}

	scope := metrics["S"]
	var pr float64
	var prOk bool
	if scope == "C" {
		pr, prOk = prChanged[metrics["PR"]]
	} else {
		pr, prOk = prUnchanged[metrics["PR"]]
	}
	if !prOk {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)

	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scope == "U" {
		base = math.Min(impact+exploitability, 10)
	} else {
		base = math.Min(1.08*(impact+exploitability), 10)
	}

	// CVSS spec roundup: smallest value to 1 decimal place >= input.
	base = math.Ceil(base*10) / 10
	return base, true
}
