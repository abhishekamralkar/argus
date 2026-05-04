package ingest

import (
	"io"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/abhishekamralkar/argus/internal/store"
)

type pypaAdvisory struct {
	ID      string `yaml:"id"`
	Package struct {
		Name      string `yaml:"name"`
		Ecosystem string `yaml:"ecosystem"`
	} `yaml:"package"`
	Summary   string    `yaml:"summary"`
	Details   string    `yaml:"details"`
	Published time.Time `yaml:"published"`
	Aliases   []string  `yaml:"aliases"`
	Severity  []struct {
		Type  string `yaml:"type"`
		Score string `yaml:"score"`
	} `yaml:"severity"`
	Affected []struct {
		Ranges []struct {
			Type   string `yaml:"type"`
			Events []struct {
				Introduced string `yaml:"introduced"`
				Fixed      string `yaml:"fixed"`
			} `yaml:"events"`
		} `yaml:"ranges"`
	} `yaml:"affected"`
}

// LoadPyPA downloads the PyPA advisory DB and calls fn per advisory.
func LoadPyPA(fn func(*store.Vulnerability) error) error {
	zr, err := downloadZip("https://github.com/pypa/advisory-database/archive/refs/heads/main.zip")
	if err != nil {
		return err
	}

	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".yaml") && !strings.HasSuffix(f.Name, ".yml") {
			continue
		}
		// advisory-database-main/advisories/pypi/<pkg>/<id>.yaml
		parts := strings.Split(f.Name, "/")
		if len(parts) < 5 || parts[1] != "advisories" {
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

		var adv pypaAdvisory
		if err := yaml.Unmarshal(data, &adv); err != nil {
			continue
		}
		if adv.ID == "" || adv.Package.Name == "" {
			continue
		}

		fixedIn := ""
		for _, a := range adv.Affected {
			for _, rng := range a.Ranges {
				for _, ev := range rng.Events {
					if ev.Fixed != "" {
						fixedIn = ev.Fixed
						break
					}
				}
			}
		}

		severity := ""
		for _, s := range adv.Severity {
			if strings.Contains(strings.ToUpper(s.Score), "CRITICAL") {
				severity = "CRITICAL"
				break
			} else if strings.Contains(strings.ToUpper(s.Score), "HIGH") {
				severity = "HIGH"
			}
		}

		v := &store.Vulnerability{
			ID:        adv.ID,
			Ecosystem: "python",
			Package:   adv.Package.Name,
			Aliases:   adv.Aliases,
			Summary:   adv.Summary,
			Details:   adv.Details,
			Severity:  severity,
			FixedIn:   fixedIn,
			Published: adv.Published,
		}
		if err := fn(v); err != nil {
			return err
		}
	}
	return nil
}
