package ingest

import (
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
	return loadFromZip(
		"https://github.com/pypa/advisory-database/archive/refs/heads/main.zip",
		func(name string) bool {
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				return false
			}
			// advisory-database-main/advisories/pypi/<pkg>/<id>.yaml
			parts := strings.Split(name, "/")
			return len(parts) >= 5 && parts[1] == "advisories"
		},
		func(name string, data []byte) error {
			var adv pypaAdvisory
			if err := yaml.Unmarshal(data, &adv); err != nil {
				return nil
			}
			if adv.ID == "" || adv.Package.Name == "" {
				return nil
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
			return fn(v)
		},
	)
}
