package parser

import (
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

type pubspecLockFile struct {
	Packages map[string]struct {
		Version string `yaml:"version"`
	} `yaml:"packages"`
}

// ParsePubspecLock parses a Dart/Flutter pubspec.lock and returns all packages.
func ParsePubspecLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock pubspecLockFile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	deps := make([]Dependency, 0, len(lock.Packages))
	for name, pkg := range lock.Packages {
		if name == "" || pkg.Version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: "dart",
		})
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}
