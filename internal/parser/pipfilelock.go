package parser

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

type pipfileLock struct {
	Default map[string]pipfilePackage `json:"default"`
	Develop map[string]pipfilePackage `json:"develop"`
}

type pipfilePackage struct {
	Version string `json:"version"`
}

// ParsePipfileLock parses a Pipfile.lock and returns all pinned packages.
// Versions are stored as "==X.Y.Z"; the "==" prefix is stripped.
func ParsePipfileLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock pipfileLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var deps []Dependency
	add := func(name string, pkg pipfilePackage) {
		if seen[name] {
			return
		}
		ver := strings.TrimPrefix(pkg.Version, "==")
		if name == "" || ver == "" {
			return
		}
		seen[name] = true
		deps = append(deps, Dependency{
			Name:      name,
			Version:   ver,
			Ecosystem: "python",
		})
	}
	for name, pkg := range lock.Default {
		add(name, pkg)
	}
	for name, pkg := range lock.Develop {
		add(name, pkg)
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}
