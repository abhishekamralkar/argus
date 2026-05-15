package parser

import (
	"encoding/json"
	"os"
	"sort"
)

// ParseComposerLock parses a PHP composer.lock file and returns all resolved
// dependencies from the "packages" and "packages-dev" arrays.
func ParseComposerLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []Dependency
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		if p.Name == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: "php",
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
