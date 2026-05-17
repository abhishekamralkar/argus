package parser

import (
	"os"
	"sort"

	"github.com/BurntSushi/toml"
)

type cargoLockFile struct {
	Package []cargoLockPackage `toml:"package"`
}

type cargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

// ParseCargoLock parses a Cargo.lock and returns all resolved packages,
// including transitive dependencies. Direct: false for all entries because
// Cargo.lock does not distinguish direct from transitive deps; pair with
// ParseCargoToml results to identify which are direct.
func ParseCargoLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock cargoLockFile
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, err
	}

	var deps []Dependency
	for _, pkg := range lock.Package {
		if pkg.Name == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "rust",
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
