package parser

import (
	"os"
	"sort"

	"github.com/BurntSushi/toml"
)

type poetryLockFile struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"package"`
}

// ParsePoetryLock parses a poetry.lock file and returns all pinned packages.
func ParsePoetryLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock poetryLockFile
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, err
	}

	deps := make([]Dependency, 0, len(lock.Package))
	for _, p := range lock.Package {
		if p.Name == "" || p.Version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: "python",
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
