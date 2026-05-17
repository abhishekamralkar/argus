package parser

import (
	"encoding/json"
	"os"
	"sort"
)

// ParsePackageResolved parses a Swift Package Manager Package.resolved file
// and returns all pinned packages. Both v1 and v2 formats are supported.
func ParsePackageResolved(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Detect format version.
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, err
	}

	switch header.Version {
	case 1:
		return parsePackageResolvedV1(data)
	default:
		return parsePackageResolvedV2(data)
	}
}

type packageResolvedV1 struct {
	Object struct {
		Pins []struct {
			Package string `json:"package"`
			State   struct {
				Version string `json:"version"`
			} `json:"state"`
		} `json:"pins"`
	} `json:"object"`
}

func parsePackageResolvedV1(data []byte) ([]Dependency, error) {
	var f packageResolvedV1
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	var deps []Dependency
	for _, p := range f.Object.Pins {
		if p.Package == "" || p.State.Version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      p.Package,
			Version:   p.State.Version,
			Ecosystem: "swift",
		})
	}
	sortDeps(deps)
	return deps, nil
}

type packageResolvedV2 struct {
	Pins []struct {
		Identity string `json:"identity"`
		State    struct {
			Version string `json:"version"`
		} `json:"state"`
	} `json:"pins"`
}

func parsePackageResolvedV2(data []byte) ([]Dependency, error) {
	var f packageResolvedV2
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	var deps []Dependency
	for _, p := range f.Pins {
		if p.Identity == "" || p.State.Version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      p.Identity,
			Version:   p.State.Version,
			Ecosystem: "swift",
		})
	}
	sortDeps(deps)
	return deps, nil
}

func sortDeps(deps []Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
}
