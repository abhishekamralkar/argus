package parser

import (
	"os"

	"github.com/BurntSushi/toml"
)

type cargoManifest struct {
	Dependencies    map[string]tomlDep `toml:"dependencies"`
	DevDependencies map[string]tomlDep `toml:"dev-dependencies"`
}

// tomlDep handles both string ("1.0") and table ({version = "1.0"}) forms.
type tomlDep struct {
	Version string
}

func (d *tomlDep) UnmarshalTOML(v any) error {
	switch val := v.(type) {
	case string:
		d.Version = val
	case map[string]any:
		if ver, ok := val["version"].(string); ok {
			d.Version = ver
		}
	}
	return nil
}

// ParseCargoToml parses a Cargo.toml and returns all dependencies.
func ParseCargoToml(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var manifest cargoManifest
	if _, err := toml.Decode(string(data), &manifest); err != nil {
		return nil, err
	}

	var deps []Dependency
	for name, dep := range manifest.Dependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "rust",
		})
	}
	for name, dep := range manifest.DevDependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "rust",
		})
	}
	return deps, nil
}
