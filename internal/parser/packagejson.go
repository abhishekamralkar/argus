package parser

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// ParsePackageJSON parses a package.json file and returns all dependencies
// (dependencies + devDependencies). Version range prefixes (^, ~, >=, etc.)
// are stripped to produce a bare version string for comparison.
func ParsePackageJSON(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	var deps []Dependency
	for name, ver := range manifest.Dependencies {
		deps = append(deps, Dependency{Name: name, Version: StripNPMRange(ver), Ecosystem: "npm"})
	}
	for name, ver := range manifest.DevDependencies {
		deps = append(deps, Dependency{Name: name, Version: StripNPMRange(ver), Ecosystem: "npm"})
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}

// ParsePackageLockJSON parses a package-lock.json (v1, v2, or v3) and returns
// exact resolved versions for all packages. Lock file versions are preferred
// over package.json ranges because they represent the version actually installed.
// For v2/v3 format, packages listed in the root entry's dependencies or
// devDependencies are marked Direct: true.
func ParsePackageLockJSON(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2/v3: flat "packages" map keyed "" (root) or "node_modules/<name>"
		Packages map[string]struct {
			Version         string            `json:"version"`
			Dev             bool              `json:"dev"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		} `json:"packages"`
		// v1: nested "dependencies" map
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []Dependency
	if lock.LockfileVersion >= 2 {
		// Collect direct dep names from the root "" entry.
		directNames := map[string]bool{}
		if root, ok := lock.Packages[""]; ok {
			for name := range root.Dependencies {
				directNames[name] = true
			}
			for name := range root.DevDependencies {
				directNames[name] = true
			}
		}
		for key, pkg := range lock.Packages {
			name, ok := strings.CutPrefix(key, "node_modules/")
			if !ok || name == "" || pkg.Version == "" {
				continue
			}
			deps = append(deps, Dependency{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "npm",
				Direct:    directNames[name],
			})
		}
	} else {
		for name, pkg := range lock.Dependencies {
			if pkg.Version == "" {
				continue
			}
			deps = append(deps, Dependency{Name: name, Version: pkg.Version, Ecosystem: "npm"})
		}
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}

// StripNPMRange removes npm semver range operators (^, ~, >=, >, <=, <, =)
// and the "v" prefix so the remaining string is a plain version number.
// Returns the original string unchanged for non-standard values like "latest".
func StripNPMRange(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~>=<v ")
	return v
}
