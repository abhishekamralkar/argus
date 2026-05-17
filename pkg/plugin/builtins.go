package plugin

import (
	"os"
	"path/filepath"

	"github.com/abhishekamralkar/argus/internal/parser"
)

// builtins returns the built-in ecosystem plugins in priority order.
// npm-lock is registered before npm-package; the latter implements
// ConditionalPlugin to skip directories where a lock file is present.
func builtins() []EcosystemPlugin {
	return []EcosystemPlugin{
		simpleParser{name: "go", patterns: []string{"go.mod"}, fn: wrap(parser.ParseGoMod)},
		simpleParser{name: "python", patterns: []string{"requirements.txt"}, fn: wrap(parser.ParseRequirements)},
		cargoPlugin{},
		simpleParser{name: "maven", patterns: []string{"pom.xml"}, fn: wrap(parser.ParsePomXML)},
		simpleParser{name: "nuget-config", patterns: []string{"packages.config"}, fn: wrap(parser.ParsePackagesConfig)},
		npmLockPlugin{},
		npmPackagePlugin{},
		csprojPlugin{},
		simpleParser{name: "ruby", patterns: []string{"Gemfile.lock"}, fn: wrap(parser.ParseGemfileLock)},
		simpleParser{name: "php", patterns: []string{"composer.lock"}, fn: wrap(parser.ParseComposerLock)},
	}
}

// simpleParser wraps a parse function that follows the standard signature.
type simpleParser struct {
	name     string
	patterns []string
	fn       func(string) ([]Dependency, error)
}

func (p simpleParser) Name() string                            { return p.name }
func (p simpleParser) FilePatterns() []string                  { return p.patterns }
func (p simpleParser) Parse(path string) ([]Dependency, error) { return p.fn(path) }

// wrap converts a parser function returning []parser.Dependency to one
// returning []Dependency, which is the public plugin type.
func wrap(fn func(string) ([]parser.Dependency, error)) func(string) ([]Dependency, error) {
	return func(path string) ([]Dependency, error) {
		deps, err := fn(path)
		if err != nil {
			return nil, err
		}
		return convertDeps(deps), nil
	}
}

func convertDeps(in []parser.Dependency) []Dependency {
	out := make([]Dependency, len(in))
	for i, d := range in {
		out[i] = Dependency{Name: d.Name, Version: d.Version, Ecosystem: d.Ecosystem, Direct: d.Direct}
	}
	return out
}

// npmLockPlugin parses package-lock.json (preferred over package.json).
type npmLockPlugin struct{}

func (npmLockPlugin) Name() string           { return "npm-lock" }
func (npmLockPlugin) FilePatterns() []string { return []string{"package-lock.json"} }
func (npmLockPlugin) Parse(path string) ([]Dependency, error) {
	deps, err := parser.ParsePackageLockJSON(path)
	return convertDeps(deps), err
}

// npmPackagePlugin parses package.json but skips directories where
// package-lock.json already exists (handled by npmLockPlugin).
type npmPackagePlugin struct{}

func (npmPackagePlugin) Name() string           { return "npm-package" }
func (npmPackagePlugin) FilePatterns() []string { return []string{"package.json"} }
func (npmPackagePlugin) SkipDir(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "package-lock.json"))
	return err == nil
}
func (npmPackagePlugin) Parse(path string) ([]Dependency, error) {
	deps, err := parser.ParsePackageJSON(path)
	return convertDeps(deps), err
}

// cargoPlugin parses Rust projects. It prefers Cargo.lock when present
// (which includes transitive deps), falling back to Cargo.toml (direct
// deps only). When both exist, Cargo.toml is used to tag direct deps.
type cargoPlugin struct{}

func (cargoPlugin) Name() string           { return "rust" }
func (cargoPlugin) FilePatterns() []string { return []string{"Cargo.lock", "Cargo.toml"} }
func (cargoPlugin) Parse(path string) ([]Dependency, error) {
	base := filepath.Base(path)
	dir := filepath.Dir(path)

	if base == "Cargo.toml" {
		// Only reached when no Cargo.lock exists (SkipDir would have filtered
		// the Cargo.toml match if Cargo.lock were present — but we don't
		// implement SkipDir here; instead ParseDir calls us for each match in
		// order, so we may be called for both files). If Cargo.lock is present
		// alongside this Cargo.toml, skip to avoid duplicates.
		if _, err := os.Stat(filepath.Join(dir, "Cargo.lock")); err == nil {
			return nil, nil
		}
		deps, err := parser.ParseCargoToml(path)
		return convertDeps(deps), err
	}

	// Cargo.lock — all packages; mark direct ones using Cargo.toml.
	deps, err := parser.ParseCargoLock(path)
	if err != nil {
		return nil, err
	}
	// Build direct set from Cargo.toml if it exists alongside the lock.
	if manifest, merr := parser.ParseCargoToml(filepath.Join(dir, "Cargo.toml")); merr == nil {
		direct := make(map[string]bool, len(manifest))
		for _, d := range manifest {
			direct[d.Name] = true
		}
		for i := range deps {
			deps[i].Direct = direct[deps[i].Name]
		}
	}
	return convertDeps(deps), nil
}

// csprojPlugin parses .NET .csproj project files (glob pattern).
type csprojPlugin struct{}

func (csprojPlugin) Name() string           { return "nuget-csproj" }
func (csprojPlugin) FilePatterns() []string { return []string{"*.csproj"} }
func (csprojPlugin) Parse(path string) ([]Dependency, error) {
	deps, err := parser.ParseCsproj(path)
	return convertDeps(deps), err
}
