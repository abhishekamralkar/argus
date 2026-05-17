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
		simpleParser{name: "python-poetry", patterns: []string{"poetry.lock"}, fn: wrap(parser.ParsePoetryLock)},
		simpleParser{name: "python-uv", patterns: []string{"uv.lock"}, fn: wrap(parser.ParseUVLock)},
		simpleParser{name: "python-pipfile", patterns: []string{"Pipfile.lock"}, fn: wrap(parser.ParsePipfileLock)},
		simpleParser{name: "rust", patterns: []string{"Cargo.toml"}, fn: wrap(parser.ParseCargoToml)},
		simpleParser{name: "maven", patterns: []string{"pom.xml"}, fn: wrap(parser.ParsePomXML)},
		simpleParser{name: "nuget-config", patterns: []string{"packages.config"}, fn: wrap(parser.ParsePackagesConfig)},
		npmLockPlugin{},
		npmPackagePlugin{},
		csprojPlugin{},
		simpleParser{name: "ruby", patterns: []string{"Gemfile.lock"}, fn: wrap(parser.ParseGemfileLock)},
		simpleParser{name: "php", patterns: []string{"composer.lock"}, fn: wrap(parser.ParseComposerLock)},
		simpleParser{name: "swift-cocoapods", patterns: []string{"Podfile.lock"}, fn: wrap(parser.ParsePodfileLock)},
		simpleParser{name: "swift-spm", patterns: []string{"Package.resolved"}, fn: wrap(parser.ParsePackageResolved)},
		simpleParser{name: "dart", patterns: []string{"pubspec.lock"}, fn: wrap(parser.ParsePubspecLock)},
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
		out[i] = Dependency{Name: d.Name, Version: d.Version, Ecosystem: d.Ecosystem}
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

// csprojPlugin parses .NET .csproj project files (glob pattern).
type csprojPlugin struct{}

func (csprojPlugin) Name() string           { return "nuget-csproj" }
func (csprojPlugin) FilePatterns() []string { return []string{"*.csproj"} }
func (csprojPlugin) Parse(path string) ([]Dependency, error) {
	deps, err := parser.ParseCsproj(path)
	return convertDeps(deps), err
}
