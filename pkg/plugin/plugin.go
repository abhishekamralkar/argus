// Package plugin defines the stable public interface for Argus ecosystem parsers.
// Both built-in parsers and community-contributed plugins implement [EcosystemPlugin].
//
// # Writing a plugin
//
// A plugin is a Go shared library (.so) that exports a symbol named "Plugin"
// of type EcosystemPlugin. Compile with:
//
//	go build -buildmode=plugin -o myplugin.so .
//
// Drop the .so into ~/.argus/plugins/ and it is loaded automatically.
//
// # Minimal plugin skeleton
//
//	package main
//
//	import "github.com/abhishekamralkar/argus/pkg/plugin"
//
//	type myParser struct{}
//
//	func (myParser) Name() string                               { return "myeco" }
//	func (myParser) FilePatterns() []string                     { return []string{"myfile.lock"} }
//	func (myParser) Parse(path string) ([]plugin.Dependency, error) { ... }
//
//	var Plugin myParser
package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	goPlugin "plugin"
)

// Dependency represents a single resolved software dependency.
// This is the canonical type shared between built-in parsers and external plugins.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
}

// EcosystemPlugin is the interface all ecosystem parsers must implement.
type EcosystemPlugin interface {
	// Name returns the ecosystem identifier, e.g. "go", "python", "ruby".
	Name() string
	// FilePatterns returns glob patterns (relative to project root) this parser handles,
	// e.g. ["go.mod"] or ["*.csproj"].
	FilePatterns() []string
	// Parse reads the dependency file at path and returns its dependencies.
	Parse(path string) ([]Dependency, error)
}

// ConditionalPlugin is an optional extension of EcosystemPlugin. When implemented,
// ParseDir calls SkipDir before processing any files, allowing a plugin to defer
// to a higher-priority plugin (e.g. skip package.json when package-lock.json exists).
type ConditionalPlugin interface {
	EcosystemPlugin
	SkipDir(dir string) bool
}

// Registry holds all registered ecosystem plugins, built-in and external.
type Registry struct {
	plugins []EcosystemPlugin
}

// NewRegistry returns a Registry pre-populated with all built-in parsers.
func NewRegistry() *Registry {
	r := &Registry{}
	for _, p := range builtins() {
		r.Register(p)
	}
	return r
}

// Register adds p to the registry. Plugins are queried in registration order.
func (r *Registry) Register(p EcosystemPlugin) {
	r.plugins = append(r.plugins, p)
}

// All returns every registered plugin in registration order.
func (r *Registry) All() []EcosystemPlugin {
	out := make([]EcosystemPlugin, len(r.plugins))
	copy(out, r.plugins)
	return out
}

// LoadDir loads Go plugin (.so) files from dir. Each .so must export a symbol
// named "Plugin" that implements EcosystemPlugin. A missing directory is not an
// error; individual load failures are printed to stderr and skipped.
func (r *Registry) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".so" {
			continue
		}
		if err := r.loadSO(filepath.Join(dir, e.Name())); err != nil {
			fmt.Fprintf(os.Stderr, "warning: load plugin %s: %v\n", e.Name(), err)
		}
	}
	return nil
}

func (r *Registry) loadSO(path string) error {
	p, err := goPlugin.Open(path)
	if err != nil {
		return err
	}
	sym, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("missing exported symbol 'Plugin': %w", err)
	}
	switch v := sym.(type) {
	case EcosystemPlugin:
		r.Register(v)
	case *EcosystemPlugin:
		r.Register(*v)
	default:
		return fmt.Errorf("symbol 'Plugin' does not implement EcosystemPlugin")
	}
	return nil
}

// ParseDir detects and parses all dependency files under dir using every
// registered plugin. Plugin FilePatterns are glob-matched against dir.
func (r *Registry) ParseDir(dir string) ([]Dependency, error) {
	var all []Dependency
	for _, p := range r.plugins {
		if cp, ok := p.(ConditionalPlugin); ok && cp.SkipDir(dir) {
			continue
		}
		for _, pattern := range p.FilePatterns() {
			matches, err := filepath.Glob(filepath.Join(dir, pattern))
			if err != nil {
				continue
			}
			for _, path := range matches {
				deps, err := p.Parse(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "parse %s (%s): %v\n", filepath.Base(path), p.Name(), err)
					continue
				}
				all = append(all, deps...)
			}
		}
	}
	return all, nil
}

// DefaultPluginDir returns the default directory from which external plugins
// are loaded: $HOME/.argus/plugins.
func DefaultPluginDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".argus", "plugins")
}

// containsGlob reports whether s contains any glob metacharacter.
func containsGlob(s string) bool {
	for _, c := range s {
		if c == '*' || c == '?' || c == '[' {
			return true
		}
	}
	return false
}

// DepFileNames returns exact filenames (no globs) that signal a project root,
// derived from the registered built-in plugins. Used by multi-scan walking.
func DepFileNames() map[string]bool {
	names := make(map[string]bool)
	for _, p := range builtins() {
		for _, pat := range p.FilePatterns() {
			if !containsGlob(pat) {
				names[pat] = true
			}
		}
	}
	return names
}

// DepGlobPatterns returns file patterns that require glob expansion (e.g. "*.csproj"),
// derived from the registered built-in plugins. Used by multi-scan walking.
func DepGlobPatterns() []string {
	var out []string
	for _, p := range builtins() {
		for _, pat := range p.FilePatterns() {
			if containsGlob(pat) {
				out = append(out, pat)
			}
		}
	}
	return out
}
