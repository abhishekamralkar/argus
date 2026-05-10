package plugin_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abhishekamralkar/argus/pkg/plugin"
)

// ── Registry ─────────────────────────────────────────────────────────────────

func TestNewRegistry_HasBuiltins(t *testing.T) {
	r := plugin.NewRegistry()
	if len(r.All()) == 0 {
		t.Fatal("expected built-in plugins, got none")
	}
}

func TestRegistry_Register(t *testing.T) {
	r := &plugin.Registry{}
	r.Register(stubPlugin{name: "test", patterns: []string{"test.lock"}})
	if len(r.All()) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(r.All()))
	}
}

func TestRegistry_All_ReturnsCopy(t *testing.T) {
	r := plugin.NewRegistry()
	a := r.All()
	b := r.All()
	if &a[0] == &b[0] {
		t.Error("All() should return a copy, not share the backing array")
	}
}

// ── ParseDir ──────────────────────────────────────────────────────────────────

func TestParseDir_GoMod(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/hello\ngo 1.21\n\nrequire github.com/stretchr/testify v1.8.4\n")

	r := plugin.NewRegistry()
	deps, err := r.ParseDir(dir)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	if len(deps) == 0 {
		t.Fatal("expected at least one dependency from go.mod")
	}
	for _, d := range deps {
		if d.Ecosystem != "go" {
			t.Errorf("expected ecosystem go, got %s", d.Ecosystem)
		}
	}
}

func TestParseDir_NpmPreferLock(t *testing.T) {
	dir := t.TempDir()
	// Write both package-lock.json and package.json; lock file should win.
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/express": {"version": "4.18.2", "resolved": ""}
		}
	}`)
	writeFile(t, filepath.Join(dir, "package.json"), `{"dependencies": {"express": "^4.0.0"}}`)

	r := plugin.NewRegistry()
	deps, err := r.ParseDir(dir)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	// Count unique package names — "express" should appear exactly once.
	names := make(map[string]int)
	for _, d := range deps {
		names[d.Name]++
	}
	if names["express"] != 1 {
		t.Errorf("express count = %d, want 1 (lock file should win over package.json)", names["express"])
	}
}

func TestParseDir_NpmFallsBackToPackageJSON(t *testing.T) {
	dir := t.TempDir()
	// Only package.json, no lock file.
	writeFile(t, filepath.Join(dir, "package.json"), `{"dependencies": {"lodash": "^4.17.21"}}`)

	r := plugin.NewRegistry()
	deps, err := r.ParseDir(dir)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	found := false
	for _, d := range deps {
		if d.Name == "lodash" {
			found = true
		}
	}
	if !found {
		t.Error("expected lodash from package.json fallback")
	}
}

func TestParseDir_NoDepFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "README.md"), "# hello")

	r := plugin.NewRegistry()
	deps, err := r.ParseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestParseDir_CustomPlugin(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "custom.lock"), "mypkg 1.2.3\n")

	r := plugin.NewRegistry()
	r.Register(stubPlugin{
		name:     "custom",
		patterns: []string{"custom.lock"},
		deps:     []plugin.Dependency{{Name: "mypkg", Version: "1.2.3", Ecosystem: "custom"}},
	})

	deps, err := r.ParseDir(dir)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	found := false
	for _, d := range deps {
		if d.Name == "mypkg" && d.Ecosystem == "custom" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom plugin dep")
	}
}

// ── LoadDir ───────────────────────────────────────────────────────────────────

func TestLoadDir_MissingDir(t *testing.T) {
	r := plugin.NewRegistry()
	// Non-existent directory must not return an error.
	if err := r.LoadDir(filepath.Join(t.TempDir(), "nonexistent")); err != nil {
		t.Errorf("LoadDir with missing dir returned error: %v", err)
	}
}

// ── helpers and DepFileNames ──────────────────────────────────────────────────

func TestDepFileNames_ContainsExpected(t *testing.T) {
	names := plugin.DepFileNames()
	expected := []string{"go.mod", "requirements.txt", "Cargo.toml", "pom.xml", "Gemfile.lock"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("DepFileNames missing %q", name)
		}
	}
}

func TestDepFileNames_NoGlobs(t *testing.T) {
	for name := range plugin.DepFileNames() {
		for _, c := range name {
			if c == '*' || c == '?' || c == '[' {
				t.Errorf("DepFileNames should not contain globs, but %q has one", name)
			}
		}
	}
}

func TestDepGlobPatterns_ContainsCsproj(t *testing.T) {
	found := false
	for _, pat := range plugin.DepGlobPatterns() {
		if pat == "*.csproj" {
			found = true
		}
	}
	if !found {
		t.Error("DepGlobPatterns missing *.csproj")
	}
}

// ── DefaultPluginDir ──────────────────────────────────────────────────────────

func TestDefaultPluginDir_NonEmpty(t *testing.T) {
	if plugin.DefaultPluginDir() == "" {
		t.Error("DefaultPluginDir returned empty string")
	}
}

// ── stub helpers ─────────────────────────────────────────────────────────────

type stubPlugin struct {
	name     string
	patterns []string
	deps     []plugin.Dependency
}

func (s stubPlugin) Name() string                                { return s.name }
func (s stubPlugin) FilePatterns() []string                      { return s.patterns }
func (s stubPlugin) Parse(_ string) ([]plugin.Dependency, error) { return s.deps, nil }

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
