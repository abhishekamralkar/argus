package parser_test

import (
	"testing"

	"github.com/abhishekamralkar/argus/internal/parser"
)

func TestParseGoMod(t *testing.T) {
	deps, err := parser.ParseGoMod("testdata/go.mod")
	if err != nil {
		t.Fatalf("ParseGoMod: %v", err)
	}

	byName := index(deps)

	cases := []struct{ name, version string }{
		{"github.com/gin-gonic/gin", "1.9.1"},
		{"golang.org/x/crypto", "0.0.0-20190308221718-c2843e01d9a2"},
		{"github.com/spf13/cobra", "1.8.0"},
		{"github.com/stretchr/testify", "1.8.4"},
	}
	for _, c := range cases {
		d, ok := byName[c.name]
		if !ok {
			t.Errorf("missing dependency %s", c.name)
			continue
		}
		if d.Version != c.version {
			t.Errorf("%s: want version %s, got %s", c.name, c.version, d.Version)
		}
		if d.Ecosystem != "go" {
			t.Errorf("%s: want ecosystem go, got %s", c.name, d.Ecosystem)
		}
	}
}

func TestParseRequirements(t *testing.T) {
	deps, err := parser.ParseRequirements("testdata/requirements.txt")
	if err != nil {
		t.Fatalf("ParseRequirements: %v", err)
	}

	byName := index(deps)

	cases := []struct{ name, version string }{
		{"flask", "2.3.2"},
		{"requests", "2.28.0"},
		{"cryptography", "41.0.4"},
		{"numpy", ""},
	}
	for _, c := range cases {
		d, ok := byName[c.name]
		if !ok {
			t.Errorf("missing dependency %s", c.name)
			continue
		}
		if d.Version != c.version {
			t.Errorf("%s: want version %q, got %q", c.name, c.version, d.Version)
		}
		if d.Ecosystem != "python" {
			t.Errorf("%s: want ecosystem python, got %s", c.name, d.Ecosystem)
		}
	}

	// -r lines should be ignored
	if _, ok := byName["-r"]; ok {
		t.Error("-r line should not appear as a dependency")
	}
}

func TestParseCargoToml(t *testing.T) {
	deps, err := parser.ParseCargoToml("testdata/Cargo.toml")
	if err != nil {
		t.Fatalf("ParseCargoToml: %v", err)
	}

	byName := index(deps)

	cases := []struct{ name, version string }{
		{"serde", "1.0"},
		{"tokio", "1.28"},
		{"reqwest", "0.11"},
		{"criterion", "0.5"},
	}
	for _, c := range cases {
		d, ok := byName[c.name]
		if !ok {
			t.Errorf("missing dependency %s", c.name)
			continue
		}
		if d.Version != c.version {
			t.Errorf("%s: want version %s, got %s", c.name, c.version, d.Version)
		}
		if d.Ecosystem != "rust" {
			t.Errorf("%s: want ecosystem rust, got %s", c.name, d.Ecosystem)
		}
	}
}

func TestParseRequirements_SkipsComments(t *testing.T) {
	deps, err := parser.ParseRequirements("testdata/requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range deps {
		if d.Name == "" {
			t.Error("dependency with empty name should be filtered out")
		}
	}
}

func TestParseGoMod_EcosystemIsGo(t *testing.T) {
	deps, err := parser.ParseGoMod("testdata/go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range deps {
		if d.Ecosystem != "go" {
			t.Errorf("expected ecosystem 'go', got %q for %s", d.Ecosystem, d.Name)
		}
	}
}

func TestParsePackageJSON(t *testing.T) {
	deps, err := parser.ParsePackageJSON("testdata/package.json")
	if err != nil {
		t.Fatalf("ParsePackageJSON: %v", err)
	}

	byName := index(deps)

	cases := []struct{ name, version string }{
		{"express", "4.18.2"},   // ^ stripped
		{"lodash", "4.17.21"},   // ~ stripped
		{"axios", "1.4.0"},      // >= stripped
		{"jest", "29.0.0"},      // ^ stripped (devDep)
		{"eslint", "8.0.0"},     // exact (devDep)
	}
	for _, c := range cases {
		d, ok := byName[c.name]
		if !ok {
			t.Errorf("missing dependency %s", c.name)
			continue
		}
		if d.Version != c.version {
			t.Errorf("%s: want version %s, got %s", c.name, c.version, d.Version)
		}
		if d.Ecosystem != "npm" {
			t.Errorf("%s: want ecosystem npm, got %s", c.name, d.Ecosystem)
		}
	}
}

func TestParsePackageLockJSON(t *testing.T) {
	deps, err := parser.ParsePackageLockJSON("testdata/package-lock.json")
	if err != nil {
		t.Fatalf("ParsePackageLockJSON: %v", err)
	}

	byName := index(deps)

	cases := []struct{ name, version string }{
		{"express", "4.18.2"},
		{"lodash", "4.17.21"},
	}
	for _, c := range cases {
		d, ok := byName[c.name]
		if !ok {
			t.Errorf("missing dependency %s", c.name)
			continue
		}
		if d.Version != c.version {
			t.Errorf("%s: want version %s, got %s", c.name, c.version, d.Version)
		}
		if d.Ecosystem != "npm" {
			t.Errorf("%s: want ecosystem npm, got %s", c.name, d.Ecosystem)
		}
	}
	// Root package entry ("" key) must not appear
	if _, ok := byName[""]; ok {
		t.Error("root package entry should be filtered out")
	}
}

func TestStripNPMRange(t *testing.T) {
	cases := []struct{ in, want string }{
		{"^4.18.2", "4.18.2"},
		{"~4.17.21", "4.17.21"},
		{">=1.4.0", "1.4.0"},
		{">1.0.0", "1.0.0"},
		{"<=2.0.0", "2.0.0"},
		{"<3.0.0", "3.0.0"},
		{"=1.2.3", "1.2.3"},
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"latest", "latest"},
	}
	for _, c := range cases {
		got := parser.StripNPMRange(c.in)
		if got != c.want {
			t.Errorf("StripNPMRange(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// index builds a name → Dependency map; last write wins for duplicates.
func index(deps []parser.Dependency) map[string]parser.Dependency {
	m := make(map[string]parser.Dependency, len(deps))
	for _, d := range deps {
		m[d.Name] = d
	}
	return m
}
