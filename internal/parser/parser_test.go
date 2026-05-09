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

func TestParsePomXML(t *testing.T) {
	deps, err := parser.ParsePomXML("testdata/pom.xml")
	if err != nil {
		t.Fatalf("ParsePomXML: %v", err)
	}

	byName := index(deps)

	cases := []struct{ name, version string }{
		{"com.google.guava:guava", "32.1.2-jre"},
		{"org.springframework:spring-core", "5.3.27"}, // from dependencyManagement
		{"log4j:log4j", "1.2.14"},                     // lower bound of range
		{"junit:junit", "4.13.2"},
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
		if d.Ecosystem != "maven" {
			t.Errorf("%s: want ecosystem maven, got %s", c.name, d.Ecosystem)
		}
	}
}

func TestParseCsproj(t *testing.T) {
	deps, err := parser.ParseCsproj("testdata/test.csproj")
	if err != nil {
		t.Fatalf("ParseCsproj: %v", err)
	}

	byName := index(deps)

	cases := []struct{ name, version string }{
		{"Newtonsoft.Json", "13.0.3"},
		{"Microsoft.Extensions.Logging", "7.0.0"},
		{"Dapper", "2.0.151"},
		{"xunit", "2.5.3"},
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
		if d.Ecosystem != "nuget" {
			t.Errorf("%s: want ecosystem nuget, got %s", c.name, d.Ecosystem)
		}
	}
}

func TestParsePackagesConfig(t *testing.T) {
	deps, err := parser.ParsePackagesConfig("testdata/packages.config")
	if err != nil {
		t.Fatalf("ParsePackagesConfig: %v", err)
	}

	byName := index(deps)

	cases := []struct{ name, version string }{
		{"Newtonsoft.Json", "13.0.3"},
		{"log4net", "2.0.15"},
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
		if d.Ecosystem != "nuget" {
			t.Errorf("%s: want ecosystem nuget, got %s", c.name, d.Ecosystem)
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
