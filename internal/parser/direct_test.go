package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseGoMod_DirectFlag verifies that go.mod deps without "// indirect"
// are marked Direct: true and deps with "// indirect" are marked Direct: false.
func TestParseGoMod_DirectFlag(t *testing.T) {
	deps, err := ParseGoMod("testdata/go.mod")
	if err != nil {
		t.Fatalf("ParseGoMod: %v", err)
	}
	byName := make(map[string]Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	cases := []struct {
		name   string
		direct bool
	}{
		{"github.com/gin-gonic/gin", true},
		{"github.com/spf13/cobra", true},
		{"github.com/stretchr/testify", true},
		{"golang.org/x/crypto", false}, // marked // indirect
	}
	for _, c := range cases {
		d, ok := byName[c.name]
		if !ok {
			t.Errorf("missing dep %s", c.name)
			continue
		}
		if d.Direct != c.direct {
			t.Errorf("%s: Direct=%v, want %v", c.name, d.Direct, c.direct)
		}
	}
}

// TestParseGemfileLock_DirectFlag verifies that gems listed in the
// DEPENDENCIES section are marked Direct: true.
func TestParseGemfileLock_DirectFlag(t *testing.T) {
	deps, err := ParseGemfileLock("testdata/Gemfile.lock")
	if err != nil {
		t.Fatalf("ParseGemfileLock: %v", err)
	}
	byName := make(map[string]Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	// Gemfile.lock DEPENDENCIES section: activesupport, nokogiri, rack
	directGems := []string{"activesupport", "nokogiri", "rack"}
	for _, name := range directGems {
		d, ok := byName[name]
		if !ok {
			t.Errorf("missing gem %s", name)
			continue
		}
		if !d.Direct {
			t.Errorf("%s should be Direct=true (listed in DEPENDENCIES)", name)
		}
	}

	// Transitive gems (not in DEPENDENCIES): concurrent-ruby, i18n, minitest, tzinfo
	transitiveGems := []string{"concurrent-ruby", "i18n", "minitest", "tzinfo"}
	for _, name := range transitiveGems {
		d, ok := byName[name]
		if !ok {
			t.Errorf("missing gem %s", name)
			continue
		}
		if d.Direct {
			t.Errorf("%s should be Direct=false (not in DEPENDENCIES)", name)
		}
	}
}

// TestParseCargoLock returns all packages from Cargo.lock.
func TestParseCargoLock(t *testing.T) {
	deps, err := ParseCargoLock("testdata/Cargo.lock")
	if err != nil {
		t.Fatalf("ParseCargoLock: %v", err)
	}

	byName := make(map[string]Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	want := map[string]string{
		"anyhow":       "1.0.75",
		"libc":         "0.2.147",
		"myapp":        "0.1.0",
		"proc-macro2":  "1.0.67",
		"serde":        "1.0.193",
		"serde_derive": "1.0.193",
	}
	for name, version := range want {
		d, ok := byName[name]
		if !ok {
			t.Errorf("missing package %s", name)
			continue
		}
		if d.Version != version {
			t.Errorf("%s: version=%s, want %s", name, d.Version, version)
		}
		if d.Ecosystem != "rust" {
			t.Errorf("%s: ecosystem=%s, want rust", name, d.Ecosystem)
		}
	}
}

// TestParseCargoLock_NotFound returns an error for a missing file.
func TestParseCargoLock_NotFound(t *testing.T) {
	_, err := ParseCargoLock("testdata/nonexistent.lock")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// TestParsePackageLockJSON_DirectFlag verifies that the root package's
// dependencies are tagged Direct: true in v2/v3 format.
func TestParsePackageLockJSON_DirectFlag(t *testing.T) {
	content := `{
  "lockfileVersion": 2,
  "packages": {
    "": {
      "dependencies": {"express": "^4.18.0"},
      "devDependencies": {"jest": "^29.0.0"}
    },
    "node_modules/express": {"version": "4.18.2"},
    "node_modules/jest": {"version": "29.3.1"},
    "node_modules/mime": {"version": "1.6.0"}
  }
}`
	tmp := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	deps, err := ParsePackageLockJSON(tmp)
	if err != nil {
		t.Fatalf("ParsePackageLockJSON: %v", err)
	}
	byName := make(map[string]Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}

	if !byName["express"].Direct {
		t.Error("express should be Direct=true (in root dependencies)")
	}
	if !byName["jest"].Direct {
		t.Error("jest should be Direct=true (in root devDependencies)")
	}
	if byName["mime"].Direct {
		t.Error("mime should be Direct=false (transitive, not in root)")
	}
}
