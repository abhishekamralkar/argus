package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGemfileLock(t *testing.T) {
	deps, err := ParseGemfileLock("testdata/Gemfile.lock")
	if err != nil {
		t.Fatalf("ParseGemfileLock: %v", err)
	}

	// Expect all top-level specs: activesupport, concurrent-ruby, i18n,
	// minitest, nokogiri, racc, rack, tzinfo (8 gems).
	want := map[string]string{
		"activesupport":   "7.0.4",
		"concurrent-ruby": "1.2.2",
		"i18n":            "1.14.1",
		"minitest":        "5.20.0",
		"nokogiri":        "1.16.0",
		"racc":            "1.7.3",
		"rack":            "3.0.8",
		"tzinfo":          "2.0.6",
	}
	if len(deps) != len(want) {
		t.Errorf("expected %d deps, got %d: %v", len(want), len(deps), deps)
	}
	for _, d := range deps {
		if d.Ecosystem != "ruby" {
			t.Errorf("ecosystem: want ruby, got %s", d.Ecosystem)
		}
		wantVer, ok := want[d.Name]
		if !ok {
			t.Errorf("unexpected gem %q", d.Name)
			continue
		}
		if d.Version != wantVer {
			t.Errorf("gem %s: want version %s, got %s", d.Name, wantVer, d.Version)
		}
	}
}

func TestParseGemfileLock_SubdependenciesExcluded(t *testing.T) {
	deps, err := ParseGemfileLock("testdata/Gemfile.lock")
	if err != nil {
		t.Fatalf("ParseGemfileLock: %v", err)
	}
	// Sub-dependency constraints like "concurrent-ruby (~> 1.0)" under activesupport
	// must NOT be included as separate entries.
	names := make(map[string]int)
	for _, d := range deps {
		names[d.Name]++
	}
	for name, count := range names {
		if count > 1 {
			t.Errorf("gem %q appears %d times, expected once", name, count)
		}
	}
}

func TestParseGemfileLock_MultipleSpecsSections(t *testing.T) {
	// A Gemfile.lock with both a GEM and a PATH section, each with a specs block.
	content := `GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.8)

PATH
  remote: .
  specs:
    myapp (0.1.0)
      rack

PLATFORMS
  ruby

DEPENDENCIES
  myapp!
`
	tmp := filepath.Join(t.TempDir(), "Gemfile.lock")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	deps, err := ParseGemfileLock(tmp)
	if err != nil {
		t.Fatalf("ParseGemfileLock: %v", err)
	}
	if len(deps) != 2 {
		t.Errorf("expected 2 deps (rack + myapp), got %d: %v", len(deps), deps)
	}
}

func TestParseGemfileLock_Empty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "Gemfile.lock")
	if err := os.WriteFile(tmp, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	deps, err := ParseGemfileLock(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestParseGemfileLock_NotFound(t *testing.T) {
	_, err := ParseGemfileLock("testdata/nonexistent.lock")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
