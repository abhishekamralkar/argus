package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate_Valid(t *testing.T) {
	cases := []Config{
		{},
		{Workers: 8, MinSeverity: "HIGH", Ecosystems: "go,python"},
		{ChunkSize: 512, ChunkOverlap: 64},
		{MinSeverity: "CRITICAL"},
	}
	for _, c := range cases {
		if err := c.Validate(); err != nil {
			t.Errorf("Validate(%+v) unexpected error: %v", c, err)
		}
	}
}

func TestValidate_Invalid(t *testing.T) {
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{Workers: -1}, "workers must be >= 0"},
		{Config{MinSeverity: "EXTREME"}, "min_severity"},
		{Config{Ecosystems: "go,java"}, "unknown ecosystem"},
		{Config{ChunkSize: -5}, "chunk_size must be >= 0"},
		{Config{ChunkOverlap: -1}, "chunk_overlap must be >= 0"},
		{Config{ChunkSize: 100, ChunkOverlap: 100}, "chunk_overlap must be < chunk_size"},
	}
	for _, tt := range cases {
		err := tt.cfg.Validate()
		if err == nil {
			t.Errorf("Validate(%+v) expected error containing %q, got nil", tt.cfg, tt.want)
			continue
		}
		if !containsStr(err.Error(), tt.want) {
			t.Errorf("Validate(%+v) error = %q, want it to contain %q", tt.cfg, err.Error(), tt.want)
		}
	}
}

func TestLoad_FileNotExist(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load non-existent: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil Config")
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	content := "workers: 4\nmin_severity: HIGH\n"
	if err := os.WriteFile(filepath.Join(dir, ".argus.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Workers != 4 {
		t.Errorf("Workers = %d, want 4", cfg.Workers)
	}
	if cfg.MinSeverity != "HIGH" {
		t.Errorf("MinSeverity = %q, want HIGH", cfg.MinSeverity)
	}
}

func TestLoad_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".argus.yaml"), []byte("workers: -3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for invalid config, got nil")
	}
}

func containsStr(s, sub string) bool { return strings.Contains(s, sub) }

// ── Profile tests ─────────────────────────────────────────────────────────────

func TestBuiltinProfiles_PresentAndValid(t *testing.T) {
	expected := []string{"default", "fast", "ci", "thorough"}
	cfg := &Config{}
	for _, name := range expected {
		p, ok := cfg.ResolveProfile(name)
		if !ok {
			t.Errorf("built-in profile %q not found", name)
			continue
		}
		if err := p.validate(); err != nil {
			t.Errorf("built-in profile %q invalid: %v", name, err)
		}
	}
}

func TestResolveProfile_UserDefined(t *testing.T) {
	cfg := &Config{
		Profiles: map[string]Profile{
			"myprofile": {Workers: 6, TopK: 15},
		},
	}
	p, ok := cfg.ResolveProfile("myprofile")
	if !ok {
		t.Fatal("user-defined profile not found")
	}
	if p.Workers != 6 {
		t.Errorf("Workers = %d, want 6", p.Workers)
	}
}

func TestResolveProfile_UserOverridesBuiltin(t *testing.T) {
	cfg := &Config{
		Profiles: map[string]Profile{
			"fast": {Workers: 99},
		},
	}
	p, ok := cfg.ResolveProfile("fast")
	if !ok {
		t.Fatal("profile not found")
	}
	if p.Workers != 99 {
		t.Errorf("user profile should override built-in: Workers = %d, want 99", p.Workers)
	}
}

func TestResolveProfile_Unknown(t *testing.T) {
	cfg := &Config{}
	_, ok := cfg.ResolveProfile("nonexistent")
	if ok {
		t.Error("ResolveProfile should return false for unknown profile")
	}
}

func TestResolveProfile_EmptyName(t *testing.T) {
	cfg := &Config{}
	_, ok := cfg.ResolveProfile("")
	if ok {
		t.Error("ResolveProfile should return false for empty name")
	}
}

func TestAllProfileNames_ContainsBuiltins(t *testing.T) {
	cfg := &Config{
		Profiles: map[string]Profile{
			"custom": {Workers: 3},
		},
	}
	names := cfg.AllProfileNames()
	want := map[string]bool{"default": true, "fast": true, "ci": true, "thorough": true, "custom": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) > 0 {
		t.Errorf("AllProfileNames missing: %v", want)
	}
	// Verify sorted.
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("AllProfileNames not sorted: %v", names)
			break
		}
	}
}

func TestValidate_InvalidProfile(t *testing.T) {
	cfg := Config{
		Profiles: map[string]Profile{
			"bad": {Workers: -1},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for profile with workers=-1, got nil")
	}
	if !containsStr(err.Error(), "profile") {
		t.Errorf("error should mention 'profile', got: %v", err)
	}
}

func TestLoad_ProfilesFromFile(t *testing.T) {
	dir := t.TempDir()
	content := `
default_profile: fast
profiles:
  fast:
    workers: 12
    top_k: 8
    min_severity: HIGH
`
	if err := os.WriteFile(filepath.Join(dir, ".argus.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultProfile != "fast" {
		t.Errorf("DefaultProfile = %q, want fast", cfg.DefaultProfile)
	}
	p, ok := cfg.ResolveProfile("fast")
	if !ok {
		t.Fatal("profile 'fast' not found after load")
	}
	if p.Workers != 12 {
		t.Errorf("Workers = %d, want 12", p.Workers)
	}
	if p.TopK != 8 {
		t.Errorf("TopK = %d, want 8", p.TopK)
	}
}
