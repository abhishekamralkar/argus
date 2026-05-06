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
