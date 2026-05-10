package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// ── resolveMultiDirs ──────────────────────────────────────────────────────────

func TestResolveMultiDirs_ExplicitPaths(t *testing.T) {
	dirs, err := resolveMultiDirs([]string{"./a", "./b", "./c"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 3 {
		t.Fatalf("expected 3 dirs, got %d: %v", len(dirs), dirs)
	}
}

func TestResolveMultiDirs_Dedup(t *testing.T) {
	dirs, err := resolveMultiDirs([]string{"./a", "./b", "./a"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 2 {
		t.Fatalf("expected 2 after dedup, got %d: %v", len(dirs), dirs)
	}
	if dirs[0] != "./a" || dirs[1] != "./b" {
		t.Errorf("order not preserved: %v", dirs)
	}
}

func TestResolveMultiDirs_DotDotDot(t *testing.T) {
	root := t.TempDir()
	// Create two sub-projects with dep files.
	for _, sub := range []struct{ dir, file string }{
		{"svc/auth", "go.mod"},
		{"svc/api", "requirements.txt"},
	} {
		dir := filepath.Join(root, sub.dir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, sub.file), []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	dirs, err := resolveMultiDirs([]string{root + "/..."})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 2 {
		t.Fatalf("expected 2 projects, got %d: %v", len(dirs), dirs)
	}
}

func TestResolveMultiDirs_DotDotDotNoDeps(t *testing.T) {
	root := t.TempDir()
	// No dep files — should return empty slice.
	dirs, err := resolveMultiDirs([]string{root + "/..."})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 0 {
		t.Fatalf("expected 0 dirs, got %d: %v", len(dirs), dirs)
	}
}

func TestResolveMultiDirs_BareEllipsis(t *testing.T) {
	// "..." should expand from cwd (same as "./...").
	// Use a temp dir with a known file so the result is deterministic.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module test"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Change cwd to the temp dir for this test.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	dirs, err := resolveMultiDirs([]string{"..."})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("expected 1 dir, got %d: %v", len(dirs), dirs)
	}
}

// ── findProjectDirs ───────────────────────────────────────────────────────────

func TestFindProjectDirs_SingleProject(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module test"), 0o600); err != nil {
		t.Fatal(err)
	}

	dirs, err := findProjectDirs(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 1 || dirs[0] != root {
		t.Errorf("expected [%s], got %v", root, dirs)
	}
}

func TestFindProjectDirs_MultipleEcosystems(t *testing.T) {
	root := t.TempDir()
	projects := map[string]string{
		"go-service": "go.mod",
		"py-service": "requirements.txt",
		"rs-service": "Cargo.toml",
		"js-service": "package.json",
	}
	for sub, file := range projects {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	dirs, err := findProjectDirs(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 4 {
		t.Errorf("expected 4 projects, got %d: %v", len(dirs), dirs)
	}
}

func TestFindProjectDirs_OnlyOneEntryPerDir(t *testing.T) {
	// A dir with both go.mod and requirements.txt should appear only once.
	root := t.TempDir()
	for _, f := range []string{"go.mod", "requirements.txt"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	dirs, err := findProjectDirs(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 1 {
		t.Errorf("expected 1, got %d: %v", len(dirs), dirs)
	}
}

func TestFindProjectDirs_CsprojDetected(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "App.csproj"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	dirs, err := findProjectDirs(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 1 {
		t.Errorf("expected 1, got %d: %v", len(dirs), dirs)
	}
}

func TestFindProjectDirs_NoDepFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	dirs, err := findProjectDirs(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dirs) != 0 {
		t.Errorf("expected 0, got %d: %v", len(dirs), dirs)
	}
}

func TestFindProjectDirs_NestedProjects(t *testing.T) {
	root := t.TempDir()
	paths := []struct{ sub, file string }{
		{"", "go.mod"}, // root itself
		{"services/auth", "go.mod"},
		{"services/api", "requirements.txt"},
		{"frontend", "package.json"},
	}
	for _, p := range paths {
		dir := root
		if p.sub != "" {
			dir = filepath.Join(root, p.sub)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, p.file), []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	dirs, err := findProjectDirs(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(dirs)
	if len(dirs) != 4 {
		t.Errorf("expected 4, got %d: %v", len(dirs), dirs)
	}
}

// ── deduplicateDirs ───────────────────────────────────────────────────────────

func TestDeduplicateDirs_PreservesOrder(t *testing.T) {
	in := []string{"c", "a", "b", "a", "c"}
	out := deduplicateDirs(in)
	want := []string{"c", "a", "b"}
	if len(out) != len(want) {
		t.Fatalf("expected %v, got %v", want, out)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("index %d: want %q, got %q", i, want[i], out[i])
		}
	}
}

func TestDeduplicateDirs_Empty(t *testing.T) {
	out := deduplicateDirs(nil)
	if len(out) != 0 {
		t.Errorf("expected empty, got %v", out)
	}
}

func TestDeduplicateDirs_NoDuplicates(t *testing.T) {
	in := []string{"a", "b", "c"}
	out := deduplicateDirs(in)
	if len(out) != 3 {
		t.Errorf("expected 3, got %d", len(out))
	}
}
