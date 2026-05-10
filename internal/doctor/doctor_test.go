package doctor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/abhishekamralkar/argus/internal/store"
)

var bg = context.Background()

// ── .argus.yaml ──────────────────────────────────────────────────────────────

func TestCheckConfigFile_Missing(t *testing.T) {
	dir := t.TempDir()
	c := checkConfigFile(dir)
	if !c.OK {
		t.Fatalf("expected OK for missing file, got: %s", c.Detail)
	}
	if c.Detail != "not present (using defaults)" {
		t.Errorf("unexpected detail: %q", c.Detail)
	}
}

func TestCheckConfigFile_Valid(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".argus.yaml"), []byte("workers: 4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkConfigFile(dir)
	if !c.OK {
		t.Fatalf("expected OK for valid file, got: %s", c.Detail)
	}
	if c.Detail != "valid" {
		t.Errorf("unexpected detail: %q", c.Detail)
	}
}

func TestCheckConfigFile_Invalid(t *testing.T) {
	dir := t.TempDir()
	// workers must be >= 0; -5 is invalid
	if err := os.WriteFile(filepath.Join(dir, ".argus.yaml"), []byte("workers: -5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkConfigFile(dir)
	if c.OK {
		t.Fatal("expected failure for invalid config, got OK")
	}
	if c.Hint == "" {
		t.Error("expected a non-empty Hint on failure")
	}
}

// ── .argusignore ─────────────────────────────────────────────────────────────

func TestCheckIgnoreFile_Missing(t *testing.T) {
	dir := t.TempDir()
	c := checkIgnoreFile(dir)
	if !c.OK {
		t.Fatalf("expected OK for missing file, got: %s", c.Detail)
	}
	if c.Detail != "not present (no suppressions)" {
		t.Errorf("unexpected detail: %q", c.Detail)
	}
}

func TestCheckIgnoreFile_Valid(t *testing.T) {
	dir := t.TempDir()
	content := "# comment\nCVE-2024-1234\nrequests\n"
	if err := os.WriteFile(filepath.Join(dir, ".argusignore"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	c := checkIgnoreFile(dir)
	if !c.OK {
		t.Fatalf("expected OK for valid file, got: %s", c.Detail)
	}
}

// ── database ─────────────────────────────────────────────────────────────────

func TestCheckDB_NotFound(t *testing.T) {
	c := checkDB(bg, filepath.Join(t.TempDir(), "nonexistent.db"))
	if c.OK {
		t.Fatal("expected failure for missing DB")
	}
	if c.Hint == "" {
		t.Error("expected a Hint for missing DB")
	}
}

func TestCheckDB_EmptyDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "empty.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	c := checkDB(bg, dbPath)
	if c.OK {
		t.Fatal("expected failure for empty DB")
	}
	if c.Hint == "" {
		t.Error("expected a Hint for empty DB")
	}
}

func TestCheckDB_PopulatedDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vulns.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	v := &store.Vulnerability{
		ID: "CVE-2024-0001", Ecosystem: "go",
		Package: "example.com/pkg", Summary: "test vuln",
	}
	if err := db.UpsertVulnMeta(bg, v); err != nil {
		t.Fatalf("UpsertVulnMeta: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	c := checkDB(bg, dbPath)
	if !c.OK {
		t.Fatalf("expected OK for populated DB, got: %s", c.Detail)
	}
}

// ── Ollama endpoint ───────────────────────────────────────────────────────────

func TestCheckOllamaEndpoint_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"models":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := checkOllamaEndpoint(bg, srv.URL)
	if !c.OK {
		t.Fatalf("expected OK, got: %s", c.Detail)
	}
}

func TestCheckOllamaEndpoint_Unreachable(t *testing.T) {
	c := checkOllamaEndpoint(bg, "http://127.0.0.1:19999")
	if c.OK {
		t.Fatal("expected failure for unreachable endpoint")
	}
	if c.Hint == "" {
		t.Error("expected a Hint for unreachable endpoint")
	}
}

func TestCheckOllamaEndpoint_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := checkOllamaEndpoint(bg, srv.URL)
	if c.OK {
		t.Fatal("expected failure for non-200 response")
	}
}

// ── Ollama model ──────────────────────────────────────────────────────────────

func newOllamaSrv(t *testing.T, models []string) *httptest.Server {
	t.Helper()
	type modelEntry struct {
		Name string `json:"name"`
	}
	type tagsResp struct {
		Models []modelEntry `json:"models"`
	}
	entries := make([]modelEntry, len(models))
	for i, m := range models {
		entries[i] = modelEntry{Name: m}
	}
	payload, _ := json.Marshal(tagsResp{Models: entries})

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestCheckOllamaModel_Found(t *testing.T) {
	srv := newOllamaSrv(t, []string{"llama3.1:8b", "nomic-embed-text:latest"})
	defer srv.Close()

	c := checkOllamaModel(bg, srv.URL, "llama3.1:8b", "LLM")
	if !c.OK {
		t.Fatalf("expected OK for present model, got: %s", c.Detail)
	}
}

func TestCheckOllamaModel_FoundWithoutLatestTag(t *testing.T) {
	// Model stored as "nomic-embed-text:latest"; queried without tag.
	srv := newOllamaSrv(t, []string{"nomic-embed-text:latest"})
	defer srv.Close()

	c := checkOllamaModel(bg, srv.URL, "nomic-embed-text", "embedding")
	if !c.OK {
		t.Fatalf("expected OK when model matches without :latest tag, got: %s", c.Detail)
	}
}

func TestCheckOllamaModel_NotFound(t *testing.T) {
	srv := newOllamaSrv(t, []string{"other-model:latest"})
	defer srv.Close()

	c := checkOllamaModel(bg, srv.URL, "llama3.1:8b", "LLM")
	if c.OK {
		t.Fatal("expected failure for absent model")
	}
	if c.Hint == "" {
		t.Error("expected a Hint with pull instructions")
	}
}

func TestCheckOllamaModel_EmptyList(t *testing.T) {
	srv := newOllamaSrv(t, nil)
	defer srv.Close()

	c := checkOllamaModel(bg, srv.URL, "llama3.1:8b", "LLM")
	if c.OK {
		t.Fatal("expected failure when model list is empty")
	}
}

// ── OpenAI endpoint ───────────────────────────────────────────────────────────

func TestCheckOpenAIEndpoint_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := checkOpenAIEndpoint(bg, srv.URL, "test-key")
	if !c.OK {
		t.Fatalf("expected OK, got: %s", c.Detail)
	}
}

func TestCheckOpenAIEndpoint_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := checkOpenAIEndpoint(bg, srv.URL, "bad-key")
	if c.OK {
		t.Fatal("expected failure for 401")
	}
	if c.Hint == "" {
		t.Error("expected a Hint for 401")
	}
}

func TestCheckOpenAIEndpoint_Unreachable(t *testing.T) {
	c := checkOpenAIEndpoint(bg, "http://127.0.0.1:19999", "key")
	if c.OK {
		t.Fatal("expected failure for unreachable endpoint")
	}
}

// ── Run (integration) ─────────────────────────────────────────────────────────

func TestRun_OllamaMode(t *testing.T) {
	srv := newOllamaSrv(t, []string{"llama3.1:8b", "nomic-embed-text:latest"})
	defer srv.Close()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vulns.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := db.UpsertVulnMeta(bg, &store.Vulnerability{
		ID: "CVE-2024-RUN", Ecosystem: "go", Package: "pkg", Summary: "run test",
	}); err != nil {
		t.Fatalf("UpsertVulnMeta: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	checks := Run(bg, Config{
		DBPath:     dbPath,
		ProjectDir: dir,
		OllamaHost: srv.URL,
	})

	for _, c := range checks {
		if !c.OK {
			t.Errorf("check %q failed: %s (hint: %s)", c.Name, c.Detail, c.Hint)
		}
	}
}

func TestRun_OllamaEndpointDown_SkipsModelChecks(t *testing.T) {
	checks := Run(bg, Config{
		DBPath:     filepath.Join(t.TempDir(), "missing.db"),
		ProjectDir: t.TempDir(),
		OllamaHost: "http://127.0.0.1:19999",
	})

	skipped := 0
	for _, c := range checks {
		if !c.OK && c.Detail == "skipped — Ollama endpoint unreachable" {
			skipped++
		}
	}
	if skipped != 2 {
		t.Errorf("expected 2 skipped model checks, got %d", skipped)
	}
}

func TestRun_OpenAIMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	checks := Run(bg, Config{
		DBPath:     filepath.Join(dir, "missing.db"),
		ProjectDir: dir,
		LLMBaseURL: srv.URL,
		APIKey:     "test-key",
	})

	// In OpenAI mode, endpoint check should be present (no Ollama model checks).
	endpointFound := false
	for _, c := range checks {
		if c.Name == "OpenAI-compatible endpoint" {
			endpointFound = true
			if !c.OK {
				t.Errorf("OpenAI endpoint check failed: %s", c.Detail)
			}
		}
		if c.Name == "Ollama endpoint" {
			t.Error("should not have Ollama endpoint check in OpenAI mode")
		}
	}
	if !endpointFound {
		t.Error("expected OpenAI-compatible endpoint check")
	}
}
