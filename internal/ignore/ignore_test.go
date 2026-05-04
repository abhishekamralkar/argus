package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	content := `# ignore known false positive
GHSA-xxxx-yyyy-zzzz
CVE-2024-1234
# ignore whole package
requests
golang.org/x/crypto
`
	if err := os.WriteFile(filepath.Join(dir, ".argusignore"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !l.VulnID("GHSA-xxxx-yyyy-zzzz") {
		t.Error("expected GHSA-xxxx-yyyy-zzzz to be ignored")
	}
	if !l.VulnID("cve-2024-1234") { // case-insensitive
		t.Error("expected CVE-2024-1234 (lower) to be ignored")
	}
	if !l.Package("requests") {
		t.Error("expected requests to be ignored")
	}
	if !l.Package("golang.org/x/crypto") {
		t.Error("expected golang.org/x/crypto to be ignored")
	}
	if l.VulnID("CVE-2099-9999") {
		t.Error("CVE-2099-9999 should not be ignored")
	}
	if l.Package("flask") {
		t.Error("flask should not be ignored")
	}
}

func TestLoadMissing(t *testing.T) {
	l, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load on missing file should not error: %v", err)
	}
	if l.VulnID("CVE-2024-1") || l.Package("anything") {
		t.Error("empty list should ignore nothing")
	}
}
