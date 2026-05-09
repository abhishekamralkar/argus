package baseline_test

import (
	"testing"

	"github.com/abhishekamralkar/argus/internal/baseline"
	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/rag"
	"github.com/abhishekamralkar/argus/internal/store"
)

func makeResult(name, eco string, ids ...string) rag.Result {
	findings := make([]store.SearchResult, len(ids))
	for i, id := range ids {
		findings[i] = store.SearchResult{ID: id, Severity: "HIGH"}
	}
	return rag.Result{
		Dep:            parser.Dependency{Name: name, Ecosystem: eco},
		RetrievedCount: len(ids),
		TopSeverity:    "HIGH",
		Findings:       findings,
	}
}

func TestDiffResults_AllNew(t *testing.T) {
	results := []rag.Result{makeResult("pkg/foo", "go", "CVE-1", "CVE-2")}
	diffed := baseline.DiffResults(results, nil)
	if len(diffed[0].Findings) != 2 {
		t.Errorf("expected 2 new findings, got %d", len(diffed[0].Findings))
	}
}

func TestDiffResults_NoneNew(t *testing.T) {
	stored := map[string][]string{"pkg/foo\x00go": {"CVE-1", "CVE-2"}}
	results := []rag.Result{makeResult("pkg/foo", "go", "CVE-1", "CVE-2")}
	diffed := baseline.DiffResults(results, stored)
	if len(diffed[0].Findings) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(diffed[0].Findings))
	}
	if diffed[0].RetrievedCount != 0 {
		t.Errorf("expected RetrievedCount 0, got %d", diffed[0].RetrievedCount)
	}
	if diffed[0].TopSeverity != "" {
		t.Errorf("expected empty TopSeverity, got %q", diffed[0].TopSeverity)
	}
}

func TestDiffResults_PartiallyNew(t *testing.T) {
	stored := map[string][]string{"pkg/foo\x00go": {"CVE-1"}}
	results := []rag.Result{makeResult("pkg/foo", "go", "CVE-1", "CVE-2", "CVE-3")}
	diffed := baseline.DiffResults(results, stored)
	if len(diffed[0].Findings) != 2 {
		t.Errorf("expected 2 new findings, got %d", len(diffed[0].Findings))
	}
	ids := map[string]bool{}
	for _, f := range diffed[0].Findings {
		ids[f.ID] = true
	}
	if !ids["CVE-2"] || !ids["CVE-3"] {
		t.Errorf("expected CVE-2 and CVE-3 as new findings, got %v", diffed[0].Findings)
	}
}

func TestDiffResults_PreservesCleanPackage(t *testing.T) {
	results := []rag.Result{makeResult("pkg/safe", "go")} // no findings
	diffed := baseline.DiffResults(results, nil)
	if len(diffed) != 1 {
		t.Errorf("expected 1 result, got %d", len(diffed))
	}
	if len(diffed[0].Findings) != 0 {
		t.Errorf("expected 0 findings for clean package")
	}
}

func TestToEntries(t *testing.T) {
	results := []rag.Result{makeResult("pkg/foo", "go", "CVE-1", "CVE-2")}
	entries := baseline.ToEntries(results)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.DepName != "pkg/foo" || e.Ecosystem != "go" {
		t.Errorf("unexpected entry: %+v", e)
	}
	if len(e.VulnIDs) != 2 {
		t.Errorf("expected 2 vuln IDs, got %d", len(e.VulnIDs))
	}
	if e.ScannedAt.IsZero() {
		t.Error("ScannedAt should not be zero")
	}
}
