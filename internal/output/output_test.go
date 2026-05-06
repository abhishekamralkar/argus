package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/rag"
	"github.com/abhishekamralkar/argus/internal/store"
)

func makeResult(name, version, ecosystem, severity string, findings []store.SearchResult) rag.Result {
	return rag.Result{
		Dep:            parser.Dependency{Name: name, Version: version, Ecosystem: ecosystem},
		RetrievedCount: len(findings),
		TopSeverity:    severity,
		Findings:       findings,
	}
}

// ── JSON ──────────────────────────────────────────────────────────────────────

func TestWriteJSON_Structure(t *testing.T) {
	results := []rag.Result{
		makeResult("example.com/foo", "1.0.0", "go", "HIGH", []store.SearchResult{
			{ID: "GO-2024-0001", Package: "example.com/foo", Severity: "HIGH", FixedIn: "1.2.0", Score: 0.9},
		}),
		makeResult("bar", "2.0.0", "python", "", nil),
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, results); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if report.ScannedAt == "" {
		t.Error("scanned_at is empty")
	}
	if len(report.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(report.Results))
	}

	r0 := report.Results[0]
	if r0.Package != "example.com/foo" {
		t.Errorf("results[0].package = %q, want %q", r0.Package, "example.com/foo")
	}
	if r0.Verdict != "HIGH" {
		t.Errorf("results[0].verdict = %q, want HIGH", r0.Verdict)
	}
	if r0.CVECount != 1 {
		t.Errorf("results[0].cve_count = %d, want 1", r0.CVECount)
	}
	if len(r0.Findings) != 1 {
		t.Fatalf("results[0].findings: got %d, want 1", len(r0.Findings))
	}
	if r0.Findings[0].ID != "GO-2024-0001" {
		t.Errorf("findings[0].id = %q, want GO-2024-0001", r0.Findings[0].ID)
	}

	r1 := report.Results[1]
	if r1.Verdict != "OK" {
		t.Errorf("results[1].verdict = %q, want OK", r1.Verdict)
	}
	if len(r1.Findings) != 0 {
		t.Errorf("results[1] should have no findings, got %d", len(r1.Findings))
	}
}

func TestWriteJSON_FindingSummaryTruncated(t *testing.T) {
	longContent := strings.Repeat("x", 500)
	results := []rag.Result{
		makeResult("pkg", "1.0.0", "go", "MEDIUM", []store.SearchResult{
			{ID: "GO-2024-9999", Content: longContent, Score: 0.8},
		}),
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, results); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var report JSONReport
	_ = json.Unmarshal(buf.Bytes(), &report)
	summary := report.Results[0].Findings[0].Summary
	if len(summary) > 303 { // 300 + "..."
		t.Errorf("summary not truncated: len=%d", len(summary))
	}
}

// ── SARIF ─────────────────────────────────────────────────────────────────────

func TestWriteSARIF_Structure(t *testing.T) {
	results := []rag.Result{
		makeResult("example.com/foo", "1.0.0", "go", "HIGH", []store.SearchResult{
			{ID: "GO-2024-0001", Package: "example.com/foo", Severity: "HIGH", FixedIn: "1.2.0", Score: 0.9, Content: "vuln desc"},
		}),
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, results, "/project"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, buf.String())
	}
	if log.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "argus" {
		t.Errorf("tool.driver.name = %q, want argus", run.Tool.Driver.Name)
	}
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	if run.Results[0].RuleID != "GO-2024-0001" {
		t.Errorf("result.ruleId = %q, want GO-2024-0001", run.Results[0].RuleID)
	}
	if run.Results[0].Level != "error" {
		t.Errorf("result.level = %q, want error for HIGH severity", run.Results[0].Level)
	}
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].Properties.Severity != "7.0" {
		t.Errorf("rule HIGH severity score = %q, want 7.0", run.Tool.Driver.Rules[0].Properties.Severity)
	}
}

func TestWriteSARIF_NoFindingsOmitted(t *testing.T) {
	results := []rag.Result{
		makeResult("safe-pkg", "1.0.0", "go", "", nil),
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, results, "/project"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var log sarifLog
	_ = json.Unmarshal(buf.Bytes(), &log)
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("expected 0 SARIF results for clean package, got %d", len(log.Runs[0].Results))
	}
}

func TestWriteSARIF_RuleDeduplicated(t *testing.T) {
	finding := store.SearchResult{ID: "CVE-2024-1234", Severity: "MEDIUM", Score: 0.7}
	results := []rag.Result{
		makeResult("pkgA", "1.0.0", "go", "MEDIUM", []store.SearchResult{finding}),
		makeResult("pkgB", "2.0.0", "go", "MEDIUM", []store.SearchResult{finding}),
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, results, "/project"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var log sarifLog
	_ = json.Unmarshal(buf.Bytes(), &log)
	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 deduplicated rule, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
	if len(log.Runs[0].Results) != 2 {
		t.Errorf("expected 2 SARIF results, got %d", len(log.Runs[0].Results))
	}
}

func TestWriteSARIF_SeverityLevels(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"", "note"},
	}
	for _, tt := range tests {
		got := severityToLevel(tt.severity)
		if got != tt.want {
			t.Errorf("severityToLevel(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate short = %q, want %q", got, "hello")
	}
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("truncate long = %q, want %q", got, "hello...")
	}
}
