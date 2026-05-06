package rag

import (
	"bytes"
	"strings"
	"testing"

	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/store"
)

func TestTopSeverity(t *testing.T) {
	cases := []struct {
		results []store.SearchResult
		want    string
	}{
		{nil, ""},
		{[]store.SearchResult{{Severity: "LOW"}}, "LOW"},
		{[]store.SearchResult{{Severity: "LOW"}, {Severity: "HIGH"}}, "HIGH"},
		{[]store.SearchResult{{Severity: "CRITICAL"}, {Severity: "MEDIUM"}}, "CRITICAL"},
		{[]store.SearchResult{{Severity: ""}}, ""},
	}
	for _, c := range cases {
		if got := topSeverity(c.results); got != c.want {
			t.Errorf("topSeverity(%v) = %q, want %q", c.results, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short string truncated: %q", got)
	}
	got := truncate("hello world", 5)
	if got != "hello..." {
		t.Errorf("truncate(11 chars, 5) = %q, want %q", got, "hello...")
	}
}

func TestBuildPrompt(t *testing.T) {
	dep := parser.Dependency{Name: "example.com/foo", Version: "1.2.3", Ecosystem: "go"}
	findings := []store.SearchResult{
		{ID: "GO-2024-0001", Package: "example.com/foo", Severity: "HIGH", FixedIn: "1.3.0", Content: "arbitrary code execution"},
	}
	prompt := buildPrompt(dep, findings)

	for _, want := range []string{
		"example.com/foo",
		"1.2.3",
		"go",
		"GO-2024-0001",
		"HIGH",
		"1.3.0",
		"arbitrary code execution",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("buildPrompt missing %q in output", want)
		}
	}
}

func TestPrintCVETable(t *testing.T) {
	results := []store.SearchResult{
		{ID: "CVE-2024-1234", Package: "pkg", Severity: "MEDIUM", FixedIn: "1.0.0", Score: 0.85},
		{ID: "GO-2024-0001", Package: "pkg2", Severity: "", FixedIn: "", Score: 0.72},
	}
	var buf bytes.Buffer
	printCVETable(&buf, results)
	out := buf.String()
	if !strings.Contains(out, "CVE-2024-1234") {
		t.Errorf("table missing CVE-2024-1234")
	}
	if !strings.Contains(out, "GO-2024-0001") {
		t.Errorf("table missing GO-2024-0001")
	}
}

func TestNewEngine_DefaultThreshold(t *testing.T) {
	e := NewEngine(nil, nil, nil, EngineConfig{})
	if e.cfg.SimilarityThreshold != store.DefaultSimilarityThreshold {
		t.Errorf("default threshold = %v, want %v", e.cfg.SimilarityThreshold, store.DefaultSimilarityThreshold)
	}
}

func TestNewEngine_CustomThreshold(t *testing.T) {
	e := NewEngine(nil, nil, nil, EngineConfig{SimilarityThreshold: 0.7})
	if e.cfg.SimilarityThreshold != 0.7 {
		t.Errorf("threshold = %v, want 0.7", e.cfg.SimilarityThreshold)
	}
}
