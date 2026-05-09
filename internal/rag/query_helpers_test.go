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

func TestNewEngine_DefaultTopK(t *testing.T) {
	e := NewEngine(nil, nil, nil, EngineConfig{})
	if e.cfg.TopK != DefaultTopK {
		t.Errorf("default TopK = %v, want %v", e.cfg.TopK, DefaultTopK)
	}
}

func TestNewEngine_CustomTopK(t *testing.T) {
	e := NewEngine(nil, nil, nil, EngineConfig{TopK: 25})
	if e.cfg.TopK != 25 {
		t.Errorf("TopK = %v, want 25", e.cfg.TopK)
	}
}

func TestPackageMatches(t *testing.T) {
	cases := []struct {
		vulnPkg string
		content string
		depName string
		want    bool
	}{
		// Exact match
		{"requests", "", "requests", true},
		{"Requests", "", "requests", true}, // case-insensitive
		// Must NOT match substring of package name
		{"requests-mock", "", "requests", false},
		{"requests-oauthlib", "", "requests", false},
		{"serde_derive", "", "serde", false},
		// Go module path suffix
		{"github.com/foo/requests", "", "requests", true},
		{"github.com/foo/bar", "", "requests", false},
		{"example.com/pkg/requests", "", "requests", true},
		// Whole-word in content
		{"other-pkg", "the requests library has a vulnerability", "requests", true},
		{"other-pkg", "use requests-mock for testing", "requests", false}, // hyphen = word char
		{"other-pkg", "affects serde version 1.0", "serde", true},
		{"other-pkg", "affects serde_derive", "serde", false}, // underscore = word char
		// Empty / no match
		{"unrelated", "unrelated content", "requests", false},
	}
	for _, c := range cases {
		got := packageMatches(c.vulnPkg, c.content, c.depName)
		if got != c.want {
			t.Errorf("packageMatches(%q, %q, %q) = %v, want %v",
				c.vulnPkg, c.content, c.depName, got, c.want)
		}
	}
}

func TestContainsWholeWord(t *testing.T) {
	cases := []struct {
		s, word string
		want    bool
	}{
		{"the requests library", "requests", true},
		{"requests library", "requests", true},         // at start
		{"use requests", "requests", true},             // at end
		{"requests", "requests", true},                 // exact
		{"requests-mock", "requests", false},           // hyphen boundary
		{"requests_mock", "requests", false},           // underscore boundary
		{"xrequests", "requests", false},               // letter boundary
		{"use requests2 carefully", "requests", false}, // digit boundary
	}
	for _, c := range cases {
		got := containsWholeWord(c.s, c.word)
		if got != c.want {
			t.Errorf("containsWholeWord(%q, %q) = %v, want %v", c.s, c.word, got, c.want)
		}
	}
}
