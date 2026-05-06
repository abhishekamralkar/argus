package color

import (
	"strings"
	"testing"
)

// All tests run with NO_COLOR=1 set by the test runner or by forcing noColor,
// so we assert on the plain string value rather than ANSI escape codes.

func init() {
	// Force no-color mode for deterministic test output.
	noColor = true
}

func TestSeverity(t *testing.T) {
	cases := []struct{ in, want string }{
		{"CRITICAL", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"LOW", "LOW"},
		{"UNKNOWN", "UNKNOWN"},
		{"", ""},
	}
	for _, c := range cases {
		if got := Severity(c.in); got != c.want {
			t.Errorf("Severity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ERROR", "ERROR"},
		{"CRITICAL", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"LOW", "LOW"},
		{"OK", "OK"},
		{"REVIEW", "REVIEW"},
		{"", ""},
	}
	for _, c := range cases {
		if got := Verdict(c.in); got != c.want {
			t.Errorf("Verdict(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGreen(t *testing.T) {
	if got := Green("hello"); got != "hello" {
		t.Errorf("Green(%q) = %q, want %q", "hello", got, "hello")
	}
}

func TestBold(t *testing.T) {
	got := Bold("hello %s", "world")
	if !strings.Contains(got, "hello world") {
		t.Errorf("Bold result %q should contain %q", got, "hello world")
	}
}
