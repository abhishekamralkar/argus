package main

import (
	"testing"
	"time"
)

func TestParseSince(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
		wantYMD string // "YYYY-MM-DD" or "" for zero
	}{
		{"", false, ""},
		{"2026-04-01", false, "2026-04-01"},
		{"2026-01-15T00:00:00Z", false, "2026-01-15"},
		{"not-a-date", true, ""},
		{"2026-13-01", true, ""}, // invalid month
		{"20260401", true, ""},   // wrong format
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			got, err := parseSince(c.input)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseSince(%q): expected error, got nil", c.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSince(%q): unexpected error: %v", c.input, err)
			}
			if c.wantYMD == "" {
				if !got.IsZero() {
					t.Errorf("parseSince(%q): expected zero, got %v", c.input, got)
				}
				return
			}
			if got.Format("2006-01-02") != c.wantYMD {
				t.Errorf("parseSince(%q): got %v, want %v", c.input, got.Format("2006-01-02"), c.wantYMD)
			}
		})
	}
}

func TestEffectiveDate(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	zero := time.Time{}

	if got := effectiveDate(t1, t2); !got.Equal(t2) {
		t.Errorf("effectiveDate: modified later — got %v, want %v", got, t2)
	}
	if got := effectiveDate(t2, t1); !got.Equal(t2) {
		t.Errorf("effectiveDate: published later — got %v, want %v", got, t2)
	}
	if got := effectiveDate(t1, zero); !got.Equal(t1) {
		t.Errorf("effectiveDate: zero modified — got %v, want %v", got, t1)
	}
	if got := effectiveDate(zero, t2); !got.Equal(t2) {
		t.Errorf("effectiveDate: zero published — got %v, want %v", got, t2)
	}
}
