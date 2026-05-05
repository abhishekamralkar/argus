package rag

import (
	"errors"
	"testing"

	"github.com/abhishekamralkar/argus/internal/store"
)

func TestResultVerdict(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   string
	}{
		{
			name:   "no findings returns OK",
			result: Result{RetrievedCount: 0},
			want:   "OK",
		},
		{
			name: "CRITICAL finding returns CRITICAL",
			result: Result{
				RetrievedCount: 1,
				TopSeverity:    "CRITICAL",
				Findings:       []store.SearchResult{{Severity: "CRITICAL"}},
			},
			want: "CRITICAL",
		},
		{
			name: "HIGH finding returns HIGH",
			result: Result{
				RetrievedCount: 1,
				TopSeverity:    "HIGH",
				Findings:       []store.SearchResult{{Severity: "HIGH"}},
			},
			want: "HIGH",
		},
		{
			name: "MEDIUM finding returns MEDIUM",
			result: Result{
				RetrievedCount: 1,
				TopSeverity:    "MEDIUM",
				Findings:       []store.SearchResult{{Severity: "MEDIUM"}},
			},
			want: "MEDIUM",
		},
		{
			name: "LOW finding returns LOW",
			result: Result{
				RetrievedCount: 1,
				TopSeverity:    "LOW",
				Findings:       []store.SearchResult{{Severity: "LOW"}},
			},
			want: "LOW",
		},
		{
			name: "unknown severity with findings returns REVIEW",
			result: Result{
				RetrievedCount: 1,
				TopSeverity:    "UNKNOWN",
				Findings:       []store.SearchResult{{Severity: "UNKNOWN"}},
			},
			want: "REVIEW",
		},
		{
			name: "Err set returns ERROR",
			result: Result{
				RetrievedCount: 0,
				Err:            errors.New("something went wrong"),
			},
			want: "ERROR",
		},
		{
			name: "Err set with findings — Err takes priority and returns ERROR",
			result: Result{
				RetrievedCount: 1,
				TopSeverity:    "CRITICAL",
				Findings:       []store.SearchResult{{Severity: "CRITICAL"}},
				Err:            errors.New("llm failure"),
			},
			want: "ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.result.Verdict()
			if got != tt.want {
				t.Errorf("Verdict() = %q, want %q", got, tt.want)
			}
		})
	}
}
