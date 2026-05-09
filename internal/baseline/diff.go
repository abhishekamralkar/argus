// Package baseline compares scan results against a stored baseline and
// surfaces only new findings.
package baseline

import (
	"time"

	"github.com/abhishekamralkar/argus/internal/rag"
	"github.com/abhishekamralkar/argus/internal/store"
)

// DiffResults filters results so each finding slice contains only vuln IDs
// that are absent from stored. A result with no new findings still appears in
// the returned slice (with empty Findings / zero RetrievedCount) so callers
// can report "no new issues" per package.
func DiffResults(results []rag.Result, stored map[string][]string) []rag.Result {
	out := make([]rag.Result, len(results))
	for i, r := range results {
		key := r.Dep.Name + "\x00" + r.Dep.Ecosystem
		known := toSet(stored[key])

		var newFindings []store.SearchResult
		for _, f := range r.Findings {
			if !known[f.ID] {
				newFindings = append(newFindings, f)
			}
		}

		nr := r
		nr.Findings = newFindings
		nr.RetrievedCount = len(newFindings)
		nr.TopSeverity = topSeverity(newFindings)
		out[i] = nr
	}
	return out
}

// ToEntries converts scan results into baseline entries ready for storage.
func ToEntries(results []rag.Result) []store.BaselineEntry {
	now := time.Now().UTC()
	entries := make([]store.BaselineEntry, len(results))
	for i, r := range results {
		ids := make([]string, len(r.Findings))
		for j, f := range r.Findings {
			ids[j] = f.ID
		}
		entries[i] = store.BaselineEntry{
			DepName:   r.Dep.Name,
			Ecosystem: r.Dep.Ecosystem,
			VulnIDs:   ids,
			ScannedAt: now,
		}
	}
	return entries
}

func toSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

var severityRank = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

func topSeverity(findings []store.SearchResult) string {
	top := ""
	for _, f := range findings {
		if severityRank[f.Severity] > severityRank[top] {
			top = f.Severity
		}
	}
	return top
}
