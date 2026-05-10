package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/abhishekamralkar/argus/internal/rag"
	"github.com/abhishekamralkar/argus/internal/store"
)

// ── JSON ────────────────────────────────────────────────────────────────────

type JSONReport struct {
	ScannedAt string       `json:"scanned_at"`
	Results   []JSONResult `json:"results"`
}

type JSONResult struct {
	Package      string        `json:"package"`
	Version      string        `json:"version"`
	Ecosystem    string        `json:"ecosystem"`
	Verdict      string        `json:"verdict"`
	Severity     string        `json:"severity,omitempty"`
	CVECount     int           `json:"cve_count"`
	TopCVSSScore float64       `json:"top_cvss_score,omitempty"`
	TopFix       string        `json:"top_fix,omitempty"`
	Findings     []JSONFinding `json:"findings,omitempty"`
}

// JSONRemediation describes a structured upgrade action for a finding.
type JSONRemediation struct {
	Action    string `json:"action"`     // always "upgrade"
	ToVersion string `json:"to_version"` // e.g. "2.31.0"
}

type JSONFinding struct {
	ID          string           `json:"id"`
	Package     string           `json:"package"`
	Severity    string           `json:"severity,omitempty"`
	CVSSScore   float64          `json:"cvss_score,omitempty"`
	CVSSVector  string           `json:"cvss_vector,omitempty"`
	FixedIn     string           `json:"fixed_in,omitempty"`
	Score       float64          `json:"score"`
	Summary     string           `json:"summary,omitempty"`
	Remediation *JSONRemediation `json:"remediation,omitempty"`
}

// BuildJSONResults converts a slice of rag.Result to []JSONResult.
// Used by both WriteJSON and multi-project JSON output.
func BuildJSONResults(results []rag.Result) []JSONResult {
	out := make([]JSONResult, len(results))
	for i, r := range results {
		jr := JSONResult{
			Package:      r.Dep.Name,
			Version:      r.Dep.Version,
			Ecosystem:    r.Dep.Ecosystem,
			Verdict:      r.Verdict(),
			Severity:     r.TopSeverity,
			CVECount:     r.RetrievedCount,
			TopCVSSScore: r.TopCVSSScore,
			TopFix:       r.TopFixedIn,
		}
		for _, f := range r.Findings {
			jf := JSONFinding{
				ID:         f.ID,
				Package:    f.Package,
				Severity:   f.Severity,
				CVSSScore:  f.CVSSScore,
				CVSSVector: f.CVSSVector,
				FixedIn:    f.FixedIn,
				Score:      f.Score,
				Summary:    truncate(f.Content, 300),
			}
			if f.FixedIn != "" {
				jf.Remediation = &JSONRemediation{
					Action:    "upgrade",
					ToVersion: f.FixedIn,
				}
			}
			jr.Findings = append(jr.Findings, jf)
		}
		out[i] = jr
	}
	return out
}

func WriteJSON(w io.Writer, results []rag.Result) error {
	report := JSONReport{
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Results:   BuildJSONResults(results),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// ── SARIF 2.1.0 ─────────────────────────────────────────────────────────────

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	Severity  string  `json:"security-severity"`
	CVSSScore float64 `json:"cvssScore,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func WriteSARIF(w io.Writer, results []rag.Result, projectDir string) error {
	rules := buildRules(results)
	var sarifResults []sarifResult

	for _, r := range results {
		if r.RetrievedCount == 0 {
			continue
		}
		for _, f := range r.Findings {
			sarifResults = append(sarifResults, sarifResult{
				RuleID: f.ID,
				Level:  severityToLevel(f.Severity),
				Message: sarifMessage{
					Text: fmt.Sprintf("%s@%s (%s): %s — fixed in %s",
						r.Dep.Name, r.Dep.Version, r.Dep.Ecosystem,
						f.ID, emptyOr(f.FixedIn, "no fix available")),
				},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: depFile(r.Dep.Ecosystem)},
					},
				}},
			})
		}
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "argus",
				Version:        "0.1.0",
				InformationURI: "https://github.com/abhishekamralkar/argus",
				Rules:          rules,
			}},
			Results: sarifResults,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func buildRules(results []rag.Result) []sarifRule {
	seen := map[string]bool{}
	var rules []sarifRule
	for _, r := range results {
		for _, f := range r.Findings {
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.ID,
				ShortDescription: sarifMessage{Text: truncate(f.Content, 200)},
				Properties: sarifRuleProps{
					Severity:  severityScore(f.Severity),
					CVSSScore: f.CVSSScore,
				},
			})
		}
	}
	return rules
}

func severityToLevel(s string) string {
	switch s {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

func severityScore(s string) string {
	switch s {
	case "CRITICAL":
		return "9.0"
	case "HIGH":
		return "7.0"
	case "MEDIUM":
		return "5.0"
	case "LOW":
		return "3.0"
	default:
		return "5.0"
	}
}

func depFile(ecosystem string) string {
	switch ecosystem {
	case "go":
		return "go.mod"
	case "python":
		return "requirements.txt"
	case "rust":
		return "Cargo.toml"
	case "npm":
		return "package.json"
	default:
		return "dependencies"
	}
}

func emptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Ensure store import is used (findings reference store.SearchResult indirectly via rag.Result)
var _ = store.SearchResult{}
