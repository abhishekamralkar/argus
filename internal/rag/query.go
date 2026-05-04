package rag

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"

	col "github.com/abhishekamralkar/argus/internal/color"
	"github.com/abhishekamralkar/argus/internal/embed"
	"github.com/abhishekamralkar/argus/internal/ignore"
	"github.com/abhishekamralkar/argus/internal/llm"
	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/store"
	"github.com/abhishekamralkar/argus/internal/version"
)

var severityOrder = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

type Engine struct {
	db           *store.DB
	embedder     *embed.Client
	generator    *llm.Client
	enhanceQuery bool
	minSeverity  string
	ignoreList   *ignore.List
}

func NewEngine(
	db *store.DB,
	embedder *embed.Client,
	generator *llm.Client,
	enhanceQuery bool,
	minSeverity string,
	ignoreList *ignore.List,
) *Engine {
	return &Engine{
		db:           db,
		embedder:     embedder,
		generator:    generator,
		enhanceQuery: enhanceQuery,
		minSeverity:  minSeverity,
		ignoreList:   ignoreList,
	}
}

// Result summarises the outcome of analysing one dependency.
type Result struct {
	Dep            parser.Dependency
	RetrievedCount int
	TopSeverity    string
	Findings       []store.SearchResult
	LLMAnalysis    string
}

func (r Result) Verdict() string {
	if r.RetrievedCount == 0 {
		return "OK"
	}
	switch r.TopSeverity {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "REVIEW"
	}
}

// enhanceQueryText uses the LLM to expand a short query for better recall.
func (e *Engine) enhanceQueryText(query string) string {
	prompt := fmt.Sprintf(
		"Expand the following software vulnerability search query with related keywords, CVE patterns, and attack vectors. "+
			"Return only the expanded query as a single line, no explanation.\n\nQuery: %s", query)
	var sb strings.Builder
	if err := e.generator.Generate(prompt, &sb); err != nil {
		return query
	}
	expanded := strings.TrimSpace(sb.String())
	if expanded == "" {
		return query
	}
	return expanded
}

// AnalyzeDependency runs the full RAG pipeline for a single dependency.
// Retrieved CVEs are printed as a table; LLM output is streamed to out.
func (e *Engine) AnalyzeDependency(dep parser.Dependency, out io.Writer) (Result, error) {
	result := Result{Dep: dep}

	query := fmt.Sprintf("%s package %s version %s vulnerability security", dep.Ecosystem, dep.Name, dep.Version)
	if e.enhanceQuery {
		query = e.enhanceQueryText(query)
	}
	vec, err := e.embedder.Embed(query)
	if err != nil {
		return result, fmt.Errorf("embed query: %w", err)
	}

	hits, err := e.db.SearchBest(dep.Ecosystem, vec, 10)
	if err != nil {
		return result, fmt.Errorf("vector search: %w", err)
	}

	// Filter: package name match + version-aware + ignore list + min-severity + alias dedup.
	nameLower := strings.ToLower(dep.Name)
	seenID := make(map[string]bool) // dedup by canonical ID and all aliases
	var relevant []store.SearchResult
	for _, r := range hits {
		// Skip if package is on the ignore list
		if e.ignoreList != nil && e.ignoreList.Package(r.Package) {
			continue
		}
		// Skip if this specific vuln ID (or any alias) is ignored
		if e.ignoreList != nil {
			if e.ignoreList.VulnID(r.ID) {
				continue
			}
			ignored := false
			for _, alias := range r.Aliases {
				if e.ignoreList.VulnID(alias) {
					ignored = true
					break
				}
			}
			if ignored {
				continue
			}
		}
		// Alias-aware deduplication: skip if we already have this vuln under another ID
		canonKey := r.ID
		for _, alias := range r.Aliases {
			if seenID[alias] {
				canonKey = ""
				break
			}
		}
		if canonKey == "" || seenID[r.ID] {
			continue
		}
		seenID[r.ID] = true
		for _, alias := range r.Aliases {
			seenID[alias] = true
		}
		// Package name match
		nameMatch := strings.Contains(strings.ToLower(r.Package), nameLower) ||
			strings.Contains(strings.ToLower(r.Content), nameLower)
		if !nameMatch {
			continue
		}
		// Version-aware: skip if already fixed
		if !version.AffectsVersion(dep.Version, r.FixedIn) {
			continue
		}
		// Min-severity filter
		if e.minSeverity != "" && r.Severity != "" {
			if severityOrder[r.Severity] < severityOrder[e.minSeverity] {
				continue
			}
		}
		relevant = append(relevant, r)
	}

	result.RetrievedCount = len(relevant)
	result.TopSeverity = topSeverity(relevant)
	result.Findings = relevant

	if len(relevant) == 0 {
		_, _ = fmt.Fprintf(out, "  No matching vulnerabilities found in database.\n")
		return result, nil
	}

	// Print retrieved CVEs as a table.
	printCVETable(out, relevant)

	// Stream LLM analysis.
	_, _ = fmt.Fprintf(out, "\n  Analyzing with %s (streaming)...\n", e.generator.Model())
	_, _ = fmt.Fprintln(out, strings.Repeat("─", 60))

	var llmBuf strings.Builder
	bw := bufio.NewWriter(io.MultiWriter(out, &llmBuf))
	err = e.generator.Generate(buildPrompt(dep, relevant), writerFunc(func(p []byte) (int, error) {
		n, err := bw.Write(p)
		_ = bw.Flush()
		return n, err
	}))
	result.LLMAnalysis = llmBuf.String()
	_, _ = fmt.Fprintln(out)
	return result, err
}

func printCVETable(out io.Writer, results []store.SearchResult) {
	_, _ = fmt.Fprintln(out)
	t := tablewriter.NewWriter(out)
	t.Header("ID", "Package", "Severity", "Fixed In", "Score")
	for _, r := range results {
		sev := r.Severity
		if sev == "" {
			sev = "—"
		}
		fix := r.FixedIn
		if fix == "" {
			fix = "—"
		}
		_ = t.Append([]string{r.ID, r.Package, col.Severity(sev), fix, fmt.Sprintf("%.3f", r.Score)})
	}
	_ = t.Render()
}

func buildPrompt(dep parser.Dependency, results []store.SearchResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "You are a security researcher analyzing software dependencies for vulnerabilities.\n\n")
	fmt.Fprintf(&sb, "Dependency under analysis: %s version %s (ecosystem: %s)\n\n", dep.Name, dep.Version, dep.Ecosystem)
	fmt.Fprintf(&sb, "Known vulnerabilities retrieved from the database:\n\n")
	for i, r := range results {
		fmt.Fprintf(&sb, "--- Vulnerability %d ---\n", i+1)
		fmt.Fprintf(&sb, "ID: %s\n", r.ID)
		fmt.Fprintf(&sb, "Package: %s\n", r.Package)
		if r.Severity != "" {
			fmt.Fprintf(&sb, "Severity: %s\n", r.Severity)
		}
		if r.FixedIn != "" {
			fmt.Fprintf(&sb, "Fixed in: %s\n", r.FixedIn)
		}
		fmt.Fprintf(&sb, "Details: %s\n\n", truncate(r.Content, 500))
	}
	fmt.Fprintf(&sb, "Based on the above, provide:\n")
	fmt.Fprintf(&sb, "1. Is this dependency vulnerable? (YES / NO / MAYBE)\n")
	fmt.Fprintf(&sb, "2. Severity level if vulnerable\n")
	fmt.Fprintf(&sb, "3. Specific CVE or advisory IDs that apply\n")
	fmt.Fprintf(&sb, "4. Recommended fix (upgrade version if applicable)\n")
	fmt.Fprintf(&sb, "5. Brief explanation of the risk\n")
	return sb.String()
}

func topSeverity(results []store.SearchResult) string {
	top := ""
	for _, r := range results {
		if severityOrder[r.Severity] > severityOrder[top] {
			top = r.Severity
		}
	}
	return top
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// writerFunc adapts a func to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
