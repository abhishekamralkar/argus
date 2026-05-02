package rag

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/abhishekamralkar/argus/internal/embed"
	"github.com/abhishekamralkar/argus/internal/llm"
	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/store"
	"github.com/abhishekamralkar/argus/internal/version"
)

type Engine struct {
	db           *store.DB
	embedder     *embed.Client
	generator    *llm.Client
	enhanceQuery bool
}

func NewEngine(db *store.DB, embedder *embed.Client, generator *llm.Client, enhanceQuery bool) *Engine {
	return &Engine{db: db, embedder: embedder, generator: generator, enhanceQuery: enhanceQuery}
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

	// Filter: package name match + version-aware (only flag if scanned version is still affected).
	nameLower := strings.ToLower(dep.Name)
	var relevant []store.SearchResult
	for _, r := range hits {
		nameMatch := strings.Contains(strings.ToLower(r.Package), nameLower) ||
			strings.Contains(strings.ToLower(r.Content), nameLower)
		if !nameMatch {
			continue
		}
		if !version.AffectsVersion(dep.Version, r.FixedIn) {
			continue // dep is already at or past the fixed version
		}
		relevant = append(relevant, r)
	}

	result.RetrievedCount = len(relevant)
	result.TopSeverity = topSeverity(relevant)
	result.Findings = relevant

	if len(relevant) == 0 {
		fmt.Fprintf(out, "  No matching vulnerabilities found in database.\n")
		return result, nil
	}

	// Print retrieved CVEs as a table.
	printCVETable(out, relevant)

	// Stream LLM analysis.
	fmt.Fprintf(out, "\n  Analyzing with %s (streaming)...\n", e.generator.Model())
	fmt.Fprintln(out, strings.Repeat("─", 60))

	var llmBuf strings.Builder
	bw := bufio.NewWriter(io.MultiWriter(out, &llmBuf))
	err = e.generator.Generate(buildPrompt(dep, relevant), writerFunc(func(p []byte) (int, error) {
		n, err := bw.Write(p)
		bw.Flush()
		return n, err
	}))
	result.LLMAnalysis = llmBuf.String()
	fmt.Fprintln(out)
	return result, err
}

func printCVETable(out io.Writer, results []store.SearchResult) {
	fmt.Fprintln(out)
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
		t.Append([]string{r.ID, r.Package, sev, fix, fmt.Sprintf("%.3f", r.Score)})
	}
	t.Render()
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
	order := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
	top := ""
	for _, r := range results {
		if order[r.Severity] > order[top] {
			top = r.Severity
		}
	}
	return top
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// writerFunc adapts a func to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

