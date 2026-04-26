package rag

import (
	"fmt"
	"io"
	"strings"

	"github.com/abhishekamralkar/argus/internal/embed"
	"github.com/abhishekamralkar/argus/internal/llm"
	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/store"
)

type Engine struct {
	db        *store.DB
	embedder  *embed.Client
	generator *llm.Client
}

func NewEngine(db *store.DB, embedder *embed.Client, generator *llm.Client) *Engine {
	return &Engine{db: db, embedder: embedder, generator: generator}
}

// AnalyzeDependency runs the full RAG pipeline for a single dependency.
// LLM output is streamed to out.
func (e *Engine) AnalyzeDependency(dep parser.Dependency, out io.Writer) error {
	query := fmt.Sprintf("%s package %s version %s vulnerability security", dep.Ecosystem, dep.Name, dep.Version)

	vec, err := e.embedder.Embed(query)
	if err != nil {
		return fmt.Errorf("embed query: %w", err)
	}

	results, err := e.db.Search(dep.Ecosystem, vec, 10)
	if err != nil {
		return fmt.Errorf("vector search: %w", err)
	}

	// Filter to results that actually mention this package name
	var relevant []store.SearchResult
	nameLower := strings.ToLower(dep.Name)
	for _, r := range results {
		if strings.Contains(strings.ToLower(r.Package), nameLower) ||
			strings.Contains(strings.ToLower(r.Content), nameLower) {
			relevant = append(relevant, r)
		}
	}

	if len(relevant) == 0 {
		fmt.Fprintf(out, "No known vulnerabilities found for %s@%s.\n", dep.Name, dep.Version)
		return nil
	}

	prompt := buildPrompt(dep, relevant)
	return e.generator.Generate(prompt, out)
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
