package rag

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

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

// DefaultTopK is the number of vector search candidates retrieved per dependency.
const DefaultTopK = 10

// EngineConfig holds optional settings for the RAG engine.
// Zero values are safe: similarity threshold defaults to store.DefaultSimilarityThreshold,
// TopK defaults to DefaultTopK.
type EngineConfig struct {
	EnhanceQuery        bool
	MinSeverity         string
	MinCVSS             float64 // skip findings with a known CVSS score below this threshold
	SimilarityThreshold float64
	TopK                int
	IgnoreList          *ignore.List
}

type Engine struct {
	db        *store.DB
	embedder  *embed.Client
	generator *llm.Client
	cfg       EngineConfig
	embedMu   sync.Mutex
	embedMemo map[string][]float32 // keyed by "ecosystem\x00name\x00version"
}

// NewEngine constructs an Engine. If cfg.SimilarityThreshold is zero the
// store default (0.5) is used. If cfg.TopK is zero, DefaultTopK is used.
func NewEngine(db *store.DB, embedder *embed.Client, generator *llm.Client, cfg EngineConfig) *Engine {
	if cfg.SimilarityThreshold == 0 {
		cfg.SimilarityThreshold = store.DefaultSimilarityThreshold
	}
	if cfg.TopK == 0 {
		cfg.TopK = DefaultTopK
	}
	return &Engine{
		db:        db,
		embedder:  embedder,
		generator: generator,
		cfg:       cfg,
		embedMemo: make(map[string][]float32),
	}
}

// Result summarises the outcome of analysing one dependency.
type Result struct {
	Dep            parser.Dependency
	RetrievedCount int
	TopSeverity    string
	TopCVSSScore   float64 // highest CVSS score across all findings (0 = none available)
	TopFixedIn     string  // fix version for the top-severity finding that has one ("" = none known)
	Findings       []store.SearchResult
	LLMAnalysis    string
	Err            error
}

func (r Result) Verdict() string {
	if r.Err != nil {
		return "ERROR"
	}
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
func (e *Engine) enhanceQueryText(ctx context.Context, query string) string {
	prompt := fmt.Sprintf(
		"Expand the following software vulnerability search query with related keywords, CVE patterns, and attack vectors. "+
			"Return only the expanded query as a single line, no explanation.\n\nQuery: %s", query)
	var sb strings.Builder
	if err := e.generator.Generate(ctx, prompt, &sb); err != nil {
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
func (e *Engine) AnalyzeDependency(ctx context.Context, dep parser.Dependency, out io.Writer) (Result, error) {
	result := Result{Dep: dep}

	query := fmt.Sprintf("%s package %s version %s vulnerability security", dep.Ecosystem, dep.Name, dep.Version)
	if e.cfg.EnhanceQuery {
		query = e.enhanceQueryText(ctx, query)
	}

	cacheKey := dep.Ecosystem + "\x00" + dep.Name + "\x00" + dep.Version
	e.embedMu.Lock()
	vec, cached := e.embedMemo[cacheKey]
	e.embedMu.Unlock()
	if !cached {
		var err error
		vec, err = e.embedder.Embed(ctx, query)
		if err != nil {
			result.Err = fmt.Errorf("embed query: %w", err)
			return result, nil
		}
		e.embedMu.Lock()
		e.embedMemo[cacheKey] = vec
		e.embedMu.Unlock()
	}

	hits, err := e.db.SearchBest(ctx, dep.Ecosystem, vec, e.cfg.TopK, e.cfg.SimilarityThreshold)
	if err != nil {
		result.Err = fmt.Errorf("vector search: %w", err)
		return result, nil
	}

	// Filter: package name match + version-aware + ignore list + min-severity + alias dedup.
	seenID := make(map[string]bool) // dedup by canonical ID and all aliases
	var relevant []store.SearchResult
	for _, r := range hits {
		// Skip if package is on the ignore list
		if e.cfg.IgnoreList != nil && e.cfg.IgnoreList.Package(r.Package) {
			continue
		}
		// Skip if this specific vuln ID (or any alias) is ignored
		if e.cfg.IgnoreList != nil {
			if e.cfg.IgnoreList.VulnID(r.ID) {
				continue
			}
			if slices.ContainsFunc(r.Aliases, e.cfg.IgnoreList.VulnID) {
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
		// Package name match (tiered: exact → module-path suffix → whole-word in content)
		if !packageMatches(r.Package, r.Content, dep.Name) {
			continue
		}
		// Version-aware: skip if already fixed
		if !version.AffectsVersion(dep.Version, r.FixedIn) {
			continue
		}
		// Min-severity filter
		if e.cfg.MinSeverity != "" && r.Severity != "" {
			if severityOrder[r.Severity] < severityOrder[e.cfg.MinSeverity] {
				continue
			}
		}
		// Min-CVSS filter: only skip findings that have a known score below the threshold.
		if e.cfg.MinCVSS > 0 && r.CVSSScore > 0 && r.CVSSScore < e.cfg.MinCVSS {
			continue
		}
		relevant = append(relevant, r)
	}

	// Sort by severity tier (desc) then CVSS score (desc) within each tier.
	slices.SortStableFunc(relevant, func(a, b store.SearchResult) int {
		ra, rb := severityOrder[a.Severity], severityOrder[b.Severity]
		if ra != rb {
			return rb - ra
		}
		if b.CVSSScore != a.CVSSScore {
			if b.CVSSScore > a.CVSSScore {
				return 1
			}
			return -1
		}
		return 0
	})

	result.RetrievedCount = len(relevant)
	result.TopSeverity = topSeverity(relevant)
	result.TopCVSSScore = topCVSSScore(relevant)
	result.TopFixedIn = topFixedIn(relevant)
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
	err = e.generator.Generate(ctx, buildPrompt(dep, relevant), writerFunc(func(p []byte) (int, error) {
		n, err := bw.Write(p)
		_ = bw.Flush()
		return n, err
	}))
	result.LLMAnalysis = llmBuf.String()
	if err != nil {
		result.Err = err
	}
	_, _ = fmt.Fprintln(out)
	return result, nil
}

func printCVETable(out io.Writer, results []store.SearchResult) {
	_, _ = fmt.Fprintln(out)
	t := tablewriter.NewWriter(out)
	t.Header("ID", "Package", "Severity", "CVSS", "Fixed In", "Score")
	for _, r := range results {
		sev := r.Severity
		if sev == "" {
			sev = "—"
		}
		fix := r.FixedIn
		if fix == "" {
			fix = "—"
		}
		cvss := "—"
		if r.CVSSScore > 0 {
			cvss = fmt.Sprintf("%.1f", r.CVSSScore)
		}
		_ = t.Append([]string{r.ID, r.Package, col.Severity(sev), cvss, fix, fmt.Sprintf("%.3f", r.Score)})
	}
	_ = t.Render()
}

func buildPrompt(dep parser.Dependency, results []store.SearchResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "You are a security researcher analyzing software dependencies for vulnerabilities.\n\n")
	fmt.Fprintf(&sb, "Dependency under analysis: %s version %s (ecosystem: %s)\n\n", dep.Name, dep.Version, dep.Ecosystem)
	fmt.Fprintf(&sb, "Known vulnerabilities retrieved from the database:\n\n")

	// Collect known fix versions so we can tailor the prompt.
	knownFixes := map[string]string{} // vuln ID → fixed-in version
	for i, r := range results {
		fmt.Fprintf(&sb, "--- Vulnerability %d ---\n", i+1)
		fmt.Fprintf(&sb, "ID: %s\n", r.ID)
		fmt.Fprintf(&sb, "Package: %s\n", r.Package)
		if r.Severity != "" {
			fmt.Fprintf(&sb, "Severity: %s\n", r.Severity)
		}
		if r.FixedIn != "" {
			fmt.Fprintf(&sb, "Fixed in: %s\n", r.FixedIn)
			knownFixes[r.ID] = r.FixedIn
		}
		fmt.Fprintf(&sb, "Details: %s\n\n", truncate(r.Content, 500))
	}

	fmt.Fprintf(&sb, "Based on the above, provide:\n")
	fmt.Fprintf(&sb, "1. Is this dependency vulnerable? (YES / NO / MAYBE)\n")
	fmt.Fprintf(&sb, "2. Severity level if vulnerable\n")
	fmt.Fprintf(&sb, "3. Specific CVE or advisory IDs that apply\n")
	if len(knownFixes) > 0 {
		fmt.Fprintf(&sb, "4. Confirm the upgrade path — fix versions are already listed above for each advisory\n")
	} else {
		fmt.Fprintf(&sb, "4. Recommended fix (upgrade version if applicable)\n")
	}
	fmt.Fprintf(&sb, "5. Brief explanation of the risk\n")
	return sb.String()
}

// topFixedIn returns the fix version of the first (highest-severity) finding
// that has one, or "" when no fix is known for any finding.
func topFixedIn(results []store.SearchResult) string {
	for _, r := range results {
		if r.FixedIn != "" {
			return r.FixedIn
		}
	}
	return ""
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

func topCVSSScore(results []store.SearchResult) float64 {
	var top float64
	for _, r := range results {
		if r.CVSSScore > top {
			top = r.CVSSScore
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

// packageMatches reports whether a vulnerability's package name corresponds to
// the given dependency using a tiered strategy that avoids false positives from
// plain substring matching (e.g. "requests" matching "requests-mock"):
//
//  1. Exact match (case-insensitive): "requests" == "requests"
//  2. Module-path suffix: "github.com/foo/requests" has suffix "/requests"
//  3. Whole-word scan of the vulnerability content (fallback for advisory text)
func packageMatches(vulnPackage, content, depName string) bool {
	pkg := strings.ToLower(vulnPackage)
	dep := strings.ToLower(depName)
	if pkg == dep {
		return true
	}
	if strings.HasSuffix(pkg, "/"+dep) {
		return true
	}
	return containsWholeWord(strings.ToLower(content), dep)
}

// containsWholeWord reports whether word appears as a whole word in s, where
// word boundaries are any character that is not part of a package/module name
// (alphanumeric, hyphen, underscore, dot).
func containsWholeWord(s, word string) bool {
	n := len(word)
	for i := 0; i <= len(s)-n; i++ {
		if s[i:i+n] == word {
			before := i == 0 || !isPkgNameChar(s[i-1])
			after := i+n == len(s) || !isPkgNameChar(s[i+n])
			if before && after {
				return true
			}
		}
	}
	return false
}

// isPkgNameChar returns true for characters that can appear inside a package or
// module name, used to detect word boundaries in vulnerability content.
func isPkgNameChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.'
}

// writerFunc adapts a func to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
