package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	col "github.com/abhishekamralkar/argus/internal/color"
	"github.com/abhishekamralkar/argus/internal/config"
	"github.com/abhishekamralkar/argus/internal/embed"
	"github.com/abhishekamralkar/argus/internal/ignore"
	"github.com/abhishekamralkar/argus/internal/ingest"
	"github.com/abhishekamralkar/argus/internal/llm"
	"github.com/abhishekamralkar/argus/internal/output"
	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/rag"
	"github.com/abhishekamralkar/argus/internal/store"
)

// Version is set at build time via -ldflags "-X main.Version=v1.2.3".
var Version = "dev"

func main() {
	root := &cobra.Command{
		Use:   "argus",
		Short: "RAG-based vulnerability scanner for Go, Python, and Rust projects",
	}

	var dbPath string
	root.PersistentFlags().StringVar(&dbPath, "db", "./vulns.db", "path to DuckDB database file")

	root.AddCommand(ingestCmd(&dbPath))
	root.AddCommand(scanCmd(&dbPath))
	root.AddCommand(searchCmd(&dbPath))
	root.AddCommand(statusCmd(&dbPath))
	root.AddCommand(versionCmd())
	root.AddCommand(completionCmd(root))

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("argus %s\n", Version)
		},
	}
}

func completionCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate shell completion script",
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(os.Stdout)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
	}
}

func statusCmd(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show vulnerability database statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()

			rows, err := db.Status()
			if err != nil {
				return fmt.Errorf("status: %w", err)
			}
			if len(rows) == 0 {
				fmt.Println("Database is empty. Run: argus ingest")
				return nil
			}

			fmt.Printf("\n%s\n\n", col.Bold("Vulnerability Database — %s", *dbPath))
			t := tablewriter.NewWriter(os.Stdout)
			t.Header("Ecosystem", "Vulnerabilities", "Chunks", "Last Ingest")
			for _, r := range rows {
				last := r.LastIngest
				if last == "" {
					last = "—"
				}
				chunks := fmt.Sprintf("%d", r.ChunkCount)
				if r.ChunkCount == 0 {
					chunks = "—"
				}
				_ = t.Append([]string{r.Ecosystem, fmt.Sprintf("%d", r.VulnCount), chunks, last})
			}
			_ = t.Render()
			fmt.Println()
			return nil
		},
	}
}

// ── ingest ──────────────────────────────────────────────────────────────────

type chunkConfig struct {
	enabled bool
	size    int
	overlap int
}

func ingestCmd(dbPath *string) *cobra.Command {
	var ecosystems string
	var embedModel string
	var workers int
	var skipExisting bool
	var noChunk bool
	var chunkSize int
	var chunkOverlap int

	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Download vulnerability databases and store embeddings",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !noChunk {
				if chunkSize <= 0 {
					return fmt.Errorf("--chunk-size must be positive, got %d", chunkSize)
				}
				if chunkOverlap < 0 || chunkOverlap >= chunkSize {
					return fmt.Errorf("--chunk-overlap must be in [0, chunk-size), got %d (chunk-size=%d)", chunkOverlap, chunkSize)
				}
			}

			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()

			cc := chunkConfig{
				enabled: !noChunk,
				size:    chunkSize,
				overlap: chunkOverlap,
			}

			embedder := embed.NewClient(embedModel)
			for eco := range strings.SplitSeq(ecosystems, ",") {
				eco = strings.TrimSpace(eco)
				if eco == "" {
					continue
				}
				if err := runIngest(db, embedder, eco, workers, skipExisting, cc); err != nil {
					fmt.Fprintf(os.Stderr, "ingest %s: %v\n", eco, err)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&ecosystems, "ecosystems", "go,python,rust", "comma-separated ecosystems to ingest")
	cmd.Flags().StringVar(&embedModel, "embed-model", "", "Ollama embedding model (default: nomic-embed-text)")
	cmd.Flags().IntVar(&workers, "workers", 8, "parallel embedding workers")
	cmd.Flags().BoolVar(&skipExisting, "skip-existing", true, "skip vulnerabilities already in the database")
	cmd.Flags().BoolVar(&noChunk, "no-chunk", false, "disable document chunking (store whole advisory as one embedding)")
	cmd.Flags().IntVar(&chunkSize, "chunk-size", ingest.DefaultChunkSize, "max characters per chunk")
	cmd.Flags().IntVar(&chunkOverlap, "chunk-overlap", ingest.DefaultChunkOverlap, "overlap characters between chunks")
	return cmd
}

const batchSize = 50

func runIngest(db *store.DB, embedder *embed.Client, ecosystem string, numWorkers int, skipExisting bool, cc chunkConfig) error {
	type source struct {
		name string
		fn   func(func(*store.Vulnerability) error) error
	}

	var sources []source
	switch ecosystem {
	case "go":
		sources = []source{
			{"OSV/Go", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("Go", fn) }},
			{"GoVulnDB", ingest.LoadGoVulnDB},
		}
	case "python":
		sources = []source{
			{"OSV/PyPI", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("PyPI", fn) }},
			{"PyPA", ingest.LoadPyPA},
		}
	case "rust":
		sources = []source{
			{"OSV/crates.io", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("crates.io", fn) }},
			{"RustSec", ingest.LoadRustSec},
		}
	default:
		return fmt.Errorf("unknown ecosystem: %s (valid: go, python, rust)", ecosystem)
	}

	for _, src := range sources {
		fmt.Printf("Ingesting %s (workers=%d, chunk=%v)...\n", src.name, numWorkers, cc.enabled)
		if err := ingestSource(db, embedder, src.name, src.fn, numWorkers, skipExisting, cc); err != nil {
			fmt.Fprintf(os.Stderr, "  source %s failed: %v\n", src.name, err)
		}
	}

	count, _ := db.Count(ecosystem)
	fmt.Printf("Total %s vulnerabilities stored: %d\n", ecosystem, count)
	return nil
}

// chunkWork is the unit sent to embed workers when chunking is enabled.
type chunkWork struct {
	vuln    *store.Vulnerability
	chunkID string
	text    string
}

// chunkResult is what workers send to the batch writer when chunking.
type chunkResult struct {
	vuln *store.Vulnerability
	item store.ChunkItem
}

func ingestSource(
	db *store.DB,
	embedder *embed.Client,
	name string,
	loader func(func(*store.Vulnerability) error) error,
	numWorkers int,
	skipExisting bool,
	cc chunkConfig,
) error {
	bar := progressbar.Default(-1, name)
	var errCount atomic.Int64

	if cc.enabled {
		return ingestSourceChunked(db, embedder, name, loader, numWorkers, skipExisting, cc, bar, &errCount)
	}
	return ingestSourceWhole(db, embedder, name, loader, numWorkers, skipExisting, bar, &errCount)
}

func ingestSourceWhole(
	db *store.DB,
	embedder *embed.Client,
	name string,
	loader func(func(*store.Vulnerability) error) error,
	numWorkers int,
	skipExisting bool,
	bar interface{ Add(int) error },
	errCount *atomic.Int64,
) error {
	workCh := make(chan *store.Vulnerability, numWorkers*4)
	resultCh := make(chan store.EmbeddedVuln, numWorkers*4)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Go(func() {
			for v := range workCh {
				vec, err := embedder.Embed(v.Summary + "\n" + v.Details)
				if err != nil {
					errCount.Add(1)
					continue
				}
				resultCh <- store.EmbeddedVuln{Vuln: v, Embedding: vec}
			}
		})
	}
	go func() { wg.Wait(); close(resultCh) }()

	writerDone := make(chan error, 1)
	go func() {
		batch := make([]store.EmbeddedVuln, 0, batchSize)
		flush := func() {
			if err := db.UpsertBatch(batch); err != nil {
				errCount.Add(int64(len(batch)))
			} else {
				_ = bar.Add(len(batch))
			}
			batch = batch[:0]
		}
		for item := range resultCh {
			batch = append(batch, item)
			if len(batch) >= batchSize {
				flush()
			}
		}
		if len(batch) > 0 {
			flush()
		}
		writerDone <- nil
	}()

	err := loader(func(v *store.Vulnerability) error {
		if skipExisting {
			exists, err := db.Exists(v.ID)
			if err != nil {
				return err
			}
			if exists {
				return nil
			}
		}
		workCh <- v
		return nil
	})
	close(workCh)
	<-writerDone

	if n := errCount.Load(); n > 0 {
		fmt.Printf("  %s: %d entries skipped due to errors\n", name, n)
	}
	_ = db.TouchIngestLog(name)
	return err
}

func ingestSourceChunked(
	db *store.DB,
	embedder *embed.Client,
	name string,
	loader func(func(*store.Vulnerability) error) error,
	numWorkers int,
	skipExisting bool,
	cc chunkConfig,
	bar interface{ Add(int) error },
	errCount *atomic.Int64,
) error {
	workCh := make(chan chunkWork, numWorkers*4)
	resultCh := make(chan chunkResult, numWorkers*4)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Go(func() {
			for w := range workCh {
				vec, err := embedder.Embed(w.text)
				if err != nil {
					errCount.Add(1)
					continue
				}
				resultCh <- chunkResult{
					vuln: w.vuln,
					item: store.ChunkItem{
						ChunkID:   w.chunkID,
						VulnID:    w.vuln.ID,
						Content:   w.text,
						Embedding: vec,
					},
				}
			}
		})
	}
	go func() { wg.Wait(); close(resultCh) }()

	writerDone := make(chan error, 1)
	go func() {
		batch := make([]store.ChunkItem, 0, batchSize)
		flush := func() {
			if err := db.UpsertChunkBatch(batch); err != nil {
				errCount.Add(int64(len(batch)))
			} else {
				_ = bar.Add(len(batch))
			}
			batch = batch[:0]
		}
		for r := range resultCh {
			batch = append(batch, r.item)
			if len(batch) >= batchSize {
				flush()
			}
		}
		if len(batch) > 0 {
			flush()
		}
		writerDone <- nil
	}()

	err := loader(func(v *store.Vulnerability) error {
		if skipExisting {
			exists, err := db.ExistsVuln(v.ID)
			if err != nil {
				return err
			}
			if exists {
				return nil
			}
		}
		// Delete stale chunks before re-ingesting so count doesn't grow unbounded.
		_ = db.DeleteChunksForVuln(v.ID)
		if err := db.UpsertVulnMeta(v); err != nil {
			errCount.Add(1)
			return nil
		}
		text := v.Summary
		if v.Details != "" {
			text += "\n" + v.Details
		}
		chunks := ingest.ChunkText(text, cc.size, cc.overlap)
		for i, chunk := range chunks {
			workCh <- chunkWork{
				vuln:    v,
				chunkID: fmt.Sprintf("%s_c%d", v.ID, i),
				text:    chunk,
			}
		}
		return nil
	})
	close(workCh)
	<-writerDone

	if n := errCount.Load(); n > 0 {
		fmt.Printf("  %s: %d chunks skipped due to errors\n", name, n)
	}
	_ = db.TouchIngestLog(name)
	return err
}

// ── scan ─────────────────────────────────────────────────────────────────────

func scanCmd(dbPath *string) *cobra.Command {
	var llmModel string
	var embedModel string
	var outputFmt string
	var enhanceQuery bool
	var workers int
	var minSeverity string
	var failOn string
	var timeoutMin int

	cmd := &cobra.Command{
		Use:   "scan <project-dir>",
		Short: "Scan a project's dependency files for vulnerabilities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectDir := args[0]

			ctx := context.Background()
			if timeoutMin > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMin)*time.Minute)
				defer cancel()
			}

			// Load config file; CLI flags take precedence
			cfg, _ := config.Load(projectDir)
			if llmModel == "" {
				llmModel = cfg.LLMModel
			}
			if embedModel == "" {
				embedModel = cfg.EmbedModel
			}
			if minSeverity == "" {
				minSeverity = cfg.MinSeverity
			}
			if workers == 4 && cfg.Workers > 0 {
				workers = cfg.Workers
			}

			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()

			ignoreList, err := ignore.Load(projectDir)
			if err != nil {
				return fmt.Errorf("load ignore list: %w", err)
			}

			embedder := embed.NewClient(embedModel)
			generator := llm.NewClient(llmModel)
			engine := rag.NewEngine(db, embedder, generator, enhanceQuery, minSeverity, ignoreList)

			deps, err := detectAndParse(projectDir)
			if err != nil {
				return err
			}
			if len(deps) == 0 {
				fmt.Println("No dependency files found (go.mod, requirements.txt, Cargo.toml).")
				return nil
			}

			isText := outputFmt == "text"

			if isText {
				fmt.Printf("\n╔══════════════════════════════════════════════════════╗\n")
				fmt.Printf("║  argus scan: %-39s║\n", truncatePath(projectDir, 39))
				fmt.Printf("║  %d dependencies found%-32s║\n", len(deps), "")
				fmt.Printf("╚══════════════════════════════════════════════════════╝\n\n")
			}

			results := parallelScan(ctx, engine, deps, workers, isText)

			switch outputFmt {
			case "json":
				return output.WriteJSON(os.Stdout, results)
			case "sarif":
				return output.WriteSARIF(os.Stdout, results, projectDir)
			default:
				printSummaryTable(results)
			}

			threshold := failOn
			if threshold == "" {
				threshold = "HIGH"
			}
			for _, r := range results {
				v := r.Verdict()
				if v == "CRITICAL" || v == "ERROR" || v == threshold ||
					(threshold == "MEDIUM" && (v == "HIGH" || v == "CRITICAL" || v == "ERROR")) ||
					(threshold == "LOW" && v != "OK" && v != "REVIEW") {
					os.Exit(1)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&llmModel, "llm-model", "", "Ollama LLM model (default: gpt-oss:20b)")
	cmd.Flags().StringVar(&embedModel, "embed-model", "", "Ollama embedding model (default: nomic-embed-text)")
	cmd.Flags().StringVar(&outputFmt, "output", "text", "output format: text, json, or sarif")
	cmd.Flags().BoolVar(&enhanceQuery, "enhance-query", false, "use LLM to expand search queries before embedding")
	cmd.Flags().IntVar(&workers, "workers", 4, "parallel dependency analysis workers")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL")
	cmd.Flags().StringVar(&failOn, "fail-on", "HIGH", "minimum severity that causes non-zero exit: LOW, MEDIUM, HIGH, CRITICAL")
	cmd.Flags().IntVar(&timeoutMin, "timeout", 30, "scan timeout in minutes (0 = no timeout)")
	return cmd
}

// parallelScan runs AnalyzeDependency for each dep concurrently, preserving order.
func parallelScan(ctx context.Context, engine *rag.Engine, deps []parser.Dependency, workers int, verbose bool) []rag.Result {
	type indexed struct {
		i      int
		result rag.Result
	}

	depCh := make(chan struct {
		i   int
		dep parser.Dependency
	}, len(deps))
	for i, d := range deps {
		depCh <- struct {
			i   int
			dep parser.Dependency
		}{i, d}
	}
	close(depCh)

	resultCh := make(chan indexed, len(deps))

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for work := range depCh {
				var out strings.Builder
				if verbose {
					fmt.Printf("┌─ [%d/%d] %s @ %s (%s)\n",
						work.i+1, len(deps), work.dep.Name, work.dep.Version, work.dep.Ecosystem)
				}
				r, err := engine.AnalyzeDependency(work.dep, os.Stdout)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  analysis failed for %s: %v\n", work.dep.Name, err)
				}
				_ = out
				if verbose {
					fmt.Println()
				}
				if ctx.Err() != nil {
					return
				}
				resultCh <- indexed{work.i, r}
			}
		})
	}

	go func() { wg.Wait(); close(resultCh) }()

	results := make([]rag.Result, len(deps))
	for ir := range resultCh {
		results[ir.i] = ir.result
	}
	return results
}

func detectAndParse(dir string) ([]parser.Dependency, error) {
	var all []parser.Dependency

	candidates := []struct {
		file   string
		parser func(string) ([]parser.Dependency, error)
	}{
		{"go.mod", parser.ParseGoMod},
		{"requirements.txt", parser.ParseRequirements},
		{"Cargo.toml", parser.ParseCargoToml},
	}

	for _, c := range candidates {
		path := filepath.Join(dir, c.file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		deps, err := c.parser(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", c.file, err)
			continue
		}
		all = append(all, deps...)
	}
	return all, nil
}

// ── search ───────────────────────────────────────────────────────────────────

func searchCmd(dbPath *string) *cobra.Command {
	var ecosystem string
	var embedModel string
	var limit int

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Semantic search against the vulnerability database",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := strings.Join(args, " ")

			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()

			embedder := embed.NewClient(embedModel)
			vec, err := embedder.Embed(query)
			if err != nil {
				return fmt.Errorf("embed query: %w", err)
			}

			results, err := db.Search(ecosystem, vec, limit)
			if err != nil {
				return fmt.Errorf("search: %w", err)
			}

			if len(results) == 0 {
				fmt.Println("No results found.")
				return nil
			}

			for _, r := range results {
				fmt.Printf("[%.3f] %s | %s | %s | fixed: %s\n", r.Score, r.ID, r.Package, r.Severity, r.FixedIn)
				if r.Content != "" {
					lines := strings.SplitN(r.Content, "\n", 3)
					fmt.Printf("  %s\n", lines[0])
				}
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&ecosystem, "ecosystem", "go", "ecosystem to search: go, python, rust")
	cmd.Flags().StringVar(&embedModel, "embed-model", "", "Ollama embedding model (default: nomic-embed-text)")
	cmd.Flags().IntVar(&limit, "limit", 10, "maximum results to return")
	return cmd
}

// ── helpers ──────────────────────────────────────────────────────────────────

func printSummaryTable(results []rag.Result) {
	fmt.Printf("\n%s\n\n", col.Bold("SCAN SUMMARY"))

	t := tablewriter.NewWriter(os.Stdout)
	t.Header("Package", "Version", "Ecosystem", "CVEs Found", "Top Severity", "Verdict")
	for _, r := range results {
		sev := r.TopSeverity
		if sev == "" {
			sev = "—"
		}
		_ = t.Append([]string{
			r.Dep.Name,
			r.Dep.Version,
			r.Dep.Ecosystem,
			fmt.Sprintf("%d", r.RetrievedCount),
			col.Severity(sev),
			col.Verdict(r.Verdict()),
		})
	}
	_ = t.Render()
}

func truncatePath(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return "..." + s[len(s)-(maxLen-3):]
}
