package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

var validFailOnValues = map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}

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
			ctx := cmd.Context()
			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()

			rows, err := db.Status(ctx)
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
	var timeoutMin int
	var quiet bool

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

			ctx := context.Background()
			if timeoutMin > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMin)*time.Minute)
				defer cancel()
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
			var errs []error
			for eco := range strings.SplitSeq(ecosystems, ",") {
				eco = strings.TrimSpace(eco)
				if eco == "" {
					continue
				}
				if ctx.Err() != nil {
					errs = append(errs, fmt.Errorf("ingest cancelled: %w", ctx.Err()))
					break
				}
				if err := runIngest(ctx, db, embedder, eco, workers, skipExisting, cc, quiet); err != nil {
					fmt.Fprintf(os.Stderr, "ingest %s: %v\n", eco, err)
					errs = append(errs, fmt.Errorf("%s: %w", eco, err))
				}
			}
			return errors.Join(errs...)
		},
	}
	cmd.Flags().StringVar(&ecosystems, "ecosystems", "go,python,rust", "comma-separated ecosystems to ingest")
	cmd.Flags().StringVar(&embedModel, "embed-model", "", "Ollama embedding model (default: nomic-embed-text)")
	cmd.Flags().IntVar(&workers, "workers", 8, "parallel embedding workers")
	cmd.Flags().BoolVar(&skipExisting, "skip-existing", true, "skip vulnerabilities already in the database")
	cmd.Flags().BoolVar(&noChunk, "no-chunk", false, "disable document chunking (store whole advisory as one embedding)")
	cmd.Flags().IntVar(&chunkSize, "chunk-size", ingest.DefaultChunkSize, "max characters per chunk")
	cmd.Flags().IntVar(&chunkOverlap, "chunk-overlap", ingest.DefaultChunkOverlap, "overlap characters between chunks")
	cmd.Flags().IntVar(&timeoutMin, "timeout", 0, "ingest timeout in minutes (0 = no timeout)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress progress bar output (useful in CI)")
	return cmd
}

const batchSize = 50

func runIngest(ctx context.Context, db *store.DB, embedder *embed.Client, ecosystem string, numWorkers int, skipExisting bool, cc chunkConfig, quiet bool) error {
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

	var errs []error
	for _, src := range sources {
		fmt.Printf("Ingesting %s (workers=%d, chunk=%v)...\n", src.name, numWorkers, cc.enabled)
		if err := ingestSource(ctx, db, embedder, src.name, src.fn, numWorkers, skipExisting, cc, quiet); err != nil {
			fmt.Fprintf(os.Stderr, "  source %s failed: %v\n", src.name, err)
			errs = append(errs, fmt.Errorf("%s: %w", src.name, err))
		}
	}

	count, _ := db.Count(ctx, ecosystem)
	fmt.Printf("Total %s vulnerabilities stored: %d\n", ecosystem, count)
	return errors.Join(errs...)
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

// progressAdder is the minimal interface used by ingest pipeline stages.
type progressAdder interface{ Add(int) error }

// noopProgress is a silent drop-in for progressbar used when --quiet is set.
type noopProgress struct{}

func (noopProgress) Add(int) error { return nil }

func ingestSource(
	ctx context.Context,
	db *store.DB,
	embedder *embed.Client,
	name string,
	loader func(func(*store.Vulnerability) error) error,
	numWorkers int,
	skipExisting bool,
	cc chunkConfig,
	quiet bool,
) error {
	var bar progressAdder
	if quiet {
		bar = noopProgress{}
	} else {
		bar = progressbar.Default(-1, name)
	}
	var errCount atomic.Int64

	if cc.enabled {
		return ingestSourceChunked(ctx, db, embedder, name, loader, numWorkers, skipExisting, cc, bar, &errCount)
	}
	return ingestSourceWhole(ctx, db, embedder, name, loader, numWorkers, skipExisting, bar, &errCount)
}

func ingestSourceWhole(
	ctx context.Context,
	db *store.DB,
	embedder *embed.Client,
	name string,
	loader func(func(*store.Vulnerability) error) error,
	numWorkers int,
	skipExisting bool,
	bar progressAdder,
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
					slog.Warn("embed failed, skipping vulnerability", "vuln_id", v.ID, "source", name, "error", err)
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
			if err := db.UpsertBatch(ctx, batch); err != nil {
				slog.Warn("batch upsert failed", "source", name, "size", len(batch), "error", err)
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
			exists, err := db.Exists(ctx, v.ID)
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
	_ = db.TouchIngestLog(ctx, name)
	return err
}

func ingestSourceChunked(
	ctx context.Context,
	db *store.DB,
	embedder *embed.Client,
	name string,
	loader func(func(*store.Vulnerability) error) error,
	numWorkers int,
	skipExisting bool,
	cc chunkConfig,
	bar progressAdder,
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
					slog.Warn("embed failed, dropping chunk", "vuln_id", w.vuln.ID, "chunk_id", w.chunkID, "source", name, "error", err)
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
			if err := db.UpsertChunkBatch(ctx, batch); err != nil {
				slog.Warn("chunk batch upsert failed", "source", name, "size", len(batch), "error", err)
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
			exists, err := db.ExistsVuln(ctx, v.ID)
			if err != nil {
				return err
			}
			if exists {
				return nil
			}
		}
		// Delete stale chunks before re-ingesting so count doesn't grow unbounded.
		_ = db.DeleteChunksForVuln(ctx, v.ID)
		if err := db.UpsertVulnMeta(ctx, v); err != nil {
			slog.Warn("upsert vuln meta failed", "vuln_id", v.ID, "source", name, "error", err)
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
	_ = db.TouchIngestLog(ctx, name)
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
	var similarityThreshold float64

	cmd := &cobra.Command{
		Use:   "scan <project-dir>",
		Short: "Scan a project's dependency files for vulnerabilities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectDir := args[0]

			if !validFailOnValues[strings.ToUpper(failOn)] {
				return fmt.Errorf("--fail-on must be one of LOW, MEDIUM, HIGH, CRITICAL (got %q)", failOn)
			}
			failOn = strings.ToUpper(failOn)

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
			engine := rag.NewEngine(db, embedder, generator, rag.EngineConfig{
				EnhanceQuery:        enhanceQuery,
				MinSeverity:         minSeverity,
				SimilarityThreshold: similarityThreshold,
				IgnoreList:          ignoreList,
			})

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
			case "cyclonedx":
				return output.WriteCycloneDX(os.Stdout, results)
			case "spdx":
				return output.WriteSPDX(os.Stdout, results, filepath.Base(projectDir))
			default:
				printSummaryTable(results)
			}

			for _, r := range results {
				if exceedsSeverity(r.Verdict(), failOn) {
					os.Exit(1)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&llmModel, "llm-model", "", "Ollama LLM model (default: gpt-oss:20b)")
	cmd.Flags().StringVar(&embedModel, "embed-model", "", "Ollama embedding model (default: nomic-embed-text)")
	cmd.Flags().StringVar(&outputFmt, "output", "text", "output format: text, json, sarif, cyclonedx, or spdx")
	cmd.Flags().BoolVar(&enhanceQuery, "enhance-query", false, "use LLM to expand search queries before embedding")
	cmd.Flags().IntVar(&workers, "workers", 4, "parallel dependency analysis workers")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL")
	cmd.Flags().StringVar(&failOn, "fail-on", "HIGH", "minimum severity that causes non-zero exit: LOW, MEDIUM, HIGH, CRITICAL")
	cmd.Flags().IntVar(&timeoutMin, "timeout", 30, "scan timeout in minutes (0 = no timeout)")
	cmd.Flags().Float64Var(&similarityThreshold, "similarity-threshold", store.DefaultSimilarityThreshold, "cosine similarity cutoff for vector search (0–1); raise to reduce false positives")
	return cmd
}

var severityRank = map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "ERROR": 5}

// exceedsSeverity returns true when verdict is at or above the threshold level.
func exceedsSeverity(verdict, threshold string) bool {
	return severityRank[verdict] >= severityRank[threshold]
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
				if verbose {
					fmt.Printf("┌─ [%d/%d] %s @ %s (%s)\n",
						work.i+1, len(deps), work.dep.Name, work.dep.Version, work.dep.Ecosystem)
				}
				r, err := engine.AnalyzeDependency(ctx, work.dep, os.Stdout)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  analysis failed for %s: %v\n", work.dep.Name, err)
				}
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
	var similarityThreshold float64

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Semantic search against the vulnerability database",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
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

			results, err := db.Search(ctx, ecosystem, vec, limit, similarityThreshold)
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
	cmd.Flags().Float64Var(&similarityThreshold, "similarity-threshold", store.DefaultSimilarityThreshold, "cosine similarity cutoff for vector search (0–1)")
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
