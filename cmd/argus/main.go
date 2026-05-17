package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/abhishekamralkar/argus/internal/attest"
	"github.com/abhishekamralkar/argus/internal/baseline"
	"github.com/abhishekamralkar/argus/internal/cache"
	col "github.com/abhishekamralkar/argus/internal/color"
	"github.com/abhishekamralkar/argus/internal/config"
	"github.com/abhishekamralkar/argus/internal/doctor"
	"github.com/abhishekamralkar/argus/internal/embed"
	argerr "github.com/abhishekamralkar/argus/internal/errs"
	"github.com/abhishekamralkar/argus/internal/ignore"
	"github.com/abhishekamralkar/argus/internal/ingest"
	"github.com/abhishekamralkar/argus/internal/llm"
	"github.com/abhishekamralkar/argus/internal/output"
	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/rag"
	"github.com/abhishekamralkar/argus/internal/store"
	"github.com/abhishekamralkar/argus/internal/web"
	"github.com/abhishekamralkar/argus/pkg/plugin"
)

// Version is set at build time via -ldflags "-X main.Version=v1.2.3".
var Version = "dev"

var validFailOnValues = map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}

// parseSince parses a --since flag value as YYYY-MM-DD or RFC3339.
func parseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("--since: cannot parse %q (use YYYY-MM-DD or RFC3339)", s)
}

// effectiveDate returns the later of published and modified (the date that
// determines whether an advisory is "new" relative to a since cutoff).
func effectiveDate(published, modified time.Time) time.Time {
	if modified.After(published) {
		return modified
	}
	return published
}

// validateFailOn accepts severity labels (LOW–CRITICAL) and "cvss:N.N" format.
func validateFailOn(s string) error {
	if validFailOnValues[strings.ToUpper(s)] {
		return nil
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "cvss:") {
		val := s[5:]
		score, err := strconv.ParseFloat(val, 64)
		if err != nil || score < 0 || score > 10 {
			return fmt.Errorf("--fail-on cvss: threshold must be a number 0.0–10.0 (got %q)", val)
		}
		return nil
	}
	return fmt.Errorf("--fail-on must be LOW, MEDIUM, HIGH, CRITICAL, or cvss:N.N (got %q)", s)
}

// failOnExceeded returns true when a result's severity or CVSS score meets the
// --fail-on threshold. The cvss: form only triggers when a score is known (>0).
func failOnExceeded(r rag.Result, failOn string) bool {
	if strings.HasPrefix(strings.ToLower(failOn), "cvss:") {
		threshold, _ := strconv.ParseFloat(failOn[5:], 64)
		return r.TopCVSSScore > 0 && r.TopCVSSScore >= threshold
	}
	return exceedsSeverity(r.Verdict(), strings.ToUpper(failOn))
}

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
	root.AddCommand(baselineCmd(&dbPath))
	root.AddCommand(doctorCmd(&dbPath))
	root.AddCommand(pluginsCmd())
	root.AddCommand(serveCmd(&dbPath))
	root.AddCommand(dbManageCmd(&dbPath))
	root.AddCommand(configCmd())
	root.AddCommand(verifyCmd())
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

			if fc, err := cache.New(); err == nil {
				if sz, err := fc.Size(); err == nil {
					fmt.Printf("Feed cache: %s (%s)\n\n", fc.Dir(), formatBytes(sz))
				}
			}

			return nil
		},
	}
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ── db management ───────────────────────────────────────────────────────────

func dbManageCmd(dbPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Manage the vulnerability database file",
	}
	cmd.AddCommand(dbStatsCmd(dbPath))
	cmd.AddCommand(dbResetCmd(dbPath))
	cmd.AddCommand(dbCompactCmd(dbPath))
	return cmd
}

func dbStatsCmd(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show row counts and file size",
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

			if fi, err := os.Stat(*dbPath); err == nil {
				fmt.Printf("\nFile: %s (%s)\n", *dbPath, formatBytes(fi.Size()))
			}
			return nil
		},
	}
}

func dbResetCmd(dbPath *string) *cobra.Command {
	var hard bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Clear all data (keeps file) or delete the database file entirely (--hard)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if hard {
				fmt.Printf("Deleting %s ...\n", *dbPath)
				if err := os.Remove(*dbPath); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("delete db: %w", err)
				}
				fmt.Println("Database file deleted.")
				return nil
			}
			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()
			fmt.Printf("Resetting %s ...\n", *dbPath)
			if err := db.Reset(ctx); err != nil {
				return fmt.Errorf("reset: %w", err)
			}
			fmt.Println("Database reset. All tables cleared and recreated.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&hard, "hard", false, "delete the .db file entirely instead of clearing tables")
	return cmd
}

func dbCompactCmd(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "compact",
		Short: "Run CHECKPOINT to reclaim space after bulk deletes",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()
			fmt.Printf("Compacting %s ...\n", *dbPath)
			if err := db.Compact(ctx); err != nil {
				return fmt.Errorf("compact: %w", err)
			}
			fmt.Println("Done.")
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
	var noCache bool
	var sinceStr string
	var full bool
	var profileName string

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

			sinceTime, err := parseSince(sinceStr)
			if err != nil {
				return err
			}

			// Apply profile values for ingest-relevant fields.
			if profileName != "" {
				cfg, _ := config.Load(".")
				if p, ok := cfg.ResolveProfile(profileName); ok {
					if !cmd.Flags().Changed("workers") && p.Workers > 0 {
						workers = p.Workers
					}
					if !cmd.Flags().Changed("embed-model") && p.EmbedModel != "" {
						embedModel = p.EmbedModel
					}
				} else {
					return fmt.Errorf("unknown profile %q (run: argus config profiles list)", profileName)
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

			var feedCache *cache.Cache
			if !noCache {
				feedCache, err = cache.New()
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not initialise feed cache: %v — downloading without cache\n", err)
				} else {
					fmt.Printf("Feed cache: %s\n", feedCache.Dir())
				}
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
				if err := runIngest(ctx, db, embedder, feedCache, eco, workers, skipExisting, cc, quiet, sinceTime, full); err != nil {
					fmt.Fprintf(os.Stderr, "ingest %s: %s\n", eco, formatError(err))
					errs = append(errs, fmt.Errorf("%s: %w", eco, err))
				}
			}
			// Record the embedding model and dimension so scan can detect mismatches.
			if dim, probeErr := embedder.Dimension(ctx); probeErr == nil {
				_ = db.SetMeta(ctx, "embed_model", embedder.Model())
				_ = db.SetMeta(ctx, "embed_dim", strconv.Itoa(dim))
			}
			return errors.Join(errs...)
		},
	}
	cmd.Flags().StringVar(&ecosystems, "ecosystems", "go,python,rust", "comma-separated ecosystems to ingest (go, python, rust, npm)")
	cmd.Flags().StringVar(&embedModel, "embed-model", "", "Ollama embedding model (default: nomic-embed-text)")
	cmd.Flags().IntVar(&workers, "workers", 8, "parallel embedding workers")
	cmd.Flags().BoolVar(&skipExisting, "skip-existing", true, "skip vulnerabilities already in the database")
	cmd.Flags().BoolVar(&noChunk, "no-chunk", false, "disable document chunking (store whole advisory as one embedding)")
	cmd.Flags().IntVar(&chunkSize, "chunk-size", ingest.DefaultChunkSize, "max characters per chunk")
	cmd.Flags().IntVar(&chunkOverlap, "chunk-overlap", ingest.DefaultChunkOverlap, "overlap characters between chunks")
	cmd.Flags().IntVar(&timeoutMin, "timeout", 0, "ingest timeout in minutes (0 = no timeout)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress progress bar output (useful in CI)")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "disable local feed cache; always re-download zip archives")
	cmd.Flags().StringVar(&sinceStr, "since", "", "only ingest advisories published/modified after this date (YYYY-MM-DD or RFC3339); auto-detected from last ingest when omitted")
	cmd.Flags().BoolVar(&full, "full", false, "re-process all advisories regardless of last-ingest time (does not bypass --no-cache)")
	cmd.Flags().StringVar(&profileName, "profile", "", "named profile from .argus.yaml or built-in; applies workers and embed-model")
	return cmd
}

const (
	batchSize      = 50 // DB write batch size
	embedBatchSize = 32 // embedding API mini-batch size
)

func runIngest(ctx context.Context, db *store.DB, embedder *embed.Client, c *cache.Cache, ecosystem string, numWorkers int, skipExisting bool, cc chunkConfig, quiet bool, globalSince time.Time, full bool) error {
	type source struct {
		name string
		fn   func(func(*store.Vulnerability) error) error
	}

	var sources []source
	switch ecosystem {
	case "go":
		sources = []source{
			{"OSV/Go", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("Go", c, fn) }},
			{"GoVulnDB", func(fn func(*store.Vulnerability) error) error { return ingest.LoadGoVulnDB(c, fn) }},
		}
	case "python":
		sources = []source{
			{"OSV/PyPI", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("PyPI", c, fn) }},
			{"PyPA", func(fn func(*store.Vulnerability) error) error { return ingest.LoadPyPA(c, fn) }},
		}
	case "rust":
		sources = []source{
			{"OSV/crates.io", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("crates.io", c, fn) }},
			{"RustSec", func(fn func(*store.Vulnerability) error) error { return ingest.LoadRustSec(c, fn) }},
		}
	case "npm":
		sources = []source{
			{"OSV/npm", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("npm", c, fn) }},
		}
	case "maven":
		sources = []source{
			{"OSV/Maven", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("Maven", c, fn) }},
		}
	case "nuget":
		sources = []source{
			{"OSV/NuGet", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("NuGet", c, fn) }},
		}
	case "ruby":
		sources = []source{
			{"OSV/RubyGems", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("RubyGems", c, fn) }},
		}
	case "php":
		sources = []source{
			{"OSV/Packagist", func(fn func(*store.Vulnerability) error) error { return ingest.LoadOSV("Packagist", c, fn) }},
		}
	default:
		return fmt.Errorf("unknown ecosystem: %s (valid: go, python, rust, npm, maven, nuget, ruby, php)", ecosystem)
	}

	var errs []error
	for _, src := range sources {
		// Determine the since cutoff for this specific source.
		var sinceCutoff time.Time
		if !full {
			sinceCutoff = globalSince
			if sinceCutoff.IsZero() {
				// Auto-detect: use last successful ingest time for this source.
				if t, ok, _ := db.GetLastIngest(ctx, src.name); ok {
					sinceCutoff = t
				}
			}
		}

		if sinceCutoff.IsZero() {
			fmt.Printf("Ingesting %s (workers=%d, chunk=%v)...\n", src.name, numWorkers, cc.enabled)
		} else {
			fmt.Printf("Ingesting %s since %s (workers=%d, chunk=%v)...\n",
				src.name, sinceCutoff.Format("2006-01-02"), numWorkers, cc.enabled)
		}

		// Wrap the loader to apply the since filter and count skipped entries.
		var sinceSkipped atomic.Int64
		loader := src.fn
		if !sinceCutoff.IsZero() {
			cutoff := sinceCutoff
			loader = func(fn func(*store.Vulnerability) error) error {
				return src.fn(func(v *store.Vulnerability) error {
					eff := effectiveDate(v.Published, v.Modified)
					if !eff.IsZero() && !eff.After(cutoff) {
						sinceSkipped.Add(1)
						return nil
					}
					return fn(v)
				})
			}
		}

		if err := ingestSource(ctx, db, embedder, src.name, loader, numWorkers, skipExisting, cc, quiet); err != nil {
			fmt.Fprintf(os.Stderr, "  source %s failed: %v\n", src.name, err)
			errs = append(errs, fmt.Errorf("%s: %w", src.name, err))
		}

		if n := sinceSkipped.Load(); n > 0 {
			fmt.Printf("  %s: %d advisories skipped (not modified since %s)\n",
				src.name, n, sinceCutoff.Format("2006-01-02"))
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
			pending := make([]*store.Vulnerability, 0, embedBatchSize)
			flush := func() {
				texts := make([]string, len(pending))
				for i, v := range pending {
					texts[i] = v.Summary + "\n" + v.Details
				}
				vecs, err := embedder.BatchEmbed(ctx, texts)
				if err != nil {
					slog.Warn("batch embed failed, skipping", "count", len(pending), "source", name, "error", err)
					errCount.Add(int64(len(pending)))
					pending = pending[:0]
					return
				}
				for i, v := range pending {
					resultCh <- store.EmbeddedVuln{Vuln: v, Embedding: vecs[i]}
				}
				pending = pending[:0]
			}
			for v := range workCh {
				pending = append(pending, v)
				if len(pending) >= embedBatchSize {
					flush()
				}
			}
			if len(pending) > 0 {
				flush()
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
			pending := make([]chunkWork, 0, embedBatchSize)
			flush := func() {
				texts := make([]string, len(pending))
				for i, w := range pending {
					texts[i] = w.text
				}
				vecs, err := embedder.BatchEmbed(ctx, texts)
				if err != nil {
					slog.Warn("batch embed failed, dropping chunks", "count", len(pending), "source", name, "error", err)
					errCount.Add(int64(len(pending)))
					pending = pending[:0]
					return
				}
				for i, w := range pending {
					resultCh <- chunkResult{
						vuln: w.vuln,
						item: store.ChunkItem{
							ChunkID:   w.chunkID,
							VulnID:    w.vuln.ID,
							Content:   w.text,
							Embedding: vecs[i],
						},
					}
				}
				pending = pending[:0]
			}
			for w := range workCh {
				pending = append(pending, w)
				if len(pending) >= embedBatchSize {
					flush()
				}
			}
			if len(pending) > 0 {
				flush()
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
			exists, err := db.Exists(ctx, v.ID)
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

var validBaselineModes = map[string]bool{"full": true, "diff": true, "update": true}

func scanCmd(dbPath *string) *cobra.Command {
	var llmModel string
	var embedModel string
	var llmBaseURL string
	var embedBaseURL string
	var outputFmt string
	var enhanceQuery bool
	var workers int
	var minSeverity string
	var minCVSS float64
	var failOn string
	var timeoutMin int
	var similarityThreshold float64
	var topK int
	var baselineMode string
	var multi bool
	var verbose bool
	var fixesOnly bool
	var profileName string
	var doAttest bool
	var attestOut string
	var directOnly bool

	cmd := &cobra.Command{
		Use:   "scan [flags] <project-dir>",
		Short: "Scan a project's dependency files for vulnerabilities",
		Args: func(cmd *cobra.Command, args []string) error {
			isMulti, _ := cmd.Flags().GetBool("multi")
			if isMulti {
				if len(args) == 0 {
					return fmt.Errorf("--multi requires at least one project path argument")
				}
				return nil
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			baselineMode = strings.ToLower(baselineMode)
			if !validBaselineModes[baselineMode] {
				return fmt.Errorf("--baseline-mode must be one of full, diff, update (got %q)", baselineMode)
			}

			ctx := context.Background()
			if timeoutMin > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMin)*time.Minute)
				defer cancel()
			}

			// In multi mode load config from cwd; in single mode load from the project dir.
			configDir := "."
			if !multi {
				configDir = args[0]
			}

			// Load config file.
			cfg, _ := config.Load(configDir)

			// Resolve profile: --profile flag, then default_profile from config.
			profName := profileName
			if profName == "" {
				profName = cfg.DefaultProfile
			}
			var prof *config.Profile
			if profName != "" {
				p, ok := cfg.ResolveProfile(profName)
				if !ok {
					return fmt.Errorf("unknown profile %q (run: argus config profiles list)", profName)
				}
				prof = p
			}

			// Apply config file top-level values where CLI flag was not set.
			if !cmd.Flags().Changed("llm-model") && cfg.LLMModel != "" {
				llmModel = cfg.LLMModel
			}
			if !cmd.Flags().Changed("embed-model") && cfg.EmbedModel != "" {
				embedModel = cfg.EmbedModel
			}
			if !cmd.Flags().Changed("min-severity") && cfg.MinSeverity != "" {
				minSeverity = cfg.MinSeverity
			}
			if !cmd.Flags().Changed("workers") && cfg.Workers > 0 {
				workers = cfg.Workers
			}
			if !cmd.Flags().Changed("top-k") && cfg.TopK > 0 {
				topK = cfg.TopK
			}
			if !cmd.Flags().Changed("llm-base-url") && cfg.LLMBaseURL != "" {
				llmBaseURL = cfg.LLMBaseURL
			}
			if !cmd.Flags().Changed("embed-base-url") && cfg.EmbedBaseURL != "" {
				embedBaseURL = cfg.EmbedBaseURL
			}

			// Apply profile values (higher priority than config file, lower than CLI).
			if prof != nil {
				if !cmd.Flags().Changed("workers") && prof.Workers > 0 {
					workers = prof.Workers
				}
				if !cmd.Flags().Changed("top-k") && prof.TopK > 0 {
					topK = prof.TopK
				}
				if !cmd.Flags().Changed("similarity-threshold") && prof.SimilarityThreshold > 0 {
					similarityThreshold = prof.SimilarityThreshold
				}
				if !cmd.Flags().Changed("llm-model") && prof.LLMModel != "" {
					llmModel = prof.LLMModel
				}
				if !cmd.Flags().Changed("embed-model") && prof.EmbedModel != "" {
					embedModel = prof.EmbedModel
				}
				if !cmd.Flags().Changed("min-severity") && prof.MinSeverity != "" {
					minSeverity = prof.MinSeverity
				}
				if !cmd.Flags().Changed("fail-on") && prof.FailOn != "" {
					failOn = prof.FailOn
				}
				if !cmd.Flags().Changed("output") && prof.OutputFormat != "" {
					outputFmt = prof.OutputFormat
				}
			}

			if err := validateFailOn(failOn); err != nil {
				return err
			}

			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()

			embedder := embed.NewClientWithConfig(embed.Config{Model: embedModel, BaseURL: embedBaseURL})
			generator := llm.NewClientWithConfig(llm.Config{Model: llmModel, BaseURL: llmBaseURL})

			if err := checkEmbedCompatibility(ctx, db, embedder); err != nil {
				return err
			}

			if multi {
				return runMultiScan(ctx, args, db, embedder, generator, multiScanOpts{
					outputFmt:           outputFmt,
					workers:             workers,
					minSeverity:         minSeverity,
					minCVSS:             minCVSS,
					failOn:              failOn,
					enhanceQuery:        enhanceQuery,
					similarityThreshold: similarityThreshold,
					topK:                topK,
					baselineMode:        baselineMode,
					verbose:             verbose,
					fixesOnly:           fixesOnly,
				})
			}

			// ── single-project scan ───────────────────────────────────────────
			projectDir := args[0]

			ignoreList, err := ignore.Load(projectDir)
			if err != nil {
				return fmt.Errorf("load ignore list: %w", err)
			}

			engine := rag.NewEngine(db, embedder, generator, rag.EngineConfig{
				EnhanceQuery:        enhanceQuery,
				MinSeverity:         minSeverity,
				MinCVSS:             minCVSS,
				SimilarityThreshold: similarityThreshold,
				TopK:                topK,
				IgnoreList:          ignoreList,
			})

			deps, err := detectAndParse(projectDir)
			if err != nil {
				return err
			}
			if len(deps) == 0 {
				fmt.Println("No dependency files found (go.mod, requirements.txt, Cargo.toml, package.json, package-lock.json, pom.xml, *.csproj, packages.config).")
				return nil
			}

			if directOnly {
				filtered := deps[:0]
				for _, d := range deps {
					if d.Direct {
						filtered = append(filtered, d)
					}
				}
				deps = filtered
				if len(deps) == 0 {
					fmt.Println("No direct dependencies found (--direct-only is set).")
					return nil
				}
			}

			isText := outputFmt == "text"

			if isText {
				fmt.Printf("\n╔══════════════════════════════════════════════════════╗\n")
				fmt.Printf("║  argus scan: %-39s║\n", truncatePath(projectDir, 39))
				fmt.Printf("║  %d dependencies found%-32s║\n", len(deps), "")
				fmt.Printf("╚══════════════════════════════════════════════════════╝\n\n")
				if profName != "" {
					fmt.Printf("Profile: %s\n\n", profName)
				}
				if baselineMode != "full" {
					fmt.Printf("Mode: baseline %s — reporting only new findings.\n\n", baselineMode)
				}
			}

			results := parallelScan(ctx, engine, deps, workers, isText)

			// Apply baseline diff if requested.
			projectKey := resolveProjectKey(projectDir)
			if baselineMode == "diff" || baselineMode == "update" {
				stored, err := db.LoadBaseline(ctx, projectKey)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not load baseline: %v\n", err)
				} else {
					results = baseline.DiffResults(results, stored)
				}
			}

			// Persist updated baseline when requested.
			if baselineMode == "update" {
				if err := db.SaveBaseline(ctx, projectKey, baseline.ToEntries(results)); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not save baseline: %v\n", err)
				}
			}

			// Filter to only actionable findings when --fixes-only is set.
			if fixesOnly {
				results = filterFixesOnly(results)
			}

			// Persist scan history (non-fatal on failure).
			if err := db.SaveScanRun(ctx, buildScanRun(projectDir, results)); err != nil {
				slog.Warn("could not save scan history", "error", err)
			}

			// Build and sign attestation when requested.
			if doAttest {
				out := attestOut
				if out == "" {
					out = "argus-attestation.json"
				}
				if err := buildAndSignAttestation(ctx, db, results, projectDir, llmModel, embedModel, out); err != nil {
					fmt.Fprintf(os.Stderr, "warning: attestation failed: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "attestation written to %s\n", out)
				}
			}

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
				printSummaryTable(results, verbose)
			}

			for _, r := range results {
				if failOnExceeded(r, failOn) {
					os.Exit(1)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&llmModel, "llm-model", "", "LLM model name (Ollama default: llama3.1:8b; OpenAI default: gpt-4o-mini)")
	cmd.Flags().StringVar(&embedModel, "embed-model", "", "embedding model name (Ollama default: nomic-embed-text; OpenAI default: text-embedding-3-small)")
	cmd.Flags().StringVar(&llmBaseURL, "llm-base-url", "", "LLM API base URL; overrides OPENAI_BASE_URL / OLLAMA_HOST")
	cmd.Flags().StringVar(&embedBaseURL, "embed-base-url", "", "embedding API base URL; overrides OPENAI_BASE_URL / OLLAMA_HOST")
	cmd.Flags().StringVar(&outputFmt, "output", "text", "output format: text, json, sarif, cyclonedx, or spdx")
	cmd.Flags().BoolVar(&enhanceQuery, "enhance-query", false, "use LLM to expand search queries before embedding")
	cmd.Flags().IntVar(&workers, "workers", 4, "parallel dependency analysis workers")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL")
	cmd.Flags().StringVar(&failOn, "fail-on", "HIGH", "severity or CVSS threshold for non-zero exit: LOW, MEDIUM, HIGH, CRITICAL, or cvss:N.N")
	cmd.Flags().Float64Var(&minCVSS, "min-cvss", 0, "minimum CVSS v3 base score to report (0 = report all)")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "show per-dependency analysis and CVSS scores in summary table")
	cmd.Flags().BoolVar(&fixesOnly, "fixes-only", false, "only report packages that have at least one finding with a known fix version")
	cmd.Flags().IntVar(&timeoutMin, "timeout", 30, "scan timeout in minutes (0 = no timeout)")
	cmd.Flags().Float64Var(&similarityThreshold, "similarity-threshold", store.DefaultSimilarityThreshold, "cosine similarity cutoff for vector search (0–1); raise to reduce false positives")
	cmd.Flags().IntVar(&topK, "top-k", 0, "number of vector search candidates per dependency (default 10; 0 = use default)")
	cmd.Flags().StringVar(&baselineMode, "baseline-mode", "full", "baseline mode: full (all findings), diff (new only), update (diff + save baseline)")
	cmd.Flags().BoolVar(&multi, "multi", false, "scan multiple project directories; each positional arg is a project path (supports ./path/...)")
	cmd.Flags().StringVar(&profileName, "profile", "", "named scan profile from .argus.yaml or built-in (default, fast, ci, thorough)")
	cmd.Flags().BoolVar(&doAttest, "attest", false, "build and sign a scan attestation (keys auto-generated in ~/.argus/keys)")
	cmd.Flags().StringVar(&attestOut, "attestation-out", "", "path to write the attestation JSON (default: argus-attestation.json)")
	cmd.Flags().BoolVar(&directOnly, "direct-only", false, "scan only direct dependencies (skip transitive deps; requires parsers that distinguish them)")
	return cmd
}

// resolveProjectKey returns a stable key for the project directory.
func resolveProjectKey(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	return abs
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
					depKind := "transitive"
					if work.dep.Direct {
						depKind = "direct"
					}
					fmt.Printf("┌─ [%d/%d] %s @ %s (%s, %s)\n",
						work.i+1, len(deps), work.dep.Name, work.dep.Version, work.dep.Ecosystem, depKind)
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

// globalRegistry is initialised once at startup with all built-in parsers and
// any external plugins found in DefaultPluginDir.
var globalRegistry = func() *plugin.Registry {
	r := plugin.NewRegistry()
	_ = r.LoadDir(plugin.DefaultPluginDir())
	return r
}()

func detectAndParse(dir string) ([]parser.Dependency, error) {
	pluginDeps, err := globalRegistry.ParseDir(dir)
	if err != nil {
		return nil, err
	}
	deps := make([]parser.Dependency, len(pluginDeps))
	for i, d := range pluginDeps {
		deps[i] = parser.Dependency{Name: d.Name, Version: d.Version, Ecosystem: d.Ecosystem, Direct: d.Direct}
	}
	return deps, nil
}

// ── plugins ──────────────────────────────────────────────────────────────────

func pluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Manage and list ecosystem parser plugins",
	}
	cmd.AddCommand(pluginsListCmd())
	return cmd
}

func pluginsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all registered ecosystem parser plugins",
		Run: func(cmd *cobra.Command, args []string) {
			r := globalRegistry
			all := r.All()

			builtin := plugin.NewRegistry().All()
			builtinNames := make(map[string]bool, len(builtin))
			for _, p := range builtin {
				builtinNames[p.Name()] = true
			}

			fmt.Printf("\n%s\n\n", col.Bold("Registered plugins (%d)", len(all)))
			t := tablewriter.NewWriter(os.Stdout)
			t.Header("Name", "File Patterns", "Source")
			for _, p := range all {
				src := "built-in"
				if !builtinNames[p.Name()] {
					src = "external"
				}
				_ = t.Append([]string{
					p.Name(),
					strings.Join(p.FilePatterns(), ", "),
					src,
				})
			}
			_ = t.Render()

			pluginDir := plugin.DefaultPluginDir()
			fmt.Printf("\nPlugin directory: %s\n", pluginDir)
			if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
				fmt.Println("  (directory does not exist — create it and add .so files to extend argus)")
			}
			fmt.Println()
		},
	}
}

// ── config ───────────────────────────────────────────────────────────────────

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config <subcommand>",
		Short: "Manage Argus configuration and profiles",
	}
	cmd.AddCommand(configProfilesCmd())
	return cmd
}

func configProfilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles <subcommand>",
		Short: "List and inspect named scan profiles",
	}
	cmd.AddCommand(configProfilesListCmd())
	return cmd
}

func configProfilesListCmd() *cobra.Command {
	var projectDir string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all available scan profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := config.Load(projectDir)

			names := cfg.AllProfileNames()
			defaultName := cfg.DefaultProfile
			if defaultName == "" {
				defaultName = "default"
			}

			fmt.Printf("\n%s\n\n", col.Bold("Available scan profiles"))
			t := tablewriter.NewWriter(os.Stdout)
			t.Header("Name", "Workers", "Top-K", "Min-Similarity", "LLM Model", "Embed Model", "Min-Severity", "Fail-On", "Output", "Default")
			for _, name := range names {
				p, _ := cfg.ResolveProfile(name)
				defMark := ""
				if name == defaultName {
					defMark = "✓"
				}
				sim := "—"
				if p.SimilarityThreshold > 0 {
					sim = fmt.Sprintf("%.2f", p.SimilarityThreshold)
				}
				workers := "—"
				if p.Workers > 0 {
					workers = fmt.Sprintf("%d", p.Workers)
				}
				topK := "—"
				if p.TopK > 0 {
					topK = fmt.Sprintf("%d", p.TopK)
				}
				llmModel := p.LLMModel
				if llmModel == "" {
					llmModel = "—"
				}
				embedModel := p.EmbedModel
				if embedModel == "" {
					embedModel = "—"
				}
				minSev := p.MinSeverity
				if minSev == "" {
					minSev = "—"
				}
				failOn := p.FailOn
				if failOn == "" {
					failOn = "—"
				}
				outFmt := p.OutputFormat
				if outFmt == "" {
					outFmt = "—"
				}
				_ = t.Append([]string{name, workers, topK, sim, llmModel, embedModel, minSev, failOn, outFmt, defMark})
			}
			_ = t.Render()
			fmt.Printf("\nUsage: argus scan --profile <name> <project-dir>\n")
			fmt.Printf("Set default_profile: <name> in .argus.yaml to use a profile automatically.\n\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&projectDir, "project-dir", ".", "directory containing .argus.yaml")
	return cmd
}

// ── baseline ─────────────────────────────────────────────────────────────────

func baselineCmd(dbPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline <subcommand>",
		Short: "Manage stored scan baselines",
	}
	cmd.AddCommand(baselineShowCmd(dbPath))
	cmd.AddCommand(baselineResetCmd(dbPath))
	return cmd
}

func baselineShowCmd(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "show <project-dir>",
		Short: "Show the stored baseline for a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			projectKey := resolveProjectKey(args[0])

			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()

			entries, err := db.ListBaseline(ctx, projectKey)
			if err != nil {
				return fmt.Errorf("list baseline: %w", err)
			}
			if len(entries) == 0 {
				fmt.Printf("No baseline stored for %s.\n", args[0])
				fmt.Println("Run: argus scan --baseline-mode update <project-dir>")
				return nil
			}

			fmt.Printf("\n%s\n\n", col.Bold("Stored baseline — %s", args[0]))
			t := tablewriter.NewWriter(os.Stdout)
			t.Header("Dependency", "Ecosystem", "CVEs in Baseline", "Last Scanned")
			for _, e := range entries {
				_ = t.Append([]string{
					e.DepName,
					e.Ecosystem,
					fmt.Sprintf("%d", len(e.VulnIDs)),
					e.ScannedAt.Format("2006-01-02 15:04 UTC"),
				})
			}
			_ = t.Render()
			fmt.Println()
			return nil
		},
	}
}

func baselineResetCmd(dbPath *string) *cobra.Command {
	var confirm bool
	cmd := &cobra.Command{
		Use:   "reset <project-dir>",
		Short: "Clear the stored baseline for a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirm {
				fmt.Printf("This will clear the baseline for %s.\n", args[0])
				fmt.Println("Re-run with --confirm to proceed.")
				return nil
			}
			ctx := cmd.Context()
			projectKey := resolveProjectKey(args[0])

			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer func() { _ = db.Close() }()

			if err := db.ResetBaseline(ctx, projectKey); err != nil {
				return fmt.Errorf("reset baseline: %w", err)
			}
			fmt.Printf("Baseline cleared for %s.\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&confirm, "confirm", false, "confirm baseline deletion")
	return cmd
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
			vec, err := embedder.Embed(ctx, query)
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

// ── doctor ───────────────────────────────────────────────────────────────────

func doctorCmd(dbPath *string) *cobra.Command {
	var projectDir string
	var llmModel string
	var embedModel string
	var llmBaseURL string
	var embedBaseURL string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Validate Argus setup: config, database, and LLM connectivity",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg := doctor.Config{
				DBPath:       *dbPath,
				ProjectDir:   projectDir,
				LLMModel:     llmModel,
				EmbedModel:   embedModel,
				LLMBaseURL:   llmBaseURL,
				EmbedBaseURL: embedBaseURL,
			}
			checks := doctor.Run(ctx, cfg)

			// Append signing-key check.
			keyDir := attest.DefaultKeyDir()
			keyFile := filepath.Join(keyDir, "signing.key")
			if _, statErr := os.Stat(keyFile); statErr == nil {
				checks = append(checks, doctor.Check{
					Name:   "Signing key",
					OK:     true,
					Detail: fmt.Sprintf("Ed25519 key found (%s)", keyDir),
				})
			} else {
				checks = append(checks, doctor.Check{
					Name:   "Signing key",
					OK:     false,
					Detail: "no signing key found",
					Hint:   fmt.Sprintf("run: argus scan --attest <dir>  (keys auto-generated in %s)", keyDir),
				})
			}

			fmt.Println()
			allOK := true
			for _, c := range checks {
				if c.OK {
					fmt.Printf("  %s %s — %s\n", col.Green("✓"), c.Name, c.Detail)
				} else {
					fmt.Printf("  %s %s — %s\n", col.Red("✗"), c.Name, c.Detail)
					if c.Hint != "" {
						fmt.Printf("    → %s\n", c.Hint)
					}
					allOK = false
				}
			}
			fmt.Println()

			if !allOK {
				return fmt.Errorf("one or more checks failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&projectDir, "project-dir", ".", "directory to check for .argus.yaml and .argusignore")
	cmd.Flags().StringVar(&llmModel, "llm-model", "", "LLM model name to check (default: llama3.1:8b or gpt-4o-mini)")
	cmd.Flags().StringVar(&embedModel, "embed-model", "", "embedding model name to check (default: nomic-embed-text or text-embedding-3-small)")
	cmd.Flags().StringVar(&llmBaseURL, "llm-base-url", "", "LLM API base URL; overrides OPENAI_BASE_URL / OLLAMA_HOST")
	cmd.Flags().StringVar(&embedBaseURL, "embed-base-url", "", "embedding API base URL; overrides OPENAI_BASE_URL / OLLAMA_HOST")
	return cmd
}

// ── serve ─────────────────────────────────────────────────────────────────────

func serveCmd(dbPath *string) *cobra.Command {
	var port int
	var host string
	var readOnly bool

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Argus web dashboard",
		Long:  "Starts an embedded HTTP server with a vulnerability dashboard at http://host:port.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return web.Serve(web.Config{
				DBPath:   *dbPath,
				Host:     host,
				Port:     port,
				ReadOnly: readOnly,
			})
		},
	}
	cmd.Flags().IntVar(&port, "port", 8080, "port to listen on")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1", "host/address to bind")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "disable all write operations via the dashboard")
	return cmd
}

// ── helpers ──────────────────────────────────────────────────────────────────

// buildAndSignAttestation builds, signs, and writes a scan attestation JSON file.
func buildAndSignAttestation(ctx context.Context, db *store.DB, results []rag.Result, projectDir, llmModel, embedModel, attestOut string) error {
	findingsJSON, err := json.Marshal(output.BuildJSONResults(results))
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}
	dbFP, totalVulns, err := db.Fingerprint(ctx)
	if err != nil {
		return fmt.Errorf("db fingerprint: %w", err)
	}
	kp, err := attest.EnsureKeys(attest.DefaultKeyDir())
	if err != nil {
		return fmt.Errorf("signing keys: %w", err)
	}
	a := attest.Build(attest.Params{
		ArgusVersion:  Version,
		ScannedPath:   projectDir,
		DBFingerprint: dbFP,
		TotalVulns:    totalVulns,
		LLMModel:      llmModel,
		EmbedModel:    embedModel,
		FindingsJSON:  findingsJSON,
		FindingsCount: len(results),
		PublicKeyHint: attest.PublicKeyHint(kp.Public),
	})
	if err := attest.Sign(a, kp.Private); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal attestation: %w", err)
	}
	return os.WriteFile(attestOut, data, 0o644) //nolint:gosec // attestation files are public artifacts
}

// verifyCmd verifies a scan attestation file produced by --attest.
func verifyCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "verify <attestation.json>",
		Short: "Verify a scan attestation signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read attestation: %w", err)
			}
			var a attest.Attestation
			if err := json.Unmarshal(data, &a); err != nil {
				return fmt.Errorf("parse attestation: %w", err)
			}
			if keyPath == "" {
				kp, err := attest.EnsureKeys(attest.DefaultKeyDir())
				if err != nil {
					return fmt.Errorf("load signing keys: %w", err)
				}
				if err := attest.Verify(&a, kp.Public); err != nil {
					return fmt.Errorf("verification failed: %w", err)
				}
			} else {
				pubKey, err := attest.LoadPublicKey(keyPath)
				if err != nil {
					return fmt.Errorf("load public key: %w", err)
				}
				if err := attest.Verify(&a, pubKey); err != nil {
					return fmt.Errorf("verification failed: %w", err)
				}
			}
			fmt.Printf("OK  signature valid\n")
			fmt.Printf("    scanned:   %s\n", a.ScannedPath)
			fmt.Printf("    scan time: %s\n", a.ScanTime)
			fmt.Printf("    findings:  %d\n", a.FindingsCount)
			fmt.Printf("    db digest: %s\n", a.DBFingerprint)
			fmt.Printf("    key hint:  %s\n", a.PublicKeyHint)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "path to PEM public key (default: ~/.argus/keys/signing.pub)")
	return cmd
}

// filterFixesOnly returns only results that have at least one finding with a
// known fix version. Results with no findings (OK) are excluded.
func filterFixesOnly(results []rag.Result) []rag.Result {
	out := results[:0:0]
	for _, r := range results {
		for _, f := range r.Findings {
			if f.FixedIn != "" {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func printSummaryTable(results []rag.Result, verbose bool) {
	fmt.Printf("\n%s\n\n", col.Bold("SCAN SUMMARY"))

	t := tablewriter.NewWriter(os.Stdout)
	if verbose {
		t.Header("Package", "Version", "Ecosystem", "CVEs Found", "Top Severity", "Top CVSS", "Fix", "Verdict")
	} else {
		t.Header("Package", "Version", "Ecosystem", "CVEs Found", "Top Severity", "Fix", "Verdict")
	}
	for _, r := range results {
		sev := r.TopSeverity
		if sev == "" {
			sev = "—"
		}
		fix := r.TopFixedIn
		if fix == "" {
			fix = "—"
		}
		if verbose {
			cvss := "—"
			if r.TopCVSSScore > 0 {
				cvss = fmt.Sprintf("%.1f", r.TopCVSSScore)
			}
			_ = t.Append([]string{
				r.Dep.Name, r.Dep.Version, r.Dep.Ecosystem,
				fmt.Sprintf("%d", r.RetrievedCount),
				col.Severity(sev), cvss, fix, col.Verdict(r.Verdict()),
			})
		} else {
			_ = t.Append([]string{
				r.Dep.Name, r.Dep.Version, r.Dep.Ecosystem,
				fmt.Sprintf("%d", r.RetrievedCount),
				col.Severity(sev), fix, col.Verdict(r.Verdict()),
			})
		}
	}
	_ = t.Render()
}

func truncatePath(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return "..." + s[len(s)-(maxLen-3):]
}

// buildScanRun aggregates scan results into a ScanRun record for history storage.
func buildScanRun(projectDir string, results []rag.Result) store.ScanRun {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	totalFindings := 0
	for _, r := range results {
		totalFindings += r.RetrievedCount
		if n, ok := counts[r.TopSeverity]; ok {
			counts[r.TopSeverity] = n + 1
		}
	}
	return store.ScanRun{
		ID:            newScanRunID(),
		ProjectDir:    projectDir,
		ScannedAt:     time.Now().UTC(),
		DepCount:      len(results),
		TotalFindings: totalFindings,
		CriticalCount: counts["CRITICAL"],
		HighCount:     counts["HIGH"],
		MediumCount:   counts["MEDIUM"],
		LowCount:      counts["LOW"],
	}
}

// newScanRunID generates a random UUID v4 for scan run records.
func newScanRunID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// formatError returns a user-friendly string for known structured error types,
// falling back to err.Error() for everything else.
func formatError(err error) string {
	var authErr *argerr.ErrAuth
	if errors.As(err, &authErr) {
		return authErr.Error() + "\nhint: set OPENAI_API_KEY (or OLLAMA_HOST for local Ollama)"
	}
	var modelErr *argerr.ErrModelNotFound
	if errors.As(err, &modelErr) {
		return modelErr.Error()
	}
	return err.Error()
}

// checkEmbedCompatibility compares the dimension of the configured embedder
// against the dimension stored in the database meta table. It returns an error
// with a clear remediation message when they differ, preventing silently wrong
// similarity results that would arise from a mismatched embedding model.
// The check is skipped when the database has no stored dimension (e.g. the DB
// was created before this feature was added, or is empty).
func checkEmbedCompatibility(ctx context.Context, db *store.DB, embedder *embed.Client) error {
	storedDimStr, ok, err := db.GetMeta(ctx, "embed_dim")
	if err != nil || !ok {
		return nil
	}
	storedDim, err := strconv.Atoi(storedDimStr)
	if err != nil {
		return nil
	}
	currentDim, err := embedder.Dimension(ctx)
	if err != nil {
		return nil
	}
	if currentDim == storedDim {
		return nil
	}
	storedModel, _, _ := db.GetMeta(ctx, "embed_model")
	hint := storedModel
	if hint == "" {
		hint = fmt.Sprintf("%d-dim model", storedDim)
	}
	return fmt.Errorf(
		"embedding dimension mismatch: database was built with %s (dim=%d), "+
			"current model %q outputs dim=%d; "+
			"re-run 'argus ingest' with the same model or reset the database",
		hint, storedDim, embedder.Model(), currentDim,
	)
}
