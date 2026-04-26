package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/abhishekamralkar/argus/internal/embed"
	"github.com/abhishekamralkar/argus/internal/ingest"
	"github.com/abhishekamralkar/argus/internal/llm"
	"github.com/abhishekamralkar/argus/internal/parser"
	"github.com/abhishekamralkar/argus/internal/rag"
	"github.com/abhishekamralkar/argus/internal/store"
)

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

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── ingest ──────────────────────────────────────────────────────────────────

func ingestCmd(dbPath *string) *cobra.Command {
	var ecosystems string
	var embedModel string
	var workers int
	var skipExisting bool

	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Download vulnerability databases and store embeddings",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer db.Close()

			embedder := embed.NewClient(embedModel)
			for eco := range strings.SplitSeq(ecosystems, ",") {
				eco = strings.TrimSpace(eco)
				if eco == "" {
					continue
				}
				if err := runIngest(db, embedder, eco, workers, skipExisting); err != nil {
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
	return cmd
}

const batchSize = 50

func runIngest(db *store.DB, embedder *embed.Client, ecosystem string, numWorkers int, skipExisting bool) error {
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
		fmt.Printf("Ingesting %s (workers=%d)...\n", src.name, numWorkers)
		if err := ingestSource(db, embedder, src.name, src.fn, numWorkers, skipExisting); err != nil {
			fmt.Fprintf(os.Stderr, "  source %s failed: %v\n", src.name, err)
		}
	}

	count, _ := db.Count(ecosystem)
	fmt.Printf("Total %s vulnerabilities stored: %d\n", ecosystem, count)
	return nil
}

func ingestSource(
	db *store.DB,
	embedder *embed.Client,
	name string,
	loader func(func(*store.Vulnerability) error) error,
	numWorkers int,
	skipExisting bool,
) error {
	bar := progressbar.Default(-1, name)
	var errCount atomic.Int64

	// workCh carries raw vulnerabilities to embed workers.
	workCh := make(chan *store.Vulnerability, numWorkers*4)
	// resultCh carries embedded results to the single batch-writer.
	resultCh := make(chan store.EmbeddedVuln, numWorkers*4)

	// Embed workers
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

	// Close resultCh once all workers finish.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Batch writer — single goroutine owns all DB writes.
	writerDone := make(chan error, 1)
	go func() {
		batch := make([]store.EmbeddedVuln, 0, batchSize)
		for item := range resultCh {
			batch = append(batch, item)
			if len(batch) >= batchSize {
				if err := db.UpsertBatch(batch); err != nil {
					errCount.Add(int64(len(batch)))
				} else {
					bar.Add(len(batch))
				}
				batch = batch[:0]
			}
		}
		// flush remainder
		if len(batch) > 0 {
			if err := db.UpsertBatch(batch); err != nil {
				errCount.Add(int64(len(batch)))
			} else {
				bar.Add(len(batch))
			}
		}
		writerDone <- nil
	}()

	// Producer: feed vulnerabilities into workCh.
	err := loader(func(v *store.Vulnerability) error {
		if skipExisting && db.Exists(v.ID) {
			return nil
		}
		workCh <- v
		return nil
	})
	close(workCh)

	<-writerDone
	bar.Finish()

	if n := errCount.Load(); n > 0 {
		fmt.Printf("  %s: %d entries skipped due to errors\n", name, n)
	}
	return err
}

// ── scan ─────────────────────────────────────────────────────────────────────

func scanCmd(dbPath *string) *cobra.Command {
	var llmModel string
	var embedModel string
	var outputFmt string

	cmd := &cobra.Command{
		Use:   "scan <project-dir>",
		Short: "Scan a project's dependency files for vulnerabilities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectDir := args[0]

			db, err := store.Open(*dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer db.Close()

			embedder := embed.NewClient(embedModel)
			generator := llm.NewClient(llmModel)
			engine := rag.NewEngine(db, embedder, generator)

			deps, err := detectAndParse(projectDir)
			if err != nil {
				return err
			}
			if len(deps) == 0 {
				fmt.Println("No dependency files found (go.mod, requirements.txt, Cargo.toml).")
				return nil
			}

			fmt.Printf("=== argus: %s (%d dependencies) ===\n\n", projectDir, len(deps))

			highFound := false
			for _, dep := range deps {
				fmt.Printf("--- %s@%s (%s) ---\n", dep.Name, dep.Version, dep.Ecosystem)
				if err := engine.AnalyzeDependency(dep, os.Stdout); err != nil {
					fmt.Fprintf(os.Stderr, "  analysis failed: %v\n", err)
				}
				fmt.Println()
			}

			_ = outputFmt // reserved for JSON output mode
			if highFound {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&llmModel, "llm-model", "", "Ollama LLM model (default: gpt-oss:20b)")
	cmd.Flags().StringVar(&embedModel, "embed-model", "", "Ollama embedding model (default: nomic-embed-text)")
	cmd.Flags().StringVar(&outputFmt, "output", "text", "output format: text or json")
	return cmd
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
			defer db.Close()

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
