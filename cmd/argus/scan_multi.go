package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"

	"github.com/abhishekamralkar/argus/internal/baseline"
	col "github.com/abhishekamralkar/argus/internal/color"
	"github.com/abhishekamralkar/argus/internal/embed"
	"github.com/abhishekamralkar/argus/internal/ignore"
	"github.com/abhishekamralkar/argus/internal/llm"
	"github.com/abhishekamralkar/argus/internal/output"
	"github.com/abhishekamralkar/argus/internal/rag"
	"github.com/abhishekamralkar/argus/internal/store"
	"github.com/abhishekamralkar/argus/pkg/plugin"
)

// ProjectResult holds scan results for one project directory.
type ProjectResult struct {
	ProjectDir string
	Results    []rag.Result
}

// multiScanOpts carries scan settings shared across all projects.
type multiScanOpts struct {
	outputFmt           string
	workers             int
	minSeverity         string
	failOn              string
	enhanceQuery        bool
	similarityThreshold float64
	topK                int
	baselineMode        string
}

// runMultiScan resolves project directories from paths, scans each one
// independently (respecting per-project .argusignore), and writes an
// aggregated report.
func runMultiScan(
	ctx context.Context,
	paths []string,
	db *store.DB,
	embedder *embed.Client,
	generator *llm.Client,
	opts multiScanOpts,
) error {
	dirs, err := resolveMultiDirs(paths)
	if err != nil {
		return fmt.Errorf("resolve project dirs: %w", err)
	}
	if len(dirs) == 0 {
		fmt.Println("No projects with dependency files found.")
		return nil
	}

	fmt.Printf("\n%s\n\n", col.Bold("argus multi-scan: %d project(s)", len(dirs)))

	var projectResults []ProjectResult
	for _, dir := range dirs {
		ignoreList, err := ignore.Load(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: load .argusignore for %s: %v\n", dir, err)
			ignoreList = ignore.Empty()
		}

		engine := rag.NewEngine(db, embedder, generator, rag.EngineConfig{
			EnhanceQuery:        opts.enhanceQuery,
			MinSeverity:         opts.minSeverity,
			SimilarityThreshold: opts.similarityThreshold,
			TopK:                opts.topK,
			IgnoreList:          ignoreList,
		})

		deps, err := detectAndParse(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: parse deps for %s: %v\n", dir, err)
			continue
		}
		if len(deps) == 0 {
			fmt.Printf("  %s — no dependency files found, skipping\n", dir)
			continue
		}

		fmt.Printf("  scanning %s (%d dependencies)...\n", dir, len(deps))
		results := parallelScan(ctx, engine, deps, opts.workers, false)

		projectKey := resolveProjectKey(dir)
		if opts.baselineMode == "diff" || opts.baselineMode == "update" {
			stored, loadErr := db.LoadBaseline(ctx, projectKey)
			if loadErr != nil {
				fmt.Fprintf(os.Stderr, "warning: load baseline for %s: %v\n", dir, loadErr)
			} else {
				results = baseline.DiffResults(results, stored)
			}
		}
		if opts.baselineMode == "update" {
			if saveErr := db.SaveBaseline(ctx, projectKey, baseline.ToEntries(results)); saveErr != nil {
				fmt.Fprintf(os.Stderr, "warning: save baseline for %s: %v\n", dir, saveErr)
			}
		}

		projectResults = append(projectResults, ProjectResult{ProjectDir: dir, Results: results})
	}

	switch opts.outputFmt {
	case "json":
		if err := writeMultiJSON(os.Stdout, projectResults); err != nil {
			return err
		}
	case "sarif":
		if err := writeMultiSARIF(os.Stdout, projectResults); err != nil {
			return err
		}
	default:
		printMultiSummaryTable(projectResults)
	}

	for _, pr := range projectResults {
		for _, r := range pr.Results {
			if exceedsSeverity(r.Verdict(), opts.failOn) {
				os.Exit(1)
			}
		}
	}
	return nil
}

// resolveMultiDirs expands paths, treating a path ending in "/..." as a
// recursive walk that finds all subdirectories containing dependency files.
// Duplicate directories are removed while preserving order.
func resolveMultiDirs(paths []string) ([]string, error) {
	var dirs []string
	for _, p := range paths {
		if strings.HasSuffix(p, "/...") || p == "..." {
			root := strings.TrimSuffix(p, "/...")
			// bare "..." → TrimSuffix leaves it unchanged; treat as cwd.
			if root == "" || root == "..." {
				root = "."
			}
			subdirs, err := findProjectDirs(root)
			if err != nil {
				return nil, fmt.Errorf("expand %s: %w", p, err)
			}
			dirs = append(dirs, subdirs...)
		} else {
			dirs = append(dirs, p)
		}
	}
	return deduplicateDirs(dirs), nil
}

// findProjectDirs walks root and returns each directory that contains at least
// one recognized dependency file, as determined by the plugin registry.
func findProjectDirs(root string) ([]string, error) {
	exactNames := plugin.DepFileNames()
	globPatterns := plugin.DepGlobPatterns()

	seen := map[string]bool{}
	var dirs []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		dir := filepath.Dir(path)
		if seen[dir] {
			return nil
		}
		base := filepath.Base(path)
		if exactNames[base] {
			seen[dir] = true
			dirs = append(dirs, dir)
			return nil
		}
		for _, pat := range globPatterns {
			if matched, _ := filepath.Match(pat, base); matched {
				seen[dir] = true
				dirs = append(dirs, dir)
				return nil
			}
		}
		return nil
	})
	return dirs, err
}

// deduplicateDirs removes duplicate paths while preserving insertion order.
func deduplicateDirs(dirs []string) []string {
	seen := make(map[string]bool, len(dirs))
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func printMultiSummaryTable(projectResults []ProjectResult) {
	fmt.Printf("\n%s\n\n", col.Bold("MULTI-SCAN SUMMARY"))
	t := tablewriter.NewWriter(os.Stdout)
	t.Header("Project", "Package", "Version", "Ecosystem", "CVEs", "Top Severity", "Verdict")
	for _, pr := range projectResults {
		for _, r := range pr.Results {
			sev := r.TopSeverity
			if sev == "" {
				sev = "—"
			}
			_ = t.Append([]string{
				pr.ProjectDir,
				r.Dep.Name,
				r.Dep.Version,
				r.Dep.Ecosystem,
				fmt.Sprintf("%d", r.RetrievedCount),
				col.Severity(sev),
				col.Verdict(r.Verdict()),
			})
		}
	}
	_ = t.Render()
}

// multiJSONReport is the top-level JSON structure for multi-project scans.
type multiJSONReport struct {
	ScannedAt string             `json:"scanned_at"`
	Projects  []projectJSONEntry `json:"projects"`
}

// projectJSONEntry is one project's entry in a multi-project JSON report.
type projectJSONEntry struct {
	Project string              `json:"project"`
	Results []output.JSONResult `json:"results"`
}

func writeMultiJSON(w io.Writer, projectResults []ProjectResult) error {
	report := multiJSONReport{
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Projects:  make([]projectJSONEntry, 0, len(projectResults)),
	}
	for _, pr := range projectResults {
		report.Projects = append(report.Projects, projectJSONEntry{
			Project: pr.ProjectDir,
			Results: output.BuildJSONResults(pr.Results),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// writeMultiSARIF aggregates all project results into a single SARIF report.
func writeMultiSARIF(w io.Writer, projectResults []ProjectResult) error {
	var all []rag.Result
	for _, pr := range projectResults {
		all = append(all, pr.Results...)
	}
	return output.WriteSARIF(w, all, ".")
}
