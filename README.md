# argus

A RAG-based (Retrieval-Augmented Generation) vulnerability scanner for **Go**, **Python**, **Rust**, **npm/Node.js**, **Maven/Java**, **NuGet/.NET**, and **Ruby** projects — powered by local [Ollama](https://ollama.com) models **or** any OpenAI-compatible API. No cloud lock-in. Your code stays on your machine.

[![CI](https://github.com/abhishekamralkar/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/abhishekamralkar/argus/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/abhishekamralkar/argus)](https://github.com/abhishekamralkar/argus/releases)
[![Ecosystems](https://img.shields.io/badge/ecosystems-7-green.svg)](#supported-ecosystems)

---

## Quick start

```bash
# 1. Install
go install github.com/abhishekamralkar/argus/cmd/argus@latest

# 2. Start Ollama and pull models
ollama pull nomic-embed-text
ollama pull llama3.1:8b

# 3. Ingest vulnerability databases (one-time, ~5–15 min; feeds cached locally)
argus ingest --ecosystems go,python,rust,npm,maven,nuget

# 4. Check database and feed-cache status
argus status

# 5. Scan your project
argus scan /path/to/your/project

# 5b. Scan an entire monorepo at once
argus scan --multi ./services/...

# 6. Check version
argus version
```

Results stream to your terminal with color-coded severity; exit code is `1` when findings meet or exceed your `--fail-on` threshold (default: `HIGH`).

---

## How it works

```
┌──────────────────────────────────────────────────────────────────────┐
│                          INGEST (one-time)                           │
│                                                                      │
│  OSV (Go/PyPI/crates.io/npm/Maven/NuGet) ──┐                        │
│  GoVulnDB ─────────────────────────────────┼──► Parse               │
│  RustSec ──────────────────────────────────┤    Chunk (512 chars)   │
│  PyPA ─────────────────────────────────────┘    Embed               │
│                                                  ──► DuckDB (local)  │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                          SCAN (per project)                          │
│                                                                      │
│  go.mod / requirements.txt / Cargo.toml                             │
│  package.json / package-lock.json                                   │
│  pom.xml / *.csproj / packages.config                               │
│       │                                                              │
│       ▼                                                              │
│  Parse deps ──► Embed query ──► Cosine search (DuckDB, top-k)      │
│                                       │                              │
│                                       ▼                              │
│              Ignore list · Alias dedup · Version filter             │
│              Min-severity gate · Parallel workers                   │
│                                       │                              │
│                                       ▼                              │
│                    LLM prompt ──► Report (text/JSON/SARIF/SBOM)     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Features

| Category | Feature |
|---|---|
| **Privacy** | Fully local by default — Ollama + DuckDB on disk, zero external calls after ingest |
| **OpenAI compat** | Drop-in OpenAI/LiteLLM/vLLM support via `--llm-base-url` / `--embed-base-url` |
| **Languages** | Go, Python, Rust, npm/Node.js, Maven/Java, NuGet/.NET, Ruby |
| **Dependency files** | `go.mod`, `requirements.txt`, `Cargo.toml`, `package.json`, `package-lock.json`, `pom.xml`, `*.csproj`, `packages.config`, `Gemfile.lock` |
| **Data sources** | OSV (all ecosystems), GoVulnDB, RustSec, PyPA |
| **Feed cache** | Zip archives cached in `~/.cache/argus/feeds` with ETag/Last-Modified — repeated ingests are instant |
| **Retrieval** | Document chunking (512-char overlapping), semantic cosine search, configurable `--top-k` |
| **Accuracy** | Version-aware CVE filtering — already-fixed advisories are silently skipped |
| **Accuracy** | Alias-aware deduplication — `GO-2024-x` and `CVE-2024-x` won't double-report |
| **CVSS scores** | Numeric CVSS v3 base scores stored and surfaced; `--min-cvss` filter; `--fail-on cvss:N.N` exit gate |
| **Noise control** | `--min-severity` hides LOW/MEDIUM findings; `.argusignore` suppresses known false positives |
| **Output** | Color terminal, `--output json`, `--output sarif`, `--output cyclonedx`, `--output spdx` |
| **SBOM** | CycloneDX 1.6 JSON and SPDX 2.3 JSON with PURL-linked components and vulnerabilities |
| **Baseline diff** | `--baseline-mode diff/update` — report only new findings since the last scan (CI noise reduction) |
| **Multi-project** | `--multi ./services/...` scans every sub-project in a monorepo in a single run |
| **Plugin system** | `pkg/plugin.EcosystemPlugin` interface — add new ecosystems without forking argus |
| **Performance** | Parallel scan workers, parallel embed workers, exponential-backoff retry |
| **CI** | `--fail-on` threshold flag, SARIF upload, official GitHub Actions composite action |
| **Docker** | Slim image (`ghcr.io/abhishekamralkar/argus`) + bundled image with Ollama included |
| **Config** | `.argus.yaml` project config file — commit once, no repeated flags in CI |

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Go | 1.26+ | Only needed for `go install` / building from source |
| [Ollama](https://ollama.com) | latest | Required for local model mode |
| DuckDB CLI | optional | For manual DB inspection |

### Pull required Ollama models

```bash
ollama pull nomic-embed-text   # embedding model (768-dim)
ollama pull llama3.1:8b        # LLM for vulnerability analysis
```

---

## Installation

### go install

```bash
go install github.com/abhishekamralkar/argus/cmd/argus@latest
```

### From source

```bash
git clone https://github.com/abhishekamralkar/argus.git
cd argus
make build           # embeds git version in binary
./argus version
```

### Download a release binary

Pre-built Linux binaries (amd64 + arm64) are on the [Releases](https://github.com/abhishekamralkar/argus/releases) page.

### Docker — slim image (bring your own Ollama)

```bash
docker run --rm \
  -v "$PWD:/project" \
  -v argus-data:/data \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/abhishekamralkar/argus \
  scan /project
```

### Docker — bundled image (Ollama included)

The `:bundled` tag ships Ollama inside the image. Models are pulled on first run and cached in a named volume.

```bash
docker run --rm \
  -v "$PWD:/project" \
  -v argus-data:/data \
  ghcr.io/abhishekamralkar/argus:bundled \
  scan /project
```

### Docker Compose

```bash
# Start both Ollama and argus together
docker compose up argus
```

See [`docker-compose.yml`](docker-compose.yml) for the full configuration.

---

## Commands

### `ingest` — populate the vulnerability database

Downloads and embeds all vulnerability databases into a local DuckDB file. Run once, then periodically to pick up new advisories.

```bash
# All standard ecosystems (feeds cached locally after first download)
argus ingest --ecosystems go,python,rust,npm,maven,nuget

# Including Ruby
argus ingest --ecosystems go,python,rust,npm,maven,nuget,ruby

# Custom database path
argus ingest --db /var/lib/argus/vulns.db

# Tune chunking (default: 512 chars, 64 overlap)
argus ingest --chunk-size 256 --chunk-overlap 32

# Faster with more workers; suppress progress bar in CI
argus ingest --workers 16 --quiet

# Force re-download of all zip archives (bypass the feed cache)
argus ingest --no-cache
```

**Feed cache:** Downloaded zip archives are stored in `~/.cache/argus/feeds` (respects `XDG_CACHE_HOME`). Subsequent `ingest` runs send `If-None-Match` / `If-Modified-Since` headers and skip re-embedding unchanged feeds. The current cache size is shown by `argus status`.

**Vulnerability data sources:**

| Source | Ecosystems |
|---|---|
| [OSV](https://osv.dev) | Go, Python, Rust, npm, Maven, NuGet |
| [Go Vulnerability Database](https://vuln.go.dev) | Go |
| [RustSec](https://rustsec.org) | Rust |
| [PyPA](https://github.com/pypa/advisory-database) | Python |

> **Ruby** — `Gemfile.lock` is parsed by the built-in plugin; vulnerability lookup uses the same OSV-based RAG pipeline. A dedicated RubyGems OSV feed can be added via `argus ingest --ecosystems rubygems` once the OSV source is configured.

---

### `status` — database health check

```bash
argus status
```

```
Vulnerability Database — ./vulns.db

 ECOSYSTEM | VULNERABILITIES | CHUNKS  | LAST INGEST
 go        | 6 556           | 48 203  | 2026-05-08T08:12:00Z
 maven     | 4 821           | 31 447  | 2026-05-08T08:14:00Z
 npm       | 3 104           | 21 890  | 2026-05-08T08:18:00Z
 nuget     | 1 203           | 8 422   | 2026-05-08T08:20:00Z
 python    | 19 045          | 134 821 | 2026-05-08T08:31:00Z
 rust      | 2 267           | 15 901  | 2026-05-08T08:36:00Z

Feed cache: /home/user/.cache/argus/feeds (342.1 MB)
```

---

### `scan` — analyse a project's dependencies

Auto-detects all supported dependency files in the given directory.

```bash
argus scan /path/to/your/project
```

**Text output (default, color-coded):**

```
╔══════════════════════════════════════════════════════╗
║  argus scan: /path/to/your/project                  ║
║  42 dependencies found                               ║
╚══════════════════════════════════════════════════════╝

┌─ [1/42] golang.org/x/crypto @ 0.0.0-20190308221718 (go)

 ID             | PACKAGE              | SEVERITY | FIXED IN | SCORE
 GO-2021-0227   | golang.org/x/crypto  | HIGH     | 0.17.0   | 0.923

  Analyzing with llama3.1:8b (streaming)...
  1. Vulnerable: YES
  2. Severity: HIGH
  3. Advisory: GO-2021-0227 (CVE-2021-43565)
  4. Fix: upgrade to golang.org/x/crypto v0.17.0 or later
```

**JSON output:**

```bash
argus scan . --output json > results.json
```

**SARIF output** (GitHub Security tab):

```bash
argus scan . --output sarif > argus.sarif
```

**CycloneDX 1.6 SBOM:**

```bash
argus scan . --output cyclonedx > sbom.cdx.json
```

**SPDX 2.3 SBOM:**

```bash
argus scan . --output spdx > sbom.spdx.json
```

**All scan flags:**

| Flag | Default | Description |
|---|---|---|
| `--output` | `text` | Output format: `text`, `json`, `sarif`, `cyclonedx`, `spdx` |
| `--min-severity` | _(all)_ | Minimum severity to report: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--min-cvss` | `0` | Minimum CVSS v3 base score to report (0 = report all; skips only findings with a known score below threshold) |
| `--fail-on` | `HIGH` | Exit code 1 threshold: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, or `cvss:N.N` |
| `--verbose` | off | Stream per-dependency LLM analysis and add a "Top CVSS" column to the summary table |
| `--baseline-mode` | `full` | `full` = all findings; `diff` = new only; `update` = diff + save baseline |
| `--multi` | off | Scan multiple project directories; each positional arg is a path (supports `./path/...`) |
| `--top-k` | `10` | Vector search candidates per dependency |
| `--workers` | `4` | Parallel dependency analysis workers |
| `--enhance-query` | off | Use LLM to expand search queries before embedding |
| `--llm-model` | `llama3.1:8b` | LLM model name |
| `--embed-model` | `nomic-embed-text` | Embedding model name |
| `--llm-base-url` | _(Ollama)_ | LLM API base URL — overrides `OPENAI_BASE_URL` / `OLLAMA_HOST` |
| `--embed-base-url` | _(Ollama)_ | Embedding API base URL |
| `--similarity-threshold` | `0.5` | Cosine similarity cutoff (raise to reduce false positives) |
| `--timeout` | `30` | Scan timeout in minutes (0 = no timeout) |
| `--db` | `./vulns.db` | DuckDB database path |

---

### Multi-project scan

Scan every sub-project in a monorepo with a single command. Each project gets its own `.argusignore`, and results are aggregated in a single report.

```bash
# Scan all services under ./services
argus scan --multi ./services/...

# Scan two specific services
argus scan --multi ./api ./worker

# Multi-scan with JSON output and baseline diff
argus scan --multi ./... --output json --baseline-mode diff > results.json
```

The `./path/...` syntax recursively walks the directory tree and picks up every subdirectory that contains at least one recognized dependency file.

---

### CVSS score filtering

CVSS v3 base scores are computed from advisory vectors during ingest and stored alongside severity labels. Use them for fine-grained filtering beyond broad severity tiers.

```bash
# Only report findings with CVSS ≥ 7.0
argus scan . --min-cvss 7.0

# Exit non-zero only when a finding has CVSS ≥ 8.5
argus scan . --fail-on cvss:8.5

# Show the numeric CVSS column in the summary table
argus scan . --verbose

# Combine: report only HIGH+ with known CVSS ≥ 7, fail on CRITICAL CVSS ≥ 9
argus scan . --min-severity HIGH --min-cvss 7.0 --fail-on cvss:9.0
```

CVSS scores appear in JSON output (`top_cvss_score`, `cvss_score`, `cvss_vector`), SARIF rule properties (`cvssScore`), and the `--verbose` text summary.

---

### `baseline` — manage scan baselines

The baseline feature eliminates CI noise by only surfacing **new** vulnerabilities since the last scan.

```bash
# First run: save a baseline
argus scan . --baseline-mode update

# Subsequent runs: only report new findings
argus scan . --baseline-mode diff

# Inspect the stored baseline
argus baseline show .

# Reset (clear) the baseline for a project
argus baseline reset --confirm .
```

**Baseline modes:**

| Mode | Behaviour |
|---|---|
| `full` | Default — report every finding on every run |
| `diff` | Compare against stored baseline; report only findings not seen before |
| `update` | Run a `diff` scan, then save the new results as the updated baseline |

Baseline state is stored in the DuckDB database (a separate `scan_baseline` table), keyed by the absolute project directory path.

---

### `search` — ad-hoc semantic search

```bash
argus search "sql injection python"
argus search "memory corruption" --ecosystem rust
argus search "path traversal" --ecosystem go --limit 5
```

---

### `doctor` — validate setup

Checks Ollama/OpenAI connectivity, embedding service, and database health in one command.

```bash
argus doctor

# Check a specific project dir for .argus.yaml / .argusignore
argus doctor --project-dir ./myapp

# Check a specific model and endpoint
argus doctor --llm-model gpt-4o-mini --llm-base-url https://api.openai.com/v1
```

Sample output:

```
  ✓ Database       — ./vulns.db (go: 6556 vulns, python: 19045 vulns, ...)
  ✓ Embed service  — nomic-embed-text @ http://localhost:11434 — 768 dims
  ✓ LLM service    — llama3.1:8b @ http://localhost:11434 — OK
  ✓ Config         — .argus.yaml found (min_severity: MEDIUM, workers: 8)
  ✓ Ignore list    — .argusignore found (3 entries)
```

---

### `plugins` — list ecosystem parsers

```bash
argus plugins list
```

```
Registered plugins (10)

 NAME          | FILE PATTERNS                       | SOURCE
 go            | go.mod                              | built-in
 python        | requirements.txt                    | built-in
 rust          | Cargo.toml                          | built-in
 ruby          | Gemfile.lock                        | built-in
 npm-lock      | package-lock.json                   | built-in
 npm-package   | package.json                        | built-in
 maven         | pom.xml                             | built-in
 nuget-config  | packages.config                     | built-in
 nuget-csproj  | *.csproj                            | built-in
 php-composer  | composer.lock                       | external

Plugin directory: /home/user/.argus/plugins
```

---

### `completion` — shell completions

```bash
argus completion bash   > /etc/bash_completion.d/argus
argus completion zsh    > "${fpath[1]}/_argus"
argus completion fish   > ~/.config/fish/completions/argus.fish
argus completion powershell | Out-String | Invoke-Expression
```

---

## Plugin system

argus exposes a stable Go plugin interface so you can add support for new ecosystems without forking the project.

### Interface

```go
// pkg/plugin/plugin.go
type EcosystemPlugin interface {
    Name()         string          // unique plugin name (e.g. "php-composer")
    FilePatterns() []string        // glob/exact file names that trigger this plugin
    Parse(path string) ([]Dependency, error)
}

// Optional: skip a directory if a preferred file already exists
type ConditionalPlugin interface {
    EcosystemPlugin
    SkipDir(dir string) bool
}
```

### Authoring a plugin

1. Create a `.go` file with `package main` and `//go:build ignore` (prevents `go build ./...` from compiling it as a regular package).
2. Implement `EcosystemPlugin` and export it as `var Plugin`.
3. Build a `.so` shared library and drop it in `~/.argus/plugins/`.

```go
//go:build ignore

package main

import (
    "encoding/json"
    "os"

    "github.com/abhishekamralkar/argus/pkg/plugin"
)

type composerLock struct {
    Packages []struct {
        Name    string `json:"name"`
        Version string `json:"version"`
    } `json:"packages"`
}

type phpPlugin struct{}

func (p phpPlugin) Name() string               { return "php-composer" }
func (p phpPlugin) FilePatterns() []string     { return []string{"composer.lock"} }
func (p phpPlugin) Parse(path string) ([]plugin.Dependency, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var lock composerLock
    if err := json.Unmarshal(data, &lock); err != nil {
        return nil, err
    }
    deps := make([]plugin.Dependency, 0, len(lock.Packages))
    for _, pkg := range lock.Packages {
        deps = append(deps, plugin.Dependency{
            Name: pkg.Name, Version: pkg.Version, Ecosystem: "php",
        })
    }
    return deps, nil
}

var Plugin phpPlugin
```

Build and install:

```bash
go build -buildmode=plugin -o ~/.argus/plugins/php-composer.so plugin.go
```

Run `argus plugins list` to confirm the plugin is loaded, then use `argus scan` normally — it will detect `composer.lock` files automatically.

A complete example lives in [`examples/plugins/php/plugin.go`](examples/plugins/php/plugin.go).

---

## Supported ecosystems

| Ecosystem | Dependency file(s) | Ingest sources |
|---|---|---|
| Go | `go.mod` | OSV/Go, GoVulnDB |
| Python | `requirements.txt` | OSV/PyPI, PyPA |
| Rust | `Cargo.toml` | OSV/crates.io, RustSec |
| npm/Node.js | `package-lock.json`, `package.json` | OSV/npm |
| Maven/Java | `pom.xml` | OSV/Maven |
| NuGet/.NET | `packages.config`, `*.csproj` | OSV/NuGet |
| Ruby | `Gemfile.lock` | _(plugin-based; CVE lookup via scan)_ |

---

## OpenAI-compatible API support

argus works with any OpenAI-compatible endpoint — OpenAI, Azure OpenAI, LiteLLM, Ollama's OpenAI layer, vLLM, and others.

**Using OpenAI directly:**

```bash
export OPENAI_API_KEY=sk-...
argus scan . --llm-model gpt-4o-mini --embed-model text-embedding-3-small
```

**Using a custom endpoint (LiteLLM, vLLM, etc.):**

```bash
argus scan . \
  --llm-base-url http://localhost:4000/v1 \
  --embed-base-url http://localhost:4000/v1 \
  --llm-model my-model \
  --embed-model my-embed-model
```

**Auto-detection logic:**

1. If `OPENAI_API_KEY` is set **or** `--llm-base-url` / `OPENAI_BASE_URL` is provided → OpenAI mode
2. Otherwise → Ollama mode (uses `OLLAMA_HOST`, default `http://localhost:11434`)

---

## Configuration file

Place `.argus.yaml` in your project root to avoid repeating flags on every run. CLI flags always take precedence.

```yaml
# .argus.yaml
min_severity: MEDIUM        # skip LOW findings
workers: 8
top_k: 15                   # more vector search candidates
llm_model: llama3.1:8b
embed_model: nomic-embed-text

# OpenAI-compatible endpoint (optional)
# llm_base_url: http://localhost:4000/v1
# embed_base_url: http://localhost:4000/v1
```

---

## Ignore list

Create `.argusignore` in your project root to suppress known false positives or accepted risks:

```
# .argusignore

# Suppress a specific advisory
GHSA-xxxx-yyyy-zzzz
CVE-2024-1234

# Suppress all findings for a package
requests
golang.org/x/text
```

Lines starting with `#` are comments. IDs are matched case-insensitively and against advisory aliases (suppressing a `GO-` ID also suppresses its `CVE-` alias).

---

## CI/CD integration

### Official GitHub Actions action

The simplest way to add argus to any workflow:

```yaml
- name: Run argus vulnerability scan
  uses: abhishekamralkar/argus@main
  with:
    ecosystems: go,python           # ecosystems to ingest
    scan-path: .                    # directory to scan
    output-format: sarif            # text | json | sarif | cyclonedx | spdx
    fail-on: HIGH                   # severity threshold for non-zero exit
    upload-sarif: "true"            # auto-upload to GitHub Security tab
```

See [`action.yml`](action.yml) and [`.github/workflows/argus-example.yml`](.github/workflows/argus-example.yml) for the full reference.

### Manual GitHub Actions (Ollama)

```yaml
- name: Start Ollama
  run: |
    curl -fsSL https://ollama.com/install.sh | sh
    ollama serve &
    ollama pull nomic-embed-text
    ollama pull llama3.1:8b

- name: Cache vulnerability database
  uses: actions/cache@v4
  with:
    path: vulns.db
    key: argus-vulns-${{ runner.os }}-${{ github.run_id }}
    restore-keys: argus-vulns-${{ runner.os }}-

- name: Ingest and scan
  run: |
    argus ingest --ecosystems go,python --quiet
    argus scan . --output sarif > argus.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: argus.sarif
  if: always()
```

### Using OpenAI in CI (no Ollama needed)

```yaml
- name: Scan with OpenAI
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  run: |
    argus ingest --ecosystems go --quiet
    argus scan . --llm-model gpt-4o-mini \
                 --embed-model text-embedding-3-small \
                 --output sarif > argus.sarif
```

### Baseline diff in CI (report only new findings)

```yaml
- name: Restore baseline
  uses: actions/cache@v4
  with:
    path: vulns.db
    key: argus-baseline-${{ github.ref }}
    restore-keys: argus-baseline-

- name: Scan (new findings only)
  run: argus scan . --baseline-mode update --fail-on HIGH
```

---

## Environment variables

| Variable | Description |
|---|---|
| `OLLAMA_HOST` | Ollama server address (default: `http://localhost:11434`) |
| `OPENAI_API_KEY` | Enables OpenAI-compatible mode when set |
| `OPENAI_BASE_URL` | Base URL for OpenAI-compatible endpoint |
| `NO_COLOR` | Set to any value to disable color output |

---

## Inspecting the database

```bash
argus status          # quick summary

duckdb vulns.db       # full SQL access

-- counts per ecosystem
SELECT ecosystem, COUNT(*) FROM vulnerabilities GROUP BY ecosystem;

-- last ingest times
SELECT source, last_run_at FROM ingest_log ORDER BY last_run_at DESC;

-- unpatched CRITICAL vulns
SELECT id, package, ecosystem
FROM vulnerabilities
WHERE severity = 'CRITICAL' AND (fixed_in IS NULL OR fixed_in = '');

-- stored baselines
SELECT project_key, dep_name, ecosystem, scanned_at
FROM scan_baseline ORDER BY scanned_at DESC;
```

---

## Project structure

```
cmd/argus/
  main.go                       CLI entry point (cobra) — all commands
  scan_multi.go                 Multi-project scan logic and aggregated reporting
internal/
  baseline/diff.go              Baseline diff — compare scan results against stored snapshot
  cache/cache.go                Local feed cache (ETag/Last-Modified, XDG_CACHE_HOME)
  color/color.go                Color-coded severity/verdict output
  config/config.go              .argus.yaml loader + validation
  doctor/doctor.go              Self-diagnostic checks (DB, embed, LLM, config)
  embed/client.go               Embedding client (Ollama + OpenAI-compatible)
  ignore/ignore.go              .argusignore loader
  ingest/
    osv.go                      OSV feed (Go, PyPI, crates.io, npm, Maven, NuGet)
    govuln.go                   Go Vulnerability Database (CVSS v3 score computation)
    rustsec.go                  RustSec advisory database
    pypa.go                     PyPA advisory database
    chunk.go                    Document chunking (paragraph → sentence → char split)
  llm/client.go                 LLM client (Ollama + OpenAI-compatible, streaming + retry)
  output/
    output.go                   JSON and SARIF 2.1.0 report writers (with CVSS fields)
    cyclonedx.go                CycloneDX 1.6 JSON SBOM writer
    spdx.go                     SPDX 2.3 JSON SBOM writer
  parser/
    gomod.go                    go.mod parser
    requirements.go             requirements.txt parser
    cargotoml.go                Cargo.toml parser
    packagejson.go              package.json / package-lock.json parser
    pomxml.go                   Maven pom.xml parser
    csproj.go                   NuGet *.csproj / packages.config parser
    gemfile.go                  Ruby Gemfile.lock parser
  rag/query.go                  RAG pipeline — embed, retrieve, filter, sort by CVSS, prompt, generate
  store/
    duckdb.go                   DuckDB vector store — schema, upsert, search, status
    baseline.go                 Scan baseline persistence (scan_baseline table)
    types.go                    Shared Vulnerability type (with CVSSScore, CVSSVector)
  version/compare.go            Semver comparison for version-aware CVE filtering
pkg/plugin/
  plugin.go                     EcosystemPlugin interface + Registry + external plugin loader
  builtins.go                   Built-in parser registrations (wraps internal/parser)
examples/plugins/php/plugin.go  Example external plugin (composer.lock; //go:build ignore)
action.yml                      Official GitHub Actions composite action
Dockerfile                      Slim image (requires external Ollama)
Dockerfile.bundled              Bundled image (Ollama + argus in one container)
docker-compose.yml              Compose setup (Ollama service + argus)
docker-entrypoint.sh            Bundled image entrypoint — starts Ollama, pulls models, runs argus
```

---

## Running tests

```bash
# All tests
go test ./...

# With race detector
go test -race ./...

# Specific package
go test ./internal/parser/... -v
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
