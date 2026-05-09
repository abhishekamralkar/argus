# argus

A RAG-based (Retrieval-Augmented Generation) vulnerability scanner for **Go**, **Python**, **Rust**, **npm/Node.js**, **Maven/Java**, and **NuGet/.NET** projects — powered by local [Ollama](https://ollama.com) models **or** any OpenAI-compatible API. No cloud lock-in. Your code stays on your machine.

[![CI](https://github.com/abhishekamralkar/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/abhishekamralkar/argus/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/abhishekamralkar/argus)](https://github.com/abhishekamralkar/argus/releases)

---

## Quick start

```bash
# 1. Install
go install github.com/abhishekamralkar/argus/cmd/argus@latest

# 2. Start Ollama and pull models
ollama pull nomic-embed-text
ollama pull gpt-oss:20b

# 3. Ingest vulnerability databases (one-time, ~5–15 min)
argus ingest --ecosystems go,python,rust,npm

# 4. Check database status
argus status

# 5. Scan your project
argus scan /path/to/your/project

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
| **Languages** | Go, Python, Rust, npm/Node.js, Maven/Java, NuGet/.NET |
| **Dependency files** | `go.mod`, `requirements.txt`, `Cargo.toml`, `package.json`, `package-lock.json`, `pom.xml`, `*.csproj`, `packages.config` |
| **Data sources** | OSV (all ecosystems), GoVulnDB, RustSec, PyPA |
| **Retrieval** | Document chunking (512-char overlapping), semantic cosine search, configurable `--top-k` |
| **Accuracy** | Version-aware CVE filtering — already-fixed advisories are silently skipped |
| **Accuracy** | Alias-aware deduplication — `GO-2024-x` and `CVE-2024-x` won't double-report |
| **Noise control** | `--min-severity` hides LOW/MEDIUM findings; `.argusignore` suppresses known false positives |
| **Output** | Color terminal, `--output json`, `--output sarif`, `--output cyclonedx`, `--output spdx` |
| **SBOM** | CycloneDX 1.6 JSON and SPDX 2.3 JSON with PURL-linked components and vulnerabilities |
| **Baseline diff** | `--baseline-mode diff/update` — report only new findings since the last scan (CI noise reduction) |
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
ollama pull gpt-oss:20b        # LLM for vulnerability analysis
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
# All standard ecosystems
argus ingest --ecosystems go,python,rust,npm

# Including Maven and NuGet
argus ingest --ecosystems go,python,rust,npm,maven,nuget

# Custom database path
argus ingest --db /var/lib/argus/vulns.db

# Tune chunking (default: 512 chars, 64 overlap)
argus ingest --chunk-size 256 --chunk-overlap 32

# Faster with more workers; suppress progress bar in CI
argus ingest --workers 16 --quiet
```

**Vulnerability data sources:**

| Source | Ecosystems |
|---|---|
| [OSV](https://osv.dev) | Go, Python, Rust, npm, Maven, NuGet |
| [Go Vulnerability Database](https://vuln.go.dev) | Go |
| [RustSec](https://rustsec.org) | Rust |
| [PyPA](https://github.com/pypa/advisory-database) | Python |

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

  Analyzing with gpt-oss:20b (streaming)...
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
| `--fail-on` | `HIGH` | Minimum severity triggering exit code 1 |
| `--baseline-mode` | `full` | `full` = all findings; `diff` = new only; `update` = diff + save baseline |
| `--top-k` | `10` | Vector search candidates per dependency |
| `--workers` | `4` | Parallel dependency analysis workers |
| `--enhance-query` | off | Use LLM to expand search queries before embedding |
| `--llm-model` | `gpt-oss:20b` | LLM model name |
| `--embed-model` | `nomic-embed-text` | Embedding model name |
| `--llm-base-url` | _(Ollama)_ | LLM API base URL — overrides `OPENAI_BASE_URL` / `OLLAMA_HOST` |
| `--embed-base-url` | _(Ollama)_ | Embedding API base URL |
| `--similarity-threshold` | `0.5` | Cosine similarity cutoff (raise to reduce false positives) |
| `--timeout` | `30` | Scan timeout in minutes (0 = no timeout) |
| `--db` | `./vulns.db` | DuckDB database path |

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

### `completion` — shell completions

```bash
argus completion bash   > /etc/bash_completion.d/argus
argus completion zsh    > "${fpath[1]}/_argus"
argus completion fish   > ~/.config/fish/completions/argus.fish
argus completion powershell | Out-String | Invoke-Expression
```

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
llm_model: gpt-oss:20b
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
    ollama pull gpt-oss:20b

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
cmd/argus/main.go              CLI entry point (cobra)
internal/
  baseline/diff.go              Baseline diff logic — compare scan results against stored snapshot
  color/color.go                Color-coded severity/verdict output
  config/config.go              .argus.yaml loader + validation
  embed/ollama.go               Embedding client (Ollama + OpenAI-compatible)
  ignore/ignore.go              .argusignore loader
  ingest/
    osv.go                      OSV feed (Go, PyPI, crates.io, npm, Maven, NuGet)
    govuln.go                   Go Vulnerability Database
    rustsec.go                  RustSec advisory database
    pypa.go                     PyPA advisory database
    chunk.go                    Document chunking (paragraph → sentence → char split)
  llm/ollama.go                 LLM client (Ollama + OpenAI-compatible, streaming + retry)
  output/
    output.go                   JSON and SARIF 2.1.0 report writers
    cyclonedx.go                CycloneDX 1.6 JSON SBOM writer
    spdx.go                     SPDX 2.3 JSON SBOM writer
  parser/
    gomod.go                    go.mod parser
    requirements.go             requirements.txt parser
    cargotoml.go                Cargo.toml parser
    packagejson.go              package.json / package-lock.json parser
    pomxml.go                   Maven pom.xml parser
    csproj.go                   NuGet *.csproj / packages.config parser
  rag/query.go                  RAG pipeline — embed, retrieve, filter, prompt, generate
  store/
    duckdb.go                   DuckDB vector store — schema, upsert, search, status
    baseline.go                 Scan baseline persistence (scan_baseline table)
    types.go                    Shared Vulnerability type
  version/compare.go            Semver comparison for version-aware CVE filtering
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
