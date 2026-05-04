# argus

A RAG-based (Retrieval-Augmented Generation) vulnerability scanner for **Go**, **Python**, and **Rust** projects — powered entirely by local [Ollama](https://ollama.com) models. No API keys. No cloud. Your code stays on your machine.

[![CI](https://github.com/abhishekamralkar/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/abhishekamralkar/argus/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/abhishekamralkar/argus)](https://github.com/abhishekamralkar/argus/releases)

---

## Quick start

```bash
# 1. Install
go install github.com/abhishekamralkar/argus/cmd/argus@latest

# 2. Start Ollama and pull models
ollama pull nomic-embed-text
ollama pull gpt-oss:20b

# 3. Ingest vulnerability databases (one-time, ~5–10 min)
argus ingest --ecosystems go

# 4. Check database status
argus status

# 5. Scan your project
argus scan /path/to/your/project

# 6. Check version
argus version
```

Results stream to your terminal with color-coded severity; exit code is `1` when findings meet or exceed your `--fail-on` threshold (default: HIGH).

---

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│                        INGEST (one-time)                        │
│                                                                 │
│  OSV Feed ──┐                                                   │
│  GoVulnDB ──┼──► Parse ──► Chunk ──► Embed (nomic-embed-text)  │
│  RustSec  ──┤              512 chars   (Ollama, local)          │
│  PyPA     ──┘                    ──► DuckDB (local)             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                         SCAN (per project)                      │
│                                                                 │
│  go.mod / requirements.txt / Cargo.toml                        │
│       │                                                         │
│       ▼                                                         │
│  Parse deps ──► Embed query ──► Cosine search (DuckDB)         │
│                                       │                         │
│                                       ▼                         │
│              Ignore list · Alias dedup · Version filter         │
│              Min-severity gate · Parallel workers               │
│                                       │                         │
│                                       ▼                         │
│                    LLM prompt (gpt-oss:20b) ──► Report          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

| Category | Feature |
|---|---|
| **Privacy** | Fully local — Ollama models + DuckDB on disk, zero external API calls after ingestion |
| **Languages** | Go (`go.mod`), Python (`requirements.txt`), Rust (`Cargo.toml`) |
| **Data sources** | OSV, Go Vulnerability Database, RustSec, PyPA |
| **Retrieval** | Document chunking (512-char overlapping), semantic cosine search |
| **Accuracy** | Version-aware CVE filtering — already-fixed advisories are silently skipped |
| **Accuracy** | Alias-aware deduplication — `GO-2024-x` and `CVE-2024-x` won't double-report |
| **Noise control** | `--min-severity` hides LOW/MEDIUM findings; `.argusignore` accepts/suppresses known FPs |
| **Output** | Color-coded terminal output, `--output json`, `--output sarif` (GitHub Security tab) |
| **Performance** | Parallel scan workers, parallel embed workers, exponential-backoff retry on Ollama errors |
| **CI** | `--fail-on` threshold flag, exits non-zero on findings, SARIF upload support |
| **Config** | `.argus.yaml` project config file — no need to repeat flags in every CI command |

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Go | 1.21+ | `go install` builds the binary |
| [Ollama](https://ollama.com) | latest | Must be running locally |
| DuckDB CLI | optional | For manual DB inspection |

### Pull required Ollama models

```bash
ollama pull nomic-embed-text   # embedding model (768-dim)
ollama pull gpt-oss:20b        # LLM for vulnerability analysis
```

---

## Installation

### From source

```bash
git clone https://github.com/abhishekamralkar/argus.git
cd argus
make build           # embeds git version in binary
./argus version
```

### go install

```bash
go install github.com/abhishekamralkar/argus/cmd/argus@latest
```

### Download a release binary

Pre-built binaries for Linux, macOS, and Windows (amd64 + arm64) are on the [Releases](https://github.com/abhishekamralkar/argus/releases) page. SHA-256 checksums and cosign signatures are included.

### Docker

```bash
docker run --rm \
  -v "$PWD:/project" \
  -v argus-data:/data \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/abhishekamralkar/argus \
  scan /project
```

---

## Commands

### `ingest` — populate the vulnerability database

Downloads and embeds all vulnerability databases into a local DuckDB file. Run once, then periodically to pick up new advisories. Re-running is safe — stale chunks are replaced, not accumulated.

```bash
# All ecosystems (default)
argus ingest

# Specific ecosystems
argus ingest --ecosystems go,python

# Custom database path
argus ingest --db /var/lib/argus/vulns.db

# Tune chunking (default: 512 chars, 64 overlap)
argus ingest --chunk-size 256 --chunk-overlap 32

# Disable chunking (single embedding per advisory)
argus ingest --no-chunk

# Faster ingestion with more workers
argus ingest --workers 16
```

**What gets downloaded:**

| Source | Ecosystems |
|---|---|
| OSV | Go, Python, Rust |
| Go Vulnerability Database | Go |
| RustSec advisory database | Rust |
| PyPA advisory database | Python |

---

### `status` — database health check

```bash
argus status
```

```
Vulnerability Database — ./vulns.db

 ECOSYSTEM | VULNERABILITIES | CHUNKS  | LAST INGEST
 go        | 6556            | 48203   | 2026-05-03T08:12:00Z
 python    | 19045           | 134821  | 2026-05-03T08:31:00Z
 rust      | 2267            | 15901   | 2026-05-03T08:36:00Z
```

---

### `scan` — analyse a project's dependencies

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
  ────────────────────────────────────────────────────────────
  1. Vulnerable: YES
  2. Severity: HIGH
  3. Advisory: GO-2021-0227 (CVE-2021-43565)
  4. Fix: upgrade to golang.org/x/crypto v0.17.0 or later
  5. The SSH server implementation accepts an empty plaintext
     password even when password auth is disabled.
```

**JSON output:**

```bash
argus scan . --output json > results.json
```

```json
{
  "scanned_at": "2026-05-03T10:00:00Z",
  "results": [
    {
      "package": "golang.org/x/crypto",
      "version": "0.0.0-20190308221718",
      "ecosystem": "go",
      "verdict": "HIGH",
      "severity": "HIGH",
      "cve_count": 1,
      "findings": [
        {
          "id": "GO-2021-0227",
          "severity": "HIGH",
          "fixed_in": "0.17.0",
          "score": 0.923
        }
      ]
    }
  ]
}
```

**SARIF output** (GitHub Security tab):

```bash
argus scan . --output sarif > argus.sarif
```

**All scan flags:**

| Flag | Default | Description |
|---|---|---|
| `--output` | `text` | Output format: `text`, `json`, `sarif` |
| `--min-severity` | _(all)_ | Minimum severity to report: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--fail-on` | `HIGH` | Minimum severity triggering exit code 1 |
| `--workers` | `4` | Parallel dependency analysis workers |
| `--enhance-query` | off | LLM expands search query before embedding |
| `--llm-model` | `gpt-oss:20b` | Ollama generation model |
| `--embed-model` | `nomic-embed-text` | Ollama embedding model |
| `--db` | `./vulns.db` | DuckDB database path |

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
# Bash
argus completion bash > /etc/bash_completion.d/argus

# Zsh
argus completion zsh > "${fpath[1]}/_argus"

# Fish
argus completion fish > ~/.config/fish/completions/argus.fish

# PowerShell
argus completion powershell | Out-String | Invoke-Expression
```

---

## Configuration file

Place `.argus.yaml` in your project root to avoid repeating flags on every run. CLI flags always take precedence.

```yaml
# .argus.yaml
min_severity: MEDIUM      # skip LOW findings
workers: 8                # more parallel analysis workers
llm_model: gpt-oss:20b
embed_model: nomic-embed-text
```

See [`.argus.yaml.example`](.argus.yaml.example) for all available options.

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

Lines starting with `#` are comments. IDs are matched case-insensitively and also matched against advisory aliases (e.g. suppressing a `GO-` ID also suppresses its `CVE-` alias).

---

## CI/CD integration

### Basic GitHub Actions

```yaml
- name: Install argus
  run: go install github.com/abhishekamralkar/argus/cmd/argus@latest

- name: Cache vulnerability database
  uses: actions/cache@v4
  with:
    path: vulns.db
    key: argus-vulns-${{ runner.os }}-${{ steps.date.outputs.date }}
    restore-keys: argus-vulns-${{ runner.os }}-

- name: Ingest vulnerability databases
  run: argus ingest --ecosystems go

- name: Scan dependencies
  run: argus scan . --min-severity MEDIUM --fail-on HIGH
```

### With SARIF upload (GitHub Security tab)

```yaml
- name: Scan and emit SARIF
  run: argus scan . --output sarif > argus.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: argus.sarif
  if: always()
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server address |
| `NO_COLOR` | _(unset)_ | Set to any value to disable color output |

---

## Inspecting the database

```bash
argus status          # quick summary

duckdb vulns.db       # full SQL access

-- counts per ecosystem
SELECT ecosystem, COUNT(*) FROM vulnerabilities GROUP BY ecosystem;

-- chunk coverage
SELECT v.ecosystem, COUNT(c.chunk_id) AS chunks
FROM vulnerability_chunks c
JOIN vulnerabilities v ON c.vuln_id = v.id
GROUP BY v.ecosystem;

-- last ingest times
SELECT source, last_run_at FROM ingest_log ORDER BY last_run_at DESC;

-- unpatched CRITICAL vulns
SELECT id, package, ecosystem
FROM vulnerabilities
WHERE severity = 'CRITICAL' AND (fixed_in IS NULL OR fixed_in = '');
```

---

## Project structure

```
cmd/argus/main.go              CLI entry point (cobra)
internal/
  color/color.go                Color-coded severity/verdict output
  config/config.go              .argus.yaml loader
  embed/ollama.go               Ollama embedding client (nomic-embed-text)
  ignore/ignore.go              .argusignore loader
  ingest/
    osv.go                      OSV vulnerability feed (Go, PyPI, crates.io)
    govuln.go                   Go Vulnerability Database
    rustsec.go                  RustSec advisory database
    pypa.go                     PyPA advisory database
    chunk.go                    Document chunking (paragraph → sentence → char split)
  llm/ollama.go                 Ollama generation client (gpt-oss:20b, streaming + retry)
  output/output.go              JSON and SARIF 2.1.0 report writers
  parser/
    gomod.go                    go.mod parser
    requirements.go             requirements.txt parser
    cargotoml.go                Cargo.toml parser
  rag/query.go                  RAG pipeline — embed, retrieve, filter, prompt, generate
  store/
    duckdb.go                   DuckDB vector store — schema, upsert, search, status
    types.go                    Shared Vulnerability type
  version/compare.go            Semver comparison for version-aware CVE filtering
```

---

## Running tests

```bash
# All tests
go test ./...

# With race detector
go test -race ./...

# Benchmarks
go test -bench=. -benchmem ./internal/store/...
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Ideas for future contribution:

- Support for `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `pom.xml`
- Additional ecosystems (npm, Maven, NuGet)
- TUI / web frontend for interactive browsing
- Scheduled auto-reingest via cron / systemd timer
- SBOM generation (CycloneDX, SPDX)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
