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

# 4. Scan your project
argus scan /path/to/your/project

# 5. Check version
argus version
```

That's it. Results stream to your terminal; exit code is `1` when HIGH/CRITICAL findings are present.

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
│                       Version-aware CVE filter                  │
│                                       │                         │
│                                       ▼                         │
│                           LLM prompt (gpt-oss:20b) ──► Report  │
└─────────────────────────────────────────────────────────────────┘
```

Vulnerability databases are chunked, embedded, and stored locally in DuckDB. Each scan embeds your dependency query, retrieves semantically similar CVE chunks, filters out advisories your version has already fixed, and feeds the remaining context to a local LLM for a human-readable security report.

---

## Features

- **Fully local** — Ollama models, DuckDB on disk, no external API calls after ingestion
- **Multi-language** — Go (`go.mod`), Python (`requirements.txt`), Rust (`Cargo.toml`)
- **Four vulnerability databases** — OSV, Go Vulnerability Database, RustSec, PyPA
- **Document chunking** — long advisories split into overlapping 512-char chunks for higher-precision retrieval
- **Version-aware matching** — CVEs already fixed in your version are silently skipped
- **Semantic search** — finds relevant CVEs even when package names don't match exactly
- **Streaming output** — LLM analysis streams token-by-token to your terminal
- **Multiple output formats** — `text` (default), `json`, `sarif` (GitHub Security tab compatible)
- **Parallel scanning** — dependencies analyzed concurrently with a configurable worker pool
- **CI-friendly** — exits with code `1` when HIGH/CRITICAL vulnerabilities are found
- **Idempotent ingestion** — re-running `ingest` upserts without duplicates

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

Pre-built binaries for Linux, macOS, and Windows are available on the [Releases](https://github.com/abhishekamralkar/argus/releases) page.

---

## Usage

### ingest — populate the vulnerability database

Downloads and embeds all vulnerability databases into a local DuckDB file. Run once, then periodically to pick up new advisories.

```bash
# All ecosystems (default)
argus ingest

# Specific ecosystems
argus ingest --ecosystems go,python

# Custom database path
argus ingest --db /var/lib/argus/vulns.db

# Tune chunking (default: 512 chars, 64 overlap)
argus ingest --chunk-size 256 --chunk-overlap 32

# Legacy single-embedding mode (no chunking)
argus ingest --no-chunk

# More parallelism for faster embedding
argus ingest --workers 16
```

**What gets downloaded:**

| Source | Ecosystems | URL |
|---|---|---|
| OSV | Go, Python, Rust | `osv-vulnerabilities.storage.googleapis.com` |
| Go Vulnerability DB | Go | `vuln.go.dev` |
| RustSec | Rust | `github.com/rustsec/advisory-db` |
| PyPA | Python | `github.com/pypa/advisory-database` |

---

### scan — analyse a project's dependencies

Point `argus scan` at any project directory containing `go.mod`, `requirements.txt`, or `Cargo.toml`:

```bash
argus scan /path/to/your/project
```

**Text output (default):**

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
  "scanned_at": "2026-05-02T10:00:00Z",
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

**SARIF output** (for GitHub Security tab):

```bash
argus scan . --output sarif > results.sarif
```

Upload `results.sarif` as a GitHub Actions artifact with `github/codeql-action/upload-sarif` and findings appear natively in the Security tab.

**All scan flags:**

```bash
argus scan /path/to/project \
  --db ./vulns.db \
  --llm-model gpt-oss:20b \
  --embed-model nomic-embed-text \
  --output text|json|sarif \
  --workers 4 \
  --enhance-query        # LLM expands query before embedding
```

---

### search — ad-hoc semantic search

Search the vulnerability database without running a full scan:

```bash
argus search "sql injection python"
argus search "memory corruption" --ecosystem rust
argus search "path traversal" --ecosystem go --limit 5
```

---

## Configuration

| Flag | Env | Default | Description |
|---|---|---|---|
| `--db` | — | `./vulns.db` | DuckDB database path |
| `--embed-model` | — | `nomic-embed-text` | Ollama embedding model |
| `--llm-model` | — | `gpt-oss:20b` | Ollama generation model |
| — | `OLLAMA_HOST` | `http://localhost:11434` | Ollama server address |

---

## CI/CD integration

### Basic GitHub Actions

```yaml
- name: Install argus
  run: go install github.com/abhishekamralkar/argus/cmd/argus@latest

- name: Ingest vulnerability databases
  run: argus ingest --ecosystems go   # cache vulns.db between runs

- name: Scan dependencies
  run: argus scan .
  # exits 1 on HIGH/CRITICAL findings
```

### With SARIF upload

```yaml
- name: Scan and emit SARIF
  run: argus scan . --output sarif > argus.sarif

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: argus.sarif
```

### Cache the vulnerability database

```yaml
- name: Cache argus DB
  uses: actions/cache@v4
  with:
    path: vulns.db
    key: argus-vulns-${{ runner.os }}-${{ steps.date.outputs.date }}
    restore-keys: argus-vulns-${{ runner.os }}-
```

---

## Inspecting the database

```bash
duckdb vulns.db

-- row counts per ecosystem
SELECT ecosystem, COUNT(*) FROM vulnerabilities GROUP BY ecosystem;

-- chunk coverage (chunked ingestion)
SELECT v.ecosystem, COUNT(c.chunk_id) AS chunks
FROM vulnerability_chunks c
JOIN vulnerabilities v ON c.vuln_id = v.id
GROUP BY v.ecosystem;

-- CRITICAL vulnerabilities with no fix
SELECT id, package, ecosystem
FROM vulnerabilities
WHERE severity = 'CRITICAL' AND (fixed_in IS NULL OR fixed_in = '');

-- search by package name
SELECT id, severity, fixed_in
FROM vulnerabilities
WHERE package ILIKE '%requests%' AND ecosystem = 'python';
```

---

## Project structure

```
cmd/argus/main.go            CLI entry point (cobra)
internal/
  embed/ollama.go              Ollama embedding client (nomic-embed-text)
  llm/ollama.go                Ollama generation client (gpt-oss:20b, streaming)
  store/
    duckdb.go                  DuckDB vector store — schema, upsert, similarity search
    types.go                   Shared types (Vulnerability)
  ingest/
    osv.go                     OSV vulnerability feed (Go, PyPI, crates.io)
    govuln.go                  Go Vulnerability Database
    rustsec.go                 RustSec advisory database
    pypa.go                    PyPA advisory database
    chunk.go                   Document chunking (paragraph → sentence → char split)
  parser/
    gomod.go                   go.mod parser
    requirements.go            requirements.txt parser
    cargotoml.go               Cargo.toml parser
  rag/query.go                 RAG pipeline — embed, retrieve, version-filter, prompt, generate
  version/compare.go           Semver comparison for version-aware CVE filtering
  output/output.go             JSON and SARIF report writers
```

---

## Running tests

```bash
go test ./...
go test -race ./...
```

Parser tests run offline using fixture files in `internal/parser/testdata/`.
Version comparison tests are in `internal/version/`.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Ideas for future contribution:

- Support for `poetry.lock`, `Pipfile.lock`, `go.sum` lock files
- TUI / web frontend for interactive browsing
- Additional ecosystems (npm, Maven, NuGet)
- Scheduled auto-reingest via cron/systemd

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
