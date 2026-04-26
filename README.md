# argus

A RAG-based (Retrieval-Augmented Generation) vulnerability scanner for **Go**, **Python**, and **Rust** projects — powered entirely by local [Ollama](https://ollama.com) models. No API keys. No cloud. Your code stays on your machine.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org)

---

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│                        INGEST (one-time)                        │
│                                                                 │
│  OSV Feed ──┐                                                   │
│  GoVulnDB ──┼──► Parse ──► Embed (nomic-embed-text) ──► DuckDB │
│  RustSec  ──┤             (Ollama, local)               (local) │
│  PyPA     ──┘                                                   │
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
│                              Retrieved CVEs + context           │
│                                       │                         │
│                                       ▼                         │
│                           LLM prompt (gpt-oss:20b) ──► Report  │
└─────────────────────────────────────────────────────────────────┘
```

Vulnerability databases are embedded once and stored locally in DuckDB. Each scan embeds your dependency query and retrieves semantically similar CVEs, which are fed to a local LLM to generate a human-readable security report.

---

## Features

- **Fully local** — Ollama models, DuckDB on disk, no external API calls after ingestion
- **Multi-language** — Go (`go.mod`), Python (`requirements.txt`), Rust (`Cargo.toml`)
- **Four vulnerability databases** — OSV, Go Vulnerability Database, RustSec, PyPA
- **Semantic search** — finds relevant CVEs even when package names don't match exactly
- **Streaming output** — LLM analysis streams token-by-token to your terminal
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

```bash
git clone https://github.com/abhishekamralkar/argus.git
cd argus
go build -o argus ./cmd/argus
```

Or install directly:

```bash
go install github.com/abhishekamralkar/argus/cmd/argus@latest
```

---

## Usage

### Step 1 — Ingest vulnerability databases

Downloads and embeds all vulnerability databases into a local DuckDB file. Run this once, then periodically to pick up new advisories.

```bash
argus ingest
```

Ingest specific ecosystems only:

```bash
argus ingest --ecosystems go,python
```

Custom DB path:

```bash
argus ingest --db /var/lib/argus/vulns.db
```

**What gets downloaded:**

| Source | Ecosystem | URL |
|---|---|---|
| OSV | Go, Python, Rust | `osv-vulnerabilities.storage.googleapis.com` |
| Go Vulnerability DB | Go | `vuln.go.dev` |
| RustSec | Rust | `github.com/rustsec/advisory-db` |
| PyPA | Python | `github.com/pypa/advisory-database` |

---

### Step 2 — Scan a project

Point `argus scan` at any project directory containing a `go.mod`, `requirements.txt`, or `Cargo.toml`:

```bash
argus scan /path/to/your/project
```

Example output:

```
=== argus: /path/to/your/project (42 dependencies) ===

--- golang.org/x/crypto@0.0.0-20190308221718 (go) ---
1. Vulnerable: YES
2. Severity: HIGH
3. Advisory: GO-2021-0227 (CVE-2021-43565)
4. Fix: upgrade to golang.org/x/crypto v0.17.0 or later
5. The SSH server implementation accepts an empty plaintext password
   even when the server has disabled password authentication. An
   attacker can bypass authentication on affected servers.

--- flask@2.3.2 (python) ---
No known vulnerabilities found for flask@2.3.2.

--- serde@1.0 (rust) ---
No known vulnerabilities found for serde@1.0.
```

Flags:

```bash
argus scan /path/to/project \
  --db ./vulns.db \
  --llm-model gpt-oss:20b \
  --embed-model nomic-embed-text \
  --output text
```

---

### Step 3 — Ad-hoc semantic search

Search the vulnerability database without running a full scan:

```bash
argus search "sql injection python"
argus search "memory corruption" --ecosystem rust
argus search "path traversal" --ecosystem go --limit 5
```

Example output:

```
[0.891] PYSEC-2024-52 | sqlalchemy | HIGH | fixed: 2.0.21
  SQL injection via unsanitized input in ORM query builder

[0.834] GHSA-xxxx-yyyy-zzzz | django | MEDIUM | fixed: 4.2.4
  QuerySet.annotate() vulnerable to SQL injection
```

---

## Configuration

All configuration is via flags and environment variables:

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--db` | — | `./vulns.db` | DuckDB database path |
| `--embed-model` | — | `nomic-embed-text` | Ollama embedding model |
| `--llm-model` | — | `gpt-oss:20b` | Ollama generation model |
| — | `OLLAMA_HOST` | `http://localhost:11434` | Ollama server address |

---

## CI/CD Integration

`argus scan` exits with code `1` when HIGH or CRITICAL vulnerabilities are detected, making it easy to fail pipelines.

**GitHub Actions:**

```yaml
- name: Install argus
  run: go install github.com/abhishekamralkar/argus/cmd/argus@latest

- name: Start Ollama
  run: |
    curl -fsSL https://ollama.com/install.sh | sh
    ollama serve &
    sleep 5
    ollama pull nomic-embed-text
    ollama pull gpt-oss:20b

- name: Ingest vulnerability databases
  run: argus ingest

- name: Scan dependencies
  run: argus scan .
```

---

## Inspecting the database

Use the DuckDB CLI to query `vulns.db` directly:

```bash
duckdb vulns.db

-- counts per ecosystem
SELECT ecosystem, COUNT(*) FROM vulnerabilities GROUP BY ecosystem;

-- CRITICAL vulnerabilities with no fix
SELECT id, package, ecosystem
FROM vulnerabilities
WHERE severity = 'CRITICAL' AND (fixed_in IS NULL OR fixed_in = '');

-- search by package name
SELECT id, severity, fixed_in
FROM vulnerabilities
WHERE package ILIKE '%requests%' AND ecosystem = 'python';
```

See [DuckDB commands reference](docs/duckdb-commands.md) for more.

---

## Project structure

```
cmd/argus/main.go          CLI entry point (cobra)
internal/
  embed/ollama.go             Ollama embedding client (nomic-embed-text)
  llm/ollama.go               Ollama generation client (gpt-oss:20b, streaming)
  store/duckdb.go             DuckDB vector store — schema, upsert, similarity search
  ingest/
    osv.go                    OSV vulnerability feed (Go, PyPI, crates.io)
    govuln.go                 Go Vulnerability Database
    rustsec.go                RustSec advisory database
    pypa.go                   PyPA advisory database
  parser/
    gomod.go                  go.mod parser
    requirements.go           requirements.txt parser
    cargotoml.go              Cargo.toml parser
  rag/query.go                RAG pipeline — embed, retrieve, prompt, generate
```

---

## Running tests

```bash
go test ./...
```

Parser tests run entirely offline using fixture files in `internal/parser/testdata/`.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Ideas for contribution:

- JSON output format for `scan`
- Support for `poetry.lock`, `Pipfile.lock`, `go.sum`
- Query expansion (LLM rewrites user query before embedding)
- Document chunking for long advisories
- Web UI / TUI frontend
- Support for additional Ollama models

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
