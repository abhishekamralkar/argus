# Changelog

All notable changes to argus are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.1.0] — 2026-05-02

### Added

**Core pipeline**
- RAG-based vulnerability scanner for Go, Python, and Rust projects
- Fully local — Ollama models (`nomic-embed-text`, `gpt-oss:20b`), DuckDB on disk
- `argus ingest` — download and embed four vulnerability databases:
  - OSV (Go, PyPI, crates.io)
  - Go Vulnerability Database (`vuln.go.dev`)
  - RustSec advisory database
  - PyPA advisory database
- `argus scan` — parse dependency files, retrieve relevant CVEs, stream LLM analysis
- `argus search` — ad-hoc semantic search against the vulnerability database
- `argus version` — print version (injected at build time via `-ldflags`)

**Ingestion**
- Document chunking: long advisories split into overlapping 512-char chunks (configurable via `--chunk-size` / `--chunk-overlap`)
- `--no-chunk` flag to fall back to single-embedding-per-advisory
- Parallel embed workers (`--workers`) with single-writer goroutine to avoid DuckDB contention
- Idempotent upserts — safe to re-run; existing entries are updated, not duplicated

**Scanning**
- Version-aware CVE filtering: advisories already fixed in the scanned version are silently skipped
- Parallel dependency analysis (`--workers`, default 4)
- `--enhance-query` flag: LLM expands search query for higher recall
- `SearchBest`: automatically uses chunk table when populated, falls back to legacy whole-doc embeddings

**Output formats**
- `--output text` (default): tabular CVE table + streaming LLM analysis + summary table
- `--output json`: machine-readable report with findings per dependency
- `--output sarif`: SARIF 2.1.0 compatible with GitHub Security tab

**CI**
- GitHub Actions workflow: `go vet`, `go test -race`, build with version injection, `golangci-lint`
- Exit code `1` on HIGH/CRITICAL findings for pipeline integration

**Parsers**
- `go.mod` → `[]Dependency`
- `requirements.txt` → `[]Dependency`
- `Cargo.toml` → `[]Dependency`

---

[Unreleased]: https://github.com/abhishekamralkar/argus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/abhishekamralkar/argus/releases/tag/v0.1.0
