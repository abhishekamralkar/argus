BINARY     := argus
CMD        := ./cmd/argus
DB         := ./vulns.db
INSTALL    := $(GOPATH)/bin/$(BINARY)
OLLAMA_HOST ?= http://localhost:11434

.PHONY: all build install clean test lint vet fmt \
        ingest ingest-go ingest-python ingest-rust \
        scan search db-shell db-count db-clean help

# ── default ──────────────────────────────────────────────────────────────────

all: build

# ── build ────────────────────────────────────────────────────────────────────

build:
	go build -o $(BINARY) $(CMD)

install:
	go install $(CMD)

clean:
	rm -f $(BINARY)
	rm -f $(DB) $(DB).wal

# ── test / quality ────────────────────────────────────────────────────────────

test:
	go test ./... -v

test-short:
	go test ./... -short

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found — install from https://golangci-lint.run/usage/install/"; exit 1; }
	golangci-lint run ./...

# ── ingest ───────────────────────────────────────────────────────────────────

ingest: build
	OLLAMA_HOST=$(OLLAMA_HOST) ./$(BINARY) ingest --db $(DB)

ingest-go: build
	OLLAMA_HOST=$(OLLAMA_HOST) ./$(BINARY) ingest --db $(DB) --ecosystems go

ingest-python: build
	OLLAMA_HOST=$(OLLAMA_HOST) ./$(BINARY) ingest --db $(DB) --ecosystems python

ingest-rust: build
	OLLAMA_HOST=$(OLLAMA_HOST) ./$(BINARY) ingest --db $(DB) --ecosystems rust

ingest-fast: build
	OLLAMA_HOST=$(OLLAMA_HOST) ./$(BINARY) ingest --db $(DB) --workers 16

# ── scan ─────────────────────────────────────────────────────────────────────

# Usage: make scan DIR=/path/to/project
scan: build
	OLLAMA_HOST=$(OLLAMA_HOST) ./$(BINARY) scan $(DIR) --db $(DB)

# Usage: make search Q="sql injection"
search: build
	OLLAMA_HOST=$(OLLAMA_HOST) ./$(BINARY) search $(Q) --db $(DB)

# ── database ─────────────────────────────────────────────────────────────────

db-shell:
	duckdb $(DB)

db-count:
	duckdb $(DB) "SELECT ecosystem, COUNT(*) AS total FROM vulnerabilities GROUP BY ecosystem ORDER BY total DESC;"

db-clean:
	rm -f $(DB) $(DB).wal
	@echo "Database removed."

# ── help ─────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  argus Makefile"
	@echo ""
	@echo "  Build"
	@echo "    make build            Build the binary"
	@echo "    make install          Install to \$$GOPATH/bin"
	@echo "    make clean            Remove binary and database"
	@echo ""
	@echo "  Test / Quality"
	@echo "    make test             Run all tests"
	@echo "    make test-short       Run tests with -short flag"
	@echo "    make vet              Run go vet"
	@echo "    make fmt              Run gofmt"
	@echo "    make lint             Run golangci-lint"
	@echo ""
	@echo "  Ingest"
	@echo "    make ingest           Ingest all ecosystems (go, python, rust)"
	@echo "    make ingest-go        Ingest Go vulnerabilities only"
	@echo "    make ingest-python    Ingest Python vulnerabilities only"
	@echo "    make ingest-rust      Ingest Rust vulnerabilities only"
	@echo "    make ingest-fast      Ingest with 16 workers"
	@echo ""
	@echo "  Scan / Search"
	@echo "    make scan DIR=.       Scan a project directory"
	@echo "    make search Q='...'   Semantic search the vulnerability DB"
	@echo ""
	@echo "  Database"
	@echo "    make db-shell         Open DuckDB interactive shell"
	@echo "    make db-count         Show vulnerability counts per ecosystem"
	@echo "    make db-clean         Delete the database file"
	@echo ""
	@echo "  Environment"
	@echo "    OLLAMA_HOST           Ollama server (default: http://localhost:11434)"
	@echo "    DIR                   Project directory for 'make scan'"
	@echo "    Q                     Query string for 'make search'"
	@echo ""
