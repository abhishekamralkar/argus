# Contributing to argus

Thank you for your interest in contributing!

## Development setup

```bash
git clone https://github.com/abhishekamralkar/argus.git
cd argus

# Install Go 1.21+, then build
make build
./argus version

# Pull Ollama models (needed for integration tests)
ollama pull nomic-embed-text
ollama pull gpt-oss:20b

# Run tests
make test

# Lint (requires golangci-lint)
make lint
```

## Workflow

1. Open an issue first for significant changes — align on approach before writing code
2. Fork the repo, create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes, keeping PRs focused (one feature or fix per PR)
4. Ensure `make vet` and `make test` pass before opening a PR
5. Update `CHANGELOG.md` under the `[Unreleased]` section

## Adding a new vulnerability source

Each source is a self-contained Go file under `internal/ingest/`.

1. Create `internal/ingest/<source>.go`
2. Implement the loader signature:
   ```go
   func Load<Source>(fn func(*store.Vulnerability) error) error
   ```
3. Populate all fields of `store.Vulnerability`:
   ```go
   &store.Vulnerability{
       ID:        "SOURCE-2024-0001",  // unique, stable ID
       Ecosystem: "go",                // "go", "python", or "rust"
       Package:   "example.com/pkg",
       Summary:   "One-line description",
       Details:   "Full advisory text...",
       Severity:  "HIGH",             // CRITICAL, HIGH, MEDIUM, LOW, or ""
       FixedIn:   "1.2.3",            // earliest safe version
   }
   ```
4. Wire the loader into `runIngest()` in `cmd/argus/main.go` under the appropriate ecosystem case
5. Add a test using a fixture file under `internal/ingest/testdata/`

## Adding a new language / dependency file

1. Create `internal/parser/<lang>.go`
2. Implement:
   ```go
   func Parse<File>(path string) ([]parser.Dependency, error)
   ```
3. Add fixture files under `internal/parser/testdata/`
4. Write tests in `internal/parser/` alongside the parser
5. Register the file name + parser in `detectAndParse()` in `cmd/argus/main.go`

## Adding a new output format

Output writers live in `internal/output/output.go`.

1. Add a `Write<Format>(w io.Writer, results []rag.Result, ...) error` function
2. Wire it into the `switch outputFmt` block in `scanCmd` in `cmd/argus/main.go`
3. Update the `--output` flag description and README

## Code style

- Run `make fmt` before committing (`gofmt -s`)
- No commented-out code; no TODO comments in PRs
- No new exported symbols without a one-line doc comment
- Prefer table-driven tests with `t.Run`

## Reporting a bug

Open a GitHub issue with:

- OS and Go version (`go version`)
- argus version (`argus version`)
- Steps to reproduce
- Expected vs actual behaviour
- Relevant output or error messages

## Security vulnerabilities

Please do **not** open a public issue for security vulnerabilities. Email
[abhishekamralkar@gmail.com](mailto:abhishekamralkar@gmail.com) directly.

## License

By contributing you agree your changes will be licensed under the Apache 2.0 license.
