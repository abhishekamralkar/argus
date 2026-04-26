# Contributing to argus

Thank you for your interest in contributing!

## Getting started

1. Fork the repository and clone your fork
2. Install Go 1.21+ and [Ollama](https://ollama.com)
3. Pull required models: `ollama pull nomic-embed-text && ollama pull gpt-oss:20b`
4. Build: `go build ./cmd/argus`
5. Run tests: `go test ./...`

## Making changes

- Open an issue first for significant changes so we can align on approach
- Keep PRs focused — one feature or fix per PR
- Add or update tests for any changed behaviour
- Run `go vet ./...` and `go test ./...` before submitting

## Adding a new vulnerability database

1. Create `internal/ingest/<source>.go`
2. Implement a `Load<Source>(fn func(*store.Vulnerability) error) error` function
3. Normalize into `store.Vulnerability` — populate `ID`, `Ecosystem`, `Package`, `Summary`, `Details`, `Severity`, `FixedIn`
4. Wire it into `runIngest()` in `cmd/argus/main.go`

## Adding a new language / dependency file

1. Create `internal/parser/<lang>.go`
2. Implement `Parse<File>(path string) ([]Dependency, error)`
3. Add fixture files under `internal/parser/testdata/`
4. Write tests in `internal/parser/parser_test.go`
5. Register the file in `detectAndParse()` in `cmd/argus/main.go`

## Reporting a bug

Open a GitHub issue with:
- OS and Go version
- `argus` version or commit hash
- Steps to reproduce
- Expected vs actual behaviour

## License

By contributing you agree your changes will be licensed under Apache 2.0.
