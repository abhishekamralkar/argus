# Quality PR

Run the full quality gate before opening a pull request: golangci-lint, govulncheck, and the test suite. Fix any issues found, commit the fixes, then create the PR. Never raise a PR with known lint errors, vulnerabilities, or failing tests.

## Step 1 — Verify branch

Run `git branch --show-current`. If the result is `main`, stop immediately and tell the user to switch to a feature branch first.

## Step 2 — golangci-lint

Run:
```bash
golangci-lint run --timeout=5m ./...
```

If it exits with code 0, proceed to Step 3.

If there are lint errors, fix every one of them in the source files:

- **`unused variable / import`**: remove the declaration
- **`errcheck`**: handle or explicitly discard the error with `//nolint:errcheck` only when the error is genuinely safe to ignore — prefer fixing
- **`govet`, `staticcheck`, `gosimple`**: apply the suggested transformation directly
- **`revive` / `stylecheck` (naming, comment format)**: rename or reformat
- **`gocritic`**: apply the suggested refactor
- For anything ambiguous, fix the simplest interpretation that satisfies the linter

After fixing, re-run `golangci-lint run --timeout=5m ./...` and repeat until it exits 0. Do NOT proceed with lint failures.

Once lint is clean, stage and commit the lint fixes:
```
fix(lint): resolve golangci-lint issues before PR
```
Only commit this if there were actual changes — skip the commit if lint was already clean.

## Step 3 — govulncheck

Run:
```bash
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

If it exits cleanly (no vulnerabilities in code you call), proceed to Step 4.

If vulnerabilities are found:

- **stdlib vulnerabilities** (package path starts with `crypto/`, `net/`, `os`, `io`, `syscall`, etc.): upgrade the Go toolchain:
  ```bash
  GOTOOLCHAIN=auto go get go@<fixed-version>
  GOTOOLCHAIN=auto go mod tidy
  ```
- **Third-party module vulnerabilities**: upgrade the affected module:
  ```bash
  GOTOOLCHAIN=auto go get <module>@<fixed-version>
  GOTOOLCHAIN=auto go mod tidy
  ```

Re-run govulncheck after each fix and repeat until clean. Then commit only `go.mod` and `go.sum`:
```
fix(deps): resolve govulncheck vulnerabilities before PR

- <list each fix, e.g. "upgrade Go to 1.26.3 (GO-2026-xxxx)">
```
Only commit if there were actual changes.

## Step 4 — Full test suite

Run:
```bash
go test -race -timeout 120s ./internal/...
```

If any tests fail, stop and report the failure to the user with the full error output. Do NOT create the PR.

## Step 5 — Create the PR

Gather context:
- `git log main..HEAD --oneline` — summarise the commits on this branch
- `git diff main...HEAD --stat` — list changed files

Create the PR with `gh pr create --base main`. The PR body must include:

1. **Problem** — what issue this branch fixes (reference the GitHub issue number if one exists)
2. **Solution** — what was changed and why
3. **Quality gate results** — one line each confirming:
   - `golangci-lint`: clean (or: fixed N issues)
   - `govulncheck`: no vulnerabilities (or: fixed N CVEs, list them)
   - Tests: all pass
4. **Test plan** — what was tested

Return the PR URL to the user.
