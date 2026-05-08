# Safe PR

Create a pull request, but only after verifying there are no known vulnerabilities in the module graph. If vulnerabilities are found, fix them first, commit the fix, then open the PR.

## Steps

### 1. Check the current branch

Run `git status --short` and `git branch --show-current` to confirm we are NOT on `main`. If we are on `main`, stop and tell the user to switch to a feature branch first.

### 2. Run govulncheck

```bash
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Capture the output. If the exit code is 0 (no vulnerabilities), skip to step 5.

### 3. Fix vulnerabilities

For each vulnerability reported:

- **stdlib vulnerabilities** (package path starts with `crypto/`, `net/`, `os`, `io`, etc.): update the Go toolchain version in `go.mod` by running:
  ```bash
  GOTOOLCHAIN=auto go get go@<fixed-version>
  GOTOOLCHAIN=auto go mod tidy
  ```
  Use the "Fixed in" version from the govulncheck output.

- **Third-party module vulnerabilities**: update the affected module:
  ```bash
  GOTOOLCHAIN=auto go get <module>@<fixed-version>
  GOTOOLCHAIN=auto go mod tidy
  ```

After applying fixes, **re-run govulncheck** to confirm all vulnerabilities are resolved. If any remain, repeat until clean.

### 4. Commit the dependency fixes

Stage only `go.mod` and `go.sum`, then commit with a message in the form:
```
fix(deps): resolve govulncheck vulnerabilities before PR

<brief list of what was fixed, e.g.:
- upgrade Go to 1.26.3 (GO-2026-xxxx)
- upgrade example.com/lib to v1.2.3 (GO-2025-xxxx)>
```

### 5. Run the full test suite

```bash
go test -race -timeout 120s ./internal/...
```

If tests fail, stop and report the failure to the user. Do not raise the PR.

### 6. Create the PR

Gather:
- The current branch name
- `git log main..HEAD --oneline` to summarise commits
- `git diff main...HEAD --stat` to list changed files

Then create the PR with `gh pr create` targeting `main`. Write a clear summary covering:
- What the branch does
- Any vulnerability fixes applied in step 3–4 (if any)
- Test plan (what was run and passed)

End the PR body with:
```
🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

Return the PR URL to the user.
