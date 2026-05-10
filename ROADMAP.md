# Argus Roadmap

This document outlines the planned direction for Argus. Items are grouped by phase and theme. Priorities shift based on community feedback — open an issue or start a discussion if something here matters to you.

---

## Phase 1 — Core Hardening *(near-term)*

**Goal:** Make the existing foundation more complete before expanding surface area.

### More ecosystems

- PHP (`composer.lock`) — promote the example plugin to built-in
- Swift / CocoaPods (`Podfile.lock`)
- Dart / Pub (`pubspec.lock`)
- Elixir / Hex (`mix.lock`)
- Python lockfiles — `poetry.lock`, `Pipfile.lock`, `uv.lock`

### More advisory sources

- GitHub Advisory Database (GHSA) — largest curated source, covers all ecosystems
- NVD enrichment — pull CVSS 4.0 vectors where available
- EPSS scores (Exploit Prediction Scoring System) — probability a CVE will be exploited in the wild; pair with CVSS for finer prioritisation (`--fail-on epss:0.5`)

### Transitive dependency visibility

- Parse the full dependency tree from lockfiles, not just direct deps
- Show the chain that introduced a vulnerable package (`requests → urllib3 → CVE-XXX`)
- Flag direct vs transitive in all output formats and SARIF

### `argus fix` command

- For each finding with a known `fixed_in`, emit the exact upgrade command (`go get`, `pip install --upgrade`, `npm install`, etc.)
- `--dry-run` shows what would change without applying it
- Integrates naturally with `--fixes-only` scan mode

---

## Phase 2 — Developer Experience *(medium-term)*

**Goal:** Meet developers where they already work rather than requiring them to context-switch to a separate tool.

### VS Code extension

- Inline severity annotations on `go.mod`, `requirements.txt`, `package.json`, etc.
- Hover card showing advisory summary and fix version
- Command palette: **Argus: Scan workspace**, **Argus: Fix all**
- Backed by `argus scan --output json` — no separate protocol needed

### Pre-commit hook

- `argus scan --profile fast --fixes-only` on staged dependency file changes
- Blocks the commit if any new fixable HIGH/CRITICAL finding is introduced
- Ships as a [pre-commit](https://pre-commit.com) hook config

### Interactive TUI

- `argus scan . --interactive` — navigate findings with arrow keys
- Expand/collapse per-package details, mark findings as accepted/ignored inline
- Writes `.argusignore` entries on keypress

### VEX support (Vulnerability Exploitability eXchange)

- Consume VEX documents from vendors to automatically suppress unexploitable findings
- Produce VEX output alongside CycloneDX/SPDX SBOMs
- `argus vex apply <vex-file>` to update ignore state from a vendor statement

---

## Phase 3 — CI/CD Intelligence *(medium-to-long-term)*

**Goal:** Make Argus the engine for security gates, not just a report generator.

### Auto-fix pull requests

- `argus fix --pr` opens a GitHub/GitLab PR with the minimum set of version bumps to resolve all fixable findings
- PR description includes advisory summaries and CVSS scores
- Configurable: only open PRs for CVSS ≥ N, only for direct deps, etc.

### Policy-as-code

Define enforcement rules in `.argus-policy.yaml` alongside your code:

```yaml
rules:
  - id: block-critical
    match: { severity: CRITICAL }
    action: fail

  - id: warn-transitive-high
    match: { severity: HIGH, depth: ">1" }
    action: warn

  - id: accepted-risk
    match: { id: "CVE-2024-1234" }
    action: suppress
    reason: "mitigated by WAF rule #42"
```

Replaces ad-hoc `--fail-on` flags and `.argusignore` with auditable, reviewable policy files that live in version control.

### PR diff comments

- Post finding summaries as review comments on changed dependency files in a pull request
- Supports GitHub, GitLab, and Bitbucket via their respective APIs
- Only comments on findings introduced by *this* PR (uses baseline diff internally)

### Reachability analysis *(Go first)*

- Use `golang.org/x/tools/go/callgraph` to determine whether a vulnerable function is on a call path from `main`
- Tag findings as `REACHABLE`, `UNREACHABLE`, or `UNKNOWN`
- `--reachable-only` flag suppresses unreachable findings to cut noise dramatically

---

## Phase 4 — Platform & Observability *(longer-term)*

**Goal:** Support teams running Argus across many projects who need shared visibility and centralised governance.

### Server mode

- `argus server --port 8080` — long-running process with a REST API
- Accepts `POST /api/v1/scan` with a tarball or git URL, returns findings as JSON
- Web dashboard becomes multi-project: all scanned repos, trend charts, mean-time-to-remediate metrics
- Authentication via API keys; RBAC for read / write / admin roles

### Notifications

- Slack / Teams webhook: post a summary when a new HIGH/CRITICAL is found
- PagerDuty integration for CRITICAL findings in production services
- Email digest (configurable: immediate, daily, weekly)
- All channels configurable per project in `.argus.yaml`

### Kubernetes operator

- `ArgusPolicy` CRD to define scan frequency and thresholds per namespace
- Operator runs scheduled scans against image SBOMs or mounted source paths
- Writes findings to Kubernetes Events; optionally blocks pod scheduling on policy breach

### SBOM-first scanning

- Accept a CycloneDX or SPDX SBOM as scan input — `argus scan --sbom sbom.cdx.json`
- Useful for scanning already-built artefacts (container images, release archives) without source access

### Compliance reports

- Map findings to common frameworks: PCI-DSS 4.0, HIPAA, SOC 2 Type II, NIST 800-53
- `argus report --framework pci-dss > compliance.pdf`
- Shows which controls are satisfied by the current scan posture and which have open findings

---

## Ongoing / Cross-cutting

| Area | Work |
|---|---|
| **Performance** | Incremental re-embedding — only re-embed advisories modified since last ingest |
| **Performance** | Distributed scan workers for monorepos with hundreds of services |
| **Accuracy** | Per-ecosystem retrieval prompt tuning (Go modules, npm semver, and Maven ranges behave differently) |
| **Accuracy** | User feedback loop — mark false positives to improve similarity thresholds over time |
| **Accuracy** | Full CVSS 4.0 support (environmental and threat metrics, not just base score) |
| **Ecosystem** | Community plugin registry with official submission process |
| **Docs** | Interactive browser playground (WASM build + pre-loaded vulnerability DB) |

---

## Summary

| Phase | Theme | Key deliverables |
|---|---|---|
| 1 | Core hardening | 5 new ecosystems, EPSS scores, transitive deps, `argus fix` |
| 2 | Developer experience | VS Code extension, pre-commit hook, interactive TUI, VEX |
| 3 | CI/CD intelligence | Auto-fix PRs, policy-as-code, PR diff comments, reachability analysis |
| 4 | Platform | Server mode, Kubernetes operator, SBOM-first scanning, compliance reports |

---

## Contributing

The highest-leverage near-term item is **transitive dependency visibility** — it is the most common complaint about existing scanners and improves signal-to-noise without requiring new data sources.

If you want to work on anything listed here, open an issue to discuss the approach before starting. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
