# Argus CI/CD Templates

Drop-in pipeline templates for integrating Argus into your CI/CD system. Each template:

1. Pulls the `ghcr.io/abhishekamralkar/argus` Docker image (or installs the binary)
2. Runs `argus ingest` with DB caching
3. Runs `argus scan --output sarif`
4. Uploads the SARIF report to the platform's security dashboard
5. Fails the pipeline when findings meet the configured severity threshold

## Quick-start by platform

| Platform | Template | Security dashboard |
|---|---|---|
| GitHub Actions | [`action.yml`](../action.yml) | GitHub Security tab |
| GitLab CI | [`gitlab-ci.yml`](gitlab-ci.yml) | GitLab Security Dashboard |
| Azure DevOps | [`azure-pipelines.yml`](azure-pipelines.yml) | Advanced Security tab |
| Jenkins | [`Jenkinsfile`](Jenkinsfile) | Warning NG plugin |
| CircleCI | [`circleci-config.yml`](circleci-config.yml) | Artifacts |
| AWS CodeBuild | [`buildspec.yml`](buildspec.yml) | S3 Artifacts |
| GCP Cloud Build | [`cloudbuild.yaml`](cloudbuild.yaml) | GCS Artifacts |

---

## GitLab CI (`gitlab-ci.yml`)

Include in `.gitlab-ci.yml`:

```yaml
include:
  - local: ci-templates/gitlab-ci.yml
```

Or copy the `argus-scan` job directly. The SARIF file is uploaded as a GitLab
SAST artifact, which appears in the **Security** tab of merge requests and
pipelines.

**Key variables** (set in *Settings > CI/CD > Variables*):

| Variable | Default | Description |
|---|---|---|
| `ARGUS_ECOSYSTEMS` | `go,python,rust,npm` | Ecosystems to ingest |
| `ARGUS_FAIL_ON` | `HIGH` | Severity threshold for pipeline failure |
| `ARGUS_MIN_SEVERITY` | *(unset)* | Minimum severity to include in report |
| `OPENAI_API_KEY` | *(unset)* | Set when using an OpenAI-compatible LLM |

---

## Azure DevOps (`azure-pipelines.yml`)

Reference from an existing pipeline:

```yaml
steps:
  - template: ci-templates/azure-pipelines.yml
```

Or use it as a standalone pipeline. The SARIF artifact is published to the
pipeline run's artifact feed as `CodeAnalysisLogs`, which the **Advanced
Security** tab (if enabled) picks up automatically.

**Key variables** (set in *Library > Variable Groups* or the pipeline editor):

| Variable | Default | Description |
|---|---|---|
| `argusEcosystems` | `go,python,rust,npm` | Ecosystems to ingest |
| `argusFailOn` | `HIGH` | Severity threshold |
| `argusMinSeverity` | *(unset)* | Minimum severity |
| `OPENAI_API_KEY` | *(unset)* | OpenAI-compatible key |

---

## Jenkins (`Jenkinsfile`)

1. Create a **Pipeline** job in Jenkins.
2. Set *Definition* to **Pipeline script from SCM** and point it to this `Jenkinsfile`.
3. Add `OPENAI_API_KEY` as a **Secret text** credential (ID: `OPENAI_API_KEY`).

The pipeline uses the Argus Docker image via the `docker` agent. The
[Warning Next Generation plugin](https://plugins.jenkins.io/warnings-ng/) can
display the SARIF report inline — uncomment the `recordIssues` line.

**Key environment variables** (configure in the `environment` block):

| Variable | Default | Description |
|---|---|---|
| `ARGUS_ECOSYSTEMS` | `go,python,rust,npm` | Ecosystems to ingest |
| `ARGUS_FAIL_ON` | `HIGH` | Severity threshold |
| `ARGUS_MIN_SEVERITY` | *(empty)* | Minimum severity |

---

## CircleCI (`circleci-config.yml`)

Copy to `.circleci/config.yml` or add the `argus-scan` job and `security-scan`
workflow to your existing config.

Set environment variables in **Project Settings > Environment Variables**:

| Variable | Default | Description |
|---|---|---|
| `ARGUS_ECOSYSTEMS` | `go,python,rust,npm` | Ecosystems to ingest |
| `ARGUS_FAIL_ON` | `HIGH` | Severity threshold |
| `ARGUS_MIN_SEVERITY` | *(empty)* | Minimum severity |
| `OPENAI_API_KEY` | *(unset)* | OpenAI-compatible key |

The vuln DB is cached using CircleCI's `save_cache` / `restore_cache` steps,
keyed on your lock files (`go.sum`, `requirements.txt`). The SARIF report is
stored as a build artifact.

---

## AWS CodeBuild (`buildspec.yml`)

Reference in your CodeBuild project under *Buildspec > Use a buildspec file*,
or paste directly into the inline editor.

Store your `OPENAI_API_KEY` in AWS Secrets Manager and reference it in the
`secrets-manager` block (uncomment and update the ARN).

Enable **S3 caching** in your CodeBuild project for the `/tmp/.argus/` path so
the vuln database persists between builds.

| Variable | Default | Description |
|---|---|---|
| `ARGUS_ECOSYSTEMS` | `go,python,rust,npm` | Ecosystems to ingest |
| `ARGUS_FAIL_ON` | `HIGH` | Severity threshold |
| `ARGUS_MIN_SEVERITY` | *(empty)* | Minimum severity |

---

## GCP Cloud Build (`cloudbuild.yaml`)

Submit manually:

```bash
gcloud builds submit --config ci-templates/cloudbuild.yaml .
```

Or connect Cloud Build to your repository and point the trigger at this file.

Store `openai-api-key` in Secret Manager and grant the Cloud Build service
account `secretmanager.secretAccessor`. Cross-build DB caching requires a GCS
bucket — uncomment the `gsutil cp` steps and replace `YOUR_BUCKET`.

| Substitution | Default | Description |
|---|---|---|
| `_ARGUS_ECOSYSTEMS` | `go,python,rust,npm` | Ecosystems to ingest |
| `_ARGUS_FAIL_ON` | `HIGH` | Severity threshold |
| `_ARGUS_MIN_SEVERITY` | *(empty)* | Minimum severity |

---

## Common configuration

All templates support the same core flags via environment variables or
substitutions. CLI flags always override profile values — see
`argus scan --help` for the full list.

```yaml
# Example .argus.yaml in your project root for shared defaults:
default_profile: ci
profiles:
  ci:
    workers: 4
    top_k: 10
    min_similarity: 0.55
    fail_on: HIGH
    output: sarif
```

With `default_profile: ci` set, every `argus scan` command in your pipeline
automatically picks up the CI profile without extra flags.
