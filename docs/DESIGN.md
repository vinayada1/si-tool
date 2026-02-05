# si-gen Design Document

## Overview

`si-gen` is a CLI tool that generates `security-insights.yml` files following the [OSSF Security Insights Spec 2.0.0](https://github.com/ossf/security-insights-spec). It automates the discovery of security metadata from repositories.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (Cobra)                         │
│                      cmd/si-gen/main.go                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│  Local Scanner  │     │  GitHub Scanner │
│ scanner/local.go│     │ scanner/github.go│
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     ▼
          ┌─────────────────────┐
          │      Builder        │
          │ generator/builder.go│
          └──────────┬──────────┘
                     ▼
          ┌─────────────────────┐
          │       Writer        │
          │ generator/writer.go │
          └─────────────────────┘
```

## Data Sources

### Local Scanner (`internal/scanner/local.go`)

Scans the local filesystem for security-related files and configurations.

| Data | Source Files |
|------|-------------|
| Security Policy | `SECURITY.md`, `.github/SECURITY.md` |
| Contributing Guide | `CONTRIBUTING.md` |
| Code of Conduct | `CODE_OF_CONDUCT.md` |
| Governance | `GOVERNANCE.md` |
| License | `LICENSE`, `LICENSE.md` |
| Maintainers | `CODEOWNERS`, `MAINTAINERS.md` |
| Security Champions | Email addresses in `SECURITY.md` |
| Security Tools | `.github/workflows/*.yml` (CodeQL, Trivy, GoSec, etc.) |
| Dependency Tools | `.github/dependabot.yml`, `renovate.json` |
| Attestations | SLSA, SBOM, Sigstore in workflows |
| Audits | `audits/` directory, `AUDIT.md` |
| Distribution Points | `package.json`, `go.mod`, `Cargo.toml` |

### GitHub Scanner (`internal/scanner/github.go`)

Fetches data via GitHub API (requires `GITHUB_TOKEN` for full access).

| Data | API Endpoint |
|------|-------------|
| Repository Info | `GET /repos/{owner}/{repo}` |
| Community Health | `GET /repos/{owner}/{repo}/community/profile` |
| License | `GET /repos/{owner}/{repo}/license` |
| Contributors | `GET /repos/{owner}/{repo}/contributors` |
| Releases | `GET /repos/{owner}/{repo}/releases` |
| Branch Protection | `GET /repos/{owner}/{repo}/branches/{branch}/protection` |
| File Contents | `GET /repos/{owner}/{repo}/contents/{path}` |

**Note:** Branch protection and MFA enforcement require admin access.

## Output Structure

```yaml
header:
  schema-version: 2.0.0
  last-updated: "2026-02-04"
  url: https://github.com/org/repo/blob/main/security-insights.yml

project:                    # From GitHub API
  name: repo-name
  homepage: https://...
  vulnerability-reporting:
    reports-accepted: true
    policy: https://...

repository:                 # From Local + GitHub
  url: https://github.com/org/repo
  status: active
  documentation:
    contributing-guide: ...
    security-policy: ...
  release:
    attestations: [...]
    distribution-points: [...]
  security:
    assessments:
      self: {...}
      third-party: [...]
    champions: [...]
    tools: [...]
```

## CLI Flags

### Auto-Detection Overrides
These flags override values that can't be auto-detected or require admin API access:

| Flag | Purpose |
|------|---------|
| `--mfa-enforced` | Set MFA enforcement (requires admin API) |
| `--branch-protection` | Set branch protection (requires admin API) |
| `--code-review` | Set code review requirement |
| `--champion` | Add security champion name |
| `--champion-email` | Add security champion email |
| `--self-assessment` | URL to self-assessment document |
| `--third-party-audit` | URL to third-party audit |
| `--tool-results-url` | Base URL for tool scan results |

### Output Control

| Flag | Purpose |
|------|---------|
| `--dry-run` | Print to stdout instead of file |
| `--show-empty` | Include all fields even if empty |
| `--output, -o` | Output file path |
| `--force` | Overwrite existing file |

## Usage Patterns

### Generate from Local Repo
```bash
cd /path/to/repo
si-gen generate
```

### Generate from Remote Repo
```bash
export GITHUB_TOKEN=...
si-gen generate --repo-url https://github.com/org/repo
```

### Preview with Overrides
```bash
si-gen generate --dry-run \
  --mfa-enforced \
  --branch-protection \
  --champion "Security Team" \
  --champion-email "security@example.com"
```

### Validate Existing File
```bash
si-gen validate --input security-insights.yml
```

## Detection Logic

### Security Tools
Workflows are scanned for tool patterns:
- **SAST**: CodeQL, GoSec, Semgrep, Bandit, SonarQube
- **SCA**: Trivy, Snyk, Dependabot, Grype, npm-audit
- **Supply Chain**: SLSA, Sigstore, Cosign
- **Fuzzing**: OSS-Fuzz, Go fuzz functions

Integration type is determined by workflow triggers:
- `schedule`/`cron` → `adhoc: true`
- `push`/`pull_request` → `ci: true`
- `release` → `release: true`

### Attestations
Detected from workflow patterns:
- `slsa-github-generator` → SLSA Provenance
- `actions/attest-sbom` → SBOM
- `sigstore/cosign-installer` → Sigstore

### Third-Party Audits
Files in `audits/` directory are detected. Known auditor names are recognized:
Trail of Bits, OpenZeppelin, CertiK, Cure53, NCC Group, etc.
