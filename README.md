# si-generator

A CLI tool that generates [`security-insights.yml`](https://github.com/ossf/security-insights-spec) files for GitHub repositories by querying the GitHub API.

## Features

- **GitHub API Scanning**: Fetches repository metadata, workflows, maintainers, branch protection, releases, and community health files — all via API, no cloning required
- **Remote Workflow Analysis**: Scans GitHub Actions workflows for security tools (CodeQL, Trivy, GoSec, Snyk, etc.), attestations (Sigstore, SLSA, GoReleaser), and dependency management
- **Org-Aware**: Discovers sibling repositories, governance docs, threat models, code of conduct, and release processes from related repos in the same GitHub org
- **Package Distribution Points**: Detects package names from go.mod, package.json, Cargo.toml, pyproject.toml via API and generates purl distribution point URLs
- **Security Champions**: Extracts security contact emails from SECURITY.md
- **Threat Model Detection**: Finds threat model files in the repo and sibling repos (architecture/design-notes directories)
- **Smart Filtering**: Filters bot accounts, deduplicates entries, caps lists to avoid noise, cleans markdown artifacts from names
- **Validation**: Validates generated YAML against the official CUE schema (fetched at runtime from the OSSF repository)
- **Dry Run**: Preview output before writing to file
- **Web Wizard**: Interactive browser-based UI for reviewing, editing, and validating all fields before generating — with inline field-level validation, sticky error banners, and URL validation

## Installation

```bash
git clone https://github.com/vinayada1/si-tool.git
cd si-tool
make build
```

The binary is placed in `bin/si-gen`.

## Usage

### Generate a security-insights.yml

A GitHub token is required (via `--token` or `GITHUB_TOKEN` env var). Any token works for public repos — no special scopes needed. The token is primarily used to avoid API rate limits. For repositories that use team handles in CODEOWNERS (e.g., `@org/team-name`), a token with `read:org` scope is recommended to resolve team members; without it, the tool falls back to other maintainer sources.

```bash
# Generate from a remote repo
si-gen generate --token $GITHUB_TOKEN --repo-url https://github.com/org/repo

# Preview output without writing
si-gen generate --token $GITHUB_TOKEN --repo-url https://github.com/org/repo --dry-run

# Auto-detect repo URL from git remote in current directory
si-gen generate --token $GITHUB_TOKEN

# Specify output path
si-gen generate --token $GITHUB_TOKEN --repo-url https://github.com/org/repo --output .github/security-insights.yml

# Force overwrite existing file
si-gen generate --token $GITHUB_TOKEN --repo-url https://github.com/org/repo --force

# Verbose output (shows API calls and scanning progress)
si-gen generate --token $GITHUB_TOKEN --repo-url https://github.com/org/repo --verbose

# Override self-assessment (URL or URL,YYYY-MM-DD)
si-gen generate --token $GITHUB_TOKEN --repo-url https://github.com/org/repo \
  --self-assessment https://example.com/assessment.html,2025-06-15

# Override third-party audit
si-gen generate --token $GITHUB_TOKEN --repo-url https://github.com/org/repo \
  --third-party-audit https://example.com/audit-report.pdf,2025-03-01
```

### Interactive Wizard

Launch a web-based wizard that scans the repository, pre-populates all fields, and lets you review and edit in your browser before generating.

```bash
# Launch the wizard
si-gen wizard --token $GITHUB_TOKEN

# Pre-fill with a specific repo
si-gen wizard --token $GITHUB_TOKEN --repo-url https://github.com/org/repo

# Use a custom port
si-gen wizard --token $GITHUB_TOKEN --port 9090
```

### Validate a security-insights.yml

```bash
# Validate default path
si-gen validate

# Validate specific file
si-gen validate --input .github/security-insights.yml

# Use custom schema
si-gen validate --input security-insights.yml --schema custom-schema.cue
```

### Check Version

```bash
si-gen version
```

## CLI Flags

### Generate Command

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--token` | `-t` | GitHub token (or use `GITHUB_TOKEN` env var) | |
| `--repo-url` | `-r` | Repository URL (auto-detected from git remote) | |
| `--output` | `-o` | Output file path | `./security-insights.yml` |
| `--dry-run` | | Print to stdout instead of writing to file | `false` |
| `--force` | `-f` | Overwrite existing file | `false` |
| `--verbose` | `-v` | Enable verbose output | `false` |
| `--self-assessment` | | Self-assessment URL or `URL,YYYY-MM-DD` | |
| `--third-party-audit` | | Third-party audit URL or `URL,YYYY-MM-DD` | |

### Wizard Command

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--token` | `-t` | GitHub token (or use `GITHUB_TOKEN` env var) | |
| `--repo-url` | `-r` | Repository URL (can also be entered in the UI) | |
| `--output` | `-o` | Output file path | `./security-insights.yml` |
| `--verbose` | `-v` | Enable verbose output | `false` |
| `--port` | | Port for the wizard web server | `8899` |

### Validate Command

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--input` | `-i` | Input file to validate | `./security-insights.yml` |
| `--schema` | `-s` | Custom CUE schema file | built-in schema |
| `--verbose` | `-v` | Enable verbose output | `false` |

## What Gets Detected

All data is fetched via the GitHub API — no local filesystem scanning or cloning required.

### Repository Files (via API)

- **Security Policy**: `SECURITY.md`, `.github/SECURITY.md`
- **Code of Conduct**: Community health API + direct file checks
- **License**: SPDX expression from GitHub API
- **Contributing Guide**: Community health API
- **Governance**: `GOVERNANCE.md`, `.github/GOVERNANCE.md`
- **Support Policy**: `SUPPORT.md`, `.github/SUPPORT.md`
- **Roadmap**: `ROADMAP.md`
- **Changelog**: `CHANGELOG.md`, `HISTORY.md`
- **Review Policy**: `REVIEW_POLICY.md`, `PULL_REQUEST_TEMPLATE.md`
- **Dependency Management Policy**: `THIRD-PARTY-NOTICES.txt`, `NOTICE`
- **Maintainers**: `CODEOWNERS`, `MAINTAINERS.md`, `OWNERS.md` (with bot filtering, markdown cleanup, and team handle resolution via GitHub Teams API)

### Workflow Analysis

- **Code Scanning Tools**: CodeQL, Snyk, SonarCloud, Semgrep, Trivy, GoSec, Bandit, Grype, and more
- **Dependency Tools**: Dependabot, Renovate
- **Attestations**: SLSA, Sigstore/Cosign, GoReleaser, SBOM generation (restricted to release/build workflows)
- **Integration detection**: Schedule → adhoc, push/PR → CI, release → release

### Package Manifests (via API)

- **go.mod** → `pkg:golang/...` distribution point
- **package.json** → `pkg:npm/...` distribution point
- **Cargo.toml** → `pkg:cargo/...` distribution point
- **pyproject.toml** → `pkg:pypi/...` distribution point
- Also detects `requirements.txt`, `Pipfile`, `Gemfile`, `pom.xml`, etc. for dependency presence

### Organization Intelligence

- Repository metadata (homepage, description, topics, default branch)
- Branch protection rules and code review requirements
- Top contributors as fallback for core team
- Security contacts extracted from SECURITY.md
- Threat models and self-assessments from security-related directories
- Organization sibling repositories with governance, code of conduct, release process, and threat model scanning
- Release information and distribution points
- Bug bounty programs (known org mapping)

## Example Output

```yaml
# Security Insights Configuration
# Generated by si-generator
# Schema: https://github.com/ossf/security-insights-spec/blob/main/specification.md

header:
    schema-version: 2.0.0
    last-updated: "2026-04-01"
    last-reviewed: "2026-04-01"
    url: https://github.com/example-org/example-project/blob/main/security-insights.yml
    comment: ""
project:
    name: example-project
    homepage: https://example-project.dev
    steward:
        uri: https://github.com/example-org
        comment: 'Organization: example-org'
    documentation:
        detailed-guide: https://example-project.dev
        code-of-conduct: https://github.com/example-org/example-project/blob/main/CODE_OF_CONDUCT.md
        support-policy: https://github.com/example-org/example-project/blob/main/SUPPORT.md
    repositories:
        - name: example-project
          url: https://github.com/example-org/example-project
          comment: The main project repository.
        - name: community
          url: https://github.com/example-org/community
          comment: Governance and community material
        - name: design-notes
          url: https://github.com/example-org/design-notes
          comment: Design documents
    vulnerability-reporting:
        reports-accepted: true
        bug-bounty-available: false
        policy: https://github.com/example-org/example-project/blob/main/SECURITY.md
repository:
    url: https://github.com/example-org/example-project
    status: active
    accepts-change-request: true
    accepts-automated-change-request: false
    core-team:
        - name: Alice Maintainer
          email: alice@example.com
          primary: true
    documentation:
        contributing-guide: https://github.com/example-org/example-project/blob/main/CONTRIBUTING.md
        security-policy: https://github.com/example-org/example-project/blob/main/SECURITY.md
    license:
        url: https://github.com/example-org/example-project/blob/main/LICENSE
        expression: Apache-2.0
    release:
        automated-pipeline: true
        distribution-points:
            - uri: pkg:golang/github.com/example-org/example-project
              comment: go package
            - uri: https://github.com/example-org/example-project/releases
              comment: GitHub Releases
    security:
        assessments:
            self:
                evidence: https://github.com/example-org/design-notes/tree/main/architecture
                comment: Threat model documentation
        champions:
            - name: Security Team
              email: security@example-project.dev
              primary: true
        tools:
            - name: CodeQL
              type: SAST
              rulesets:
                - default
              results: {}
              integration:
                adhoc: false
                ci: true
                release: true
            - name: Trivy
              type: SCA
              rulesets:
                - default
              results: {}
              integration:
                adhoc: false
                ci: true
                release: false
```

## Security Insights Specification

This tool generates files conforming to the [OSSF Security Insights Specification v2.0.0](https://github.com/ossf/security-insights-spec/blob/main/specification.md).

## Known Limitations

- **GitHub token required** — a token (any scope) is needed even for public repos, primarily for API rate limits. `read:org` scope is recommended for resolving CODEOWNERS team handles to individual members
- **`accepts-automated-change-request`** defaults to `false` — must be set manually if the project accepts automated PRs
- **Core team** is capped at 5 entries; org repositories capped at 10
- **Distribution points** limited to go.mod, package.json, Cargo.toml, pyproject.toml plus GitHub Releases; non-GitHub registries (ghcr.io, Docker Hub, etc.) are not detected
- **Security contacts** are only extracted from email patterns in SECURITY.md; mailing lists in prose or SECURITY_CONTACTS files are not parsed
- **Branch protection and MFA** require admin access to the repo; these fields are left empty without admin access
- **Schema version** is hardcoded to 2.0.0
- **Project name** uses the repository name (lowercase); does not infer proper casing

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

## License

Apache-2.0 - see [LICENSE](LICENSE) for details.
