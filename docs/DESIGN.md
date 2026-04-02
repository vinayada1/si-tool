# si-gen Design Document

## Overview

`si-gen` is a CLI tool that generates [`security-insights.yml`](https://github.com/ossf/security-insights-spec) files conforming to the OSSF Security Insights Spec v2.0.0. It works entirely via the GitHub API — no local filesystem scanning or repository cloning is required. A GitHub token is the only prerequisite.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      CLI (cmd/si-gen)                        │
│         Cobra commands: generate, validate, wizard, version  │
└──────┬──────────┬───────────────┬───────────────┬────────────┘
       │          │               │               │
 ┌─────▼─────┐   │         ┌─────▼─────┐  ┌──────▼──────┐
 │  Wizard   │   │         │ Generator │  │  Validator  │
 │  (web UI  │   │         │ (builder  │  │  (CUE       │
 │  server)  │   │         │  + writer)│  │   schema)   │
 └─────┬─────┘   │         └─────┬─────┘  └─────────────┘
       │   ┌─────▼─────┐         │
       │   │  Scanner   │        │
       ├──►│  (github   │        │
       │   │   API)     │        │
       │   └─────┬──────┘        │
       │         │               │
       │         └───────┬───────┘
       │                 │
       │          ┌──────▼──────┐
       └─────────►│  pkg/model  │
                  │  (data      │
                  │   structs)  │
                  └─────────────┘
```

## Package Structure

```
cmd/si-gen/main.go            CLI entrypoint, Cobra commands, flag handling
internal/scanner/types.go     Shared data types (tool info, maintainers, etc.)
internal/scanner/github.go    GitHub API scanning + helpers
internal/generator/builder.go Builds SecurityInsights from GitHubData
internal/generator/writer.go  YAML serialization and file output
internal/validator/cue.go     CUE schema validation (runtime schema fetch)
internal/wizard/server.go     Web wizard HTTP server (scan/preview/generate/validate APIs)
internal/wizard/static.go     Embedded HTML/CSS/JS for the wizard UI
pkg/model/insights.go         Data model (SecurityInsights and all sub-types)
templates/                    YAML template (legacy, unused by current code)
```

### Package Dependency Graph

```
cmd/si-gen/main
  ├── internal/scanner    (GitHubScanner, GitHubData, shared types)
  ├── internal/generator  (Builder, Writer)
  ├── internal/validator  (CUEValidator)
  ├── internal/wizard     (Web wizard server + embedded UI)
  └── pkg/model           (SecurityInsights and all sub-types)

internal/wizard
  ├── internal/scanner    (creates GitHubScanner to scan repos)
  ├── internal/generator  (Writer for YAML preview/generate)
  ├── internal/validator  (CUEValidator for inline validation)
  └── pkg/model           (SecurityInsights for JSON API exchange)

internal/generator
  ├── internal/scanner    (uses GitHubData, shared types)
  └── pkg/model           (produces SecurityInsights)

internal/scanner
  └── (no internal deps; external: go-github, oauth2)

internal/validator
  └── (validates raw YAML bytes against CUE schema)

pkg/model
  └── (no deps, pure data structs with yaml+json tags)
```

## Data Flow

### Generate Command

```
1. CLI parses flags, resolves token + repo URL
       │
2. GitHubScanner.Scan()  ────────────────→  GitHubData
       │  (requires --token)                  (repo metadata, org info,
       │                                       workflows, maintainers,
       │                                       sibling repos, contacts,
       │                                       assessments, tools,
       │                                       package manifests)
       │
3. Builder.BuildInsights(GitHubData)  ───→  SecurityInsights
       │
4. CLI applies override flags to SecurityInsights
       │  (--self-assessment, --third-party-audit)
       │
5. Writer.Write(SecurityInsights)  ──────→  YAML file or stdout
```

### Wizard Command

```
1. CLI creates wizard.Server with token, repo URL, output path
2. Server starts on localhost:8899 (configurable via --port)
3. Browser opens automatically
4. User clicks Scan → Server calls GitHubScanner.Scan() → returns JSON
5. JS populates form fields from scan data
6. User edits fields → inline validation runs on 800ms debounce:
   a. collectForm() → JSON → POST /api/preview → YAML
   b. POST /api/validate → CUE validation → field-level error annotations
   c. Sticky error banner shows clickable links to errored fields
7. User switches to Preview tab → sees YAML output
8. User clicks Generate → confirmation dialog if errors exist
   → POST /api/generate → writes YAML file to disk
```

### Validate Command

```
1. CUEValidator.ValidateFile(path)
2. Read YAML → bytes
3. Compile CUE schema (fetched from OSSF GitHub at runtime, or custom file)
4. Unify schema with data → errors/warnings
5. Print validation result
```

## Packages in Detail

### `cmd/si-gen` — CLI Entrypoint

**File**: `main.go`

Uses [Cobra](https://github.com/spf13/cobra) to define three commands:

| Command | Function | Purpose |
|---------|----------|---------|
| `generate` | `runGenerate()` | Scan + build + write security-insights.yml |
| `validate` | `runValidate()` | Validate YAML against CUE schema |
| `wizard` | `runWizard()` | Launch web-based wizard for interactive editing |
| `version` | inline | Print version info |

The `generate` command orchestrates the full pipeline:
1. Resolves GitHub token (required — `--token` flag or `GITHUB_TOKEN` env var)
2. Resolves repo URL (`--repo-url` flag or auto-detected from git remote)
3. Creates a `GitHubScanner` and scans via API
4. Passes result to `Builder.BuildInsights()`
5. Applies CLI override flags (assessments)
6. Writes output via `Writer`

**CLI Override Flags** — allow users to manually set fields that can't be auto-detected:
- `--self-assessment` — self-assessment URL or `URL,YYYY-MM-DD`
- `--third-party-audit` — third-party audit URL or `URL,YYYY-MM-DD`

The `wizard` command launches an interactive web UI:
1. Creates a `wizard.Server` with the provided token, repo URL, and output path
2. Starts an HTTP server on `localhost:8899` (configurable via `--port`)
3. Auto-opens the browser; the user scans, edits, validates, and generates from the UI

### `internal/scanner` — Data Collection

#### Types (`types.go`)

Shared data structures used by the scanner and generator packages:

| Type | Purpose |
|------|---------|
| `SecurityToolInfo` | Tool name, type, version, rulesets, workflow, integration triggers |
| `AttestationInfo` | Attestation name, predicate URI, location, comment |
| `AssessmentInfo` | Assessment evidence URL, date, comment |
| `MaintainerInfo` | Name, email, GitHub handle, role |
| `DistributionPointInfo` | Package type (npm/go/cargo/pypi), name, purl URL |
| `OrgRepoInfo` | Sibling repo name, URL, description |
| `Contributor` | Login, name, email, contribution count |

#### GitHubScanner (`github.go`)

Fetches all repository data from the GitHub API. Requires a personal access token (any scope works for public repos — the token is primarily needed for rate limits).

**Scan sequence and API calls** (`GitHubData`):

| Step | API / Method | Data |
|------|-------------|------|
| Repo info | `Repositories.Get()` | Name, URL, branch, archived, license, topics, homepage |
| Org info | `Organizations.Get()` | MFA enforcement |
| Org repos | `Repositories.ListByOrg()` | Sibling repo names, URLs, descriptions |
| Sibling scanning | `Repositories.GetContents()` on interesting repos | Governance, code of conduct, release process, threat models |
| Community health | Community health API | Security policy, code of conduct, contributing guide |
| Repo files | `Repositories.GetContents()` | SECURITY.md, GOVERNANCE.md, CHANGELOG.md, ROADMAP.md, SUPPORT.md, etc. |
| Branch protection | `Repositories.GetBranchProtection()` | Protection rules, required reviewers |
| Releases | `Repositories.ListReleases()` | Latest release, automated release detection |
| Workflow contents | `Repositories.ListWorkflows()` + `GetContents()` | Security tools, attestations |
| Contributors | `Repositories.ListContributors()` + `Users.Get()` | Top 10 by commits, with name/email |
| Maintainers | `GetContents()` for CODEOWNERS, MAINTAINERS.md, OWNERS.md + `Teams.ListTeamMembersBySlug()` | Parsed maintainer entries (with team resolution) |
| Security contacts | `GetContents()` for SECURITY.md | Email addresses |
| Assessments | `GetContents()` for threat model directories | Threat model files, audit reports |
| Package manifests | `GetContents()` for go.mod, package.json, Cargo.toml, pyproject.toml | Distribution points + dependency detection |
| Bug bounty | Known org → URL mapping | Bug bounty URLs |

**Sibling repo scanning**: Many OSS projects split governance across multiple repos. The scanner:
1. Lists all repos in the org
2. Filters to "interesting" names (community, governance, design, security, architecture)
3. Checks each for governance files, code of conduct, release process, threat models
4. Release process scanning is restricted to repos named "community", "governance", or "project" to avoid false positives

**Package manifest scanning**: Extracts package names from manifest files to generate purl distribution points:
- `go.mod` → `pkg:golang/...`
- `package.json` → `pkg:npm/...`
- `Cargo.toml` → `pkg:cargo/...`
- `pyproject.toml` → `pkg:pypi/...`
- Also checks for `requirements.txt`, `Pipfile`, `Gemfile`, `pom.xml`, etc. to determine if the project uses third-party dependencies

**Helper functions**:
- `parseCodeownersContent()` — extracts usernames and team slugs from CODEOWNERS global `*` lines; returns both individual users and team references separately
- `resolveTeamMembers()` — resolves `@org/team` references to individual members via the GitHub Teams API (`read:org` scope); stops after the first team that returns results; fails gracefully on permission errors
- `parseMaintainersContent()` — extracts names/emails/handles from MAINTAINERS/OWNERS files with dedup
- `cleanMaintainerName()` — strips markdown artifacts: pipes, bullets, backtick prefixes, link syntax `[text](url)`, parenthetical handles `(username)`
- `IsBotAccount()` — filters known bot/CI accounts (dependabot, renovate, k8s-ci-robot, prow, mergify, etc.)

### `internal/wizard` — Web Wizard

#### Server (`server.go`)

HTTP server that exposes a browser-based UI for interactive security-insights generation.

**Endpoints**:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Serves embedded HTML UI (with `{{REPO_URL}}` and `{{OUTPUT_PATH}}` templated in) |
| `/api/scan` | POST | Accepts `{url, token}`, creates a GitHubScanner, returns scan data as JSON |
| `/api/preview` | POST | Accepts SecurityInsights JSON, returns rendered YAML |
| `/api/generate` | POST | Accepts SecurityInsights JSON + `outputPath`, writes YAML to disk |
| `/api/validate` | POST | Accepts `{yaml}`, runs CUE validation, returns errors and warnings |

The server auto-opens the browser on startup and shuts down gracefully on interrupt.

#### Static UI (`static.go`)

Full HTML/CSS/JS embedded as a Go string constant (`indexHTML`). Dark GitHub-style theme.

**UI features**:
- **Scan bar**: Enter repo URL and scan via API
- **Editor tab**: Form fields for all Security Insights spec sections; auto-populated from scan data
- **Preview tab**: Live YAML preview; Generate button writes file to disk
- **Inline validation**: Runs on 800ms debounce after field changes; annotates individual fields and sections with errors/warnings
- **Sticky error banner**: Pinned at top (visible across tabs) with clickable links that scroll to errored fields
- **Client-side URL validation**: Validates all URL fields against `^https?://[^\s]+$` pattern
- **Primary constraint check**: Warns when multiple persons are marked as primary in a section
- **Confirmation dialog**: Warns before generating if validation errors exist, allows proceeding anyway
- **Status dropdown**: All 8 CUE-valid values (active, inactive, abandoned, concept, moved, suspended, unsupported, WIP)

### `internal/generator` — Data Assembly

#### Builder (`builder.go`)

Transforms `GitHubData` into the final `SecurityInsights` model.

**Builder methods**:

| Method | Sections Built |
|--------|---------------|
| `buildProject()` | name, homepage, steward, administrators, documentation, org repos (capped at 10), vulnerability reporting |
| `buildRepository()` | URL, status, change-request policies, core-team (capped at 5), documentation, license, release, security |
| `buildSecurity()` | practices, assessments, champions, tools |
| `buildProjectDocumentation()` | detailed-guide, code-of-conduct, release-process, support-policy |
| `buildRepositoryDocumentation()` | contributing-guide, review-policy, security-policy, governance, dependency-management-policy |
| `buildRelease()` | changelog, automated-pipeline, attestations, distribution-points |
| `buildLicense()` | URL, SPDX expression |
| `buildVulnerabilityReporting()` | reports-accepted, bug-bounty, policy, contact |

**Data source priority** (for fields with multiple potential sources):

| Section | Priority | Notes |
|---------|----------|-------|
| Code of conduct | Main repo → sibling repo | Prefers org-level CoC |
| Governance | Main repo → sibling repo | |
| Release process | Sibling repo (community/governance only) | |
| Core team | CODEOWNERS (users + resolved teams)/MAINTAINERS → top contributors | Capped at 5, bots filtered |
| Assessments | Main repo → sibling threat models | Includes individual file URLs |

#### Writer (`writer.go`)

Serializes the `SecurityInsights` model to YAML.

- Uses `gopkg.in/yaml.v3` for marshaling
- Adds a header comment with generator attribution and spec link
- `--show-empty` mode: initializes all nil nested structs so every field appears
- `--dry-run`: writes to stdout instead of file
- Checks for existing file and requires `--force` to overwrite

### `internal/validator` — Schema Validation

#### CUEValidator (`cue.go`)

Validates `security-insights.yml` files against the OSSF Security Insights CUE schema.

The default schema is fetched at runtime from `https://raw.githubusercontent.com/ossf/security-insights/main/spec/schema.cue` and cached in memory via `sync.Once` for the lifetime of the process. Users can override with a local schema file via `--schema`.

1. Fetches or loads CUE schema (runtime fetch from OSSF GitHub, or user-provided file)
2. Reads and parses YAML content
3. Unifies the schema definition (`#SecurityInsights`) with the data
4. Collects errors and generates warnings for recommended-but-missing fields
5. Fallback: invokes the `cue` CLI tool if the Go library fails

### `pkg/model` — Data Model

#### SecurityInsights (`insights.go`)

Pure data structures with dual `yaml` and `json` struct tags. The `yaml` tags are used for YAML file serialization, and the `json` tags (matching the same field names) are used for the wizard's JSON API communication. No business logic.

```
SecurityInsights
├── Header
│   ├── SchemaVersion, LastUpdated, LastReviewed
│   ├── URL, ProjectSISource, Comment
├── Project
│   ├── Name, Homepage, Funding, Roadmap
│   ├── Steward {URI, Comment}
│   ├── Administrators []Person
│   ├── Documentation {DetailedGuide, CodeOfConduct, ReleaseProcess, SupportPolicy}
│   ├── Repositories []RepositoryRef {Name, URL, Comment}
│   └── VulnerabilityReporting {ReportsAccepted, BugBountyAvailable, Policy, Contact}
└── Repository
    ├── URL, Status, BugFixesOnly
    ├── AcceptsChangeRequest, AcceptsAutomatedChangeRequest
    ├── NoThirdPartyPackages
    ├── CoreTeam []Person {Name, Email, Affiliation, Social, Primary}
    ├── Documentation {ContributingGuide, ReviewPolicy, SecurityPolicy, Governance, DependencyManagementPolicy}
    ├── License {URL, Expression}
    ├── Release {Changelog, AutomatedPipeline, Attestations, DistributionPoints}
    └── Security
        ├── Practices {MFA, BranchProtection, CodeReview}
        ├── Assessments {Self, ThirdParty}
        ├── Champions []Person
        └── Tools []SecurityTool {Name, Type, Version, Rulesets, Results, Integration, Comment}
```

## Detection Logic

### Security Tools

Workflow files are fetched via API and scanned for tool name patterns:

| Category | Tools Detected |
|----------|---------------|
| SAST | CodeQL, GoSec, Semgrep, Bandit, SonarQube/SonarCloud, SpotBugs, ESLint Security |
| SCA | Trivy, Snyk, Dependabot, Renovate, Grype, npm-audit, OWASP Dependency-Check |
| Supply Chain | SLSA, Sigstore, Cosign |
| Fuzzing | OSS-Fuzz, ClusterFuzzLite |
| Other | OpenSSF Scorecard, Dependency Review |

**Version extraction**: Versions are extracted from GitHub Action refs (e.g., `@v4.34.1`) using a regex that prefers version comments (`# v4.34.1`) over action SHA-pinned refs.

**Integration detection**: Workflow triggers determine integration type:
- `schedule`/`cron` → `adhoc: true`
- `push`/`pull_request` → `ci: true`
- `release` → `release: true`

### Attestations

Detected from workflow patterns, **restricted to release/build/publish workflows only**:
- `slsa-github-generator` / `slsa-framework` → SLSA Provenance
- `actions/attest-sbom` / `anchore/sbom-action` → SBOM
- `sigstore/cosign-installer` → Sigstore Signature
- `goreleaser/goreleaser-action` → GoReleaser

### Maintainer Parsing

**CODEOWNERS**: Only processes global ownership lines (starting with `*`). Per-directory entries create excessive noise (e.g., Envoy has 100+ entries). Team references (`@org/team-name`) are resolved to individual members via the GitHub Teams API when the token has `read:org` scope. If the token lacks this scope, team resolution fails gracefully and continues. Only the first team with resolvable members is expanded (to prefer maintainer teams over less relevant teams like on-call).

**MAINTAINERS.md / OWNERS.md**: Extracts names, emails, and GitHub usernames. Handles varied formats:
- Markdown tables (`| Name | Email | GitHub |`)
- Bullet lists (`* Name <email> (@handle)`)
- Plain text with `github.com/` links

**Cleanup**: `cleanMaintainerName()` removes markdown artifacts (pipes, bullets, backtick prefixes, link syntax, parenthetical handles). Entries where the GitHub username matches the org name (URL parsing artifacts) are filtered.

**Bot filtering**: `IsBotAccount()` checks against patterns: dependabot, renovate, k8s-ci-robot, prow, mergify, codecov, stale, greenkeeper, snyk-bot, allstar, github-actions.

### Third-Party Audits

Files in `audits/` directories are detected. Known auditor names are recognized: Trail of Bits, OpenZeppelin, CertiK, Cure53, NCC Group, etc.

## Key Design Decisions

### API-Only Architecture

The tool uses the GitHub API exclusively — no local filesystem scanning or repository cloning. This simplifies the architecture and eliminates a class of bugs where the local scanner would read the wrong directory (e.g., the si-tool repo itself) when targeting a remote repository.

A GitHub token is required even for public repos. Any token works (no special scopes needed) — the primary purpose is to raise the API rate limit from 60 req/hr (unauthenticated) to 5,000 req/hr (authenticated). The `read:org` scope is recommended for resolving CODEOWNERS team handles to individual members. Branch protection and MFA detection require admin access but fail gracefully when unavailable.

### Sibling Repository Awareness

Many CNCF/OSS projects split governance, design, and community files across multiple repos in the same org. The scanner identifies "interesting" sibling repos by name/description and scans them for:
- Governance files → used as governance URL fallback
- Code of conduct → used as project-level CoC
- Release process → only from community/governance/project repos (avoids false positives)
- Threat models → individual file URLs listed in assessment comments

### Attestation Workflow Filtering

Attestation patterns (SLSA, Sigstore, etc.) are only matched in workflows whose filename contains "release", "publish", "build", "deploy", "ci", or "cd". This prevents false positives from utility workflows that reference these tools incidentally.

### Caps and Limits

To keep output manageable for large organizations:
- **Core team**: 5 members max
- **Org repositories**: 10 max
- **Top contributors fallback**: 5 max

### Conservative Defaults

`accepts-automated-change-request` defaults to `false` even when Dependabot/Renovate are detected. Having the tool enabled doesn't imply the project accepts automated PRs as policy — this is a human decision.

## Extending the Tool

### Adding a New Security Tool Detection

1. Add the tool pattern to `toolPatterns` in `scanWorkflowContents()` (github.go)
2. Each entry maps a pattern string to `SecurityToolInfo` with name, type, and optional rulesets
3. Version extraction happens automatically from action ref tags

### Adding a New File Detection

1. Add file path(s) to check in `scanRepositoryFiles()` (github.go)
2. Add a corresponding field to `GitHubData`
3. Wire it into the appropriate `build*()` method in builder.go

### Adding a New Sibling Repo Scan

1. Add file paths to check in `scanSiblingRepos()` (github.go)
2. Add a `Sibling*URL` field to `GitHubData`
3. Use it as a fallback in the appropriate builder method
