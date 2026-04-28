# AI-Assisted `security-insights.yml` Generation (IDE)

## What This File Is

This file contains a ready-to-use prompt for an AI coding assistant. You paste the prompt into an AI assistant inside your IDE (for example, GitHub Copilot in agent mode in VS Code, Cursor, or a similar tool) and the AI generates Security Insights YAML files for a GitHub repository on your behalf.

Given a repository, the AI assistant uses its tools to read that repository's GitHub metadata, documentation, and workflow files, and writes generated YAML files into a folder in your workspace. The output is intended to conform to the [OSSF Security Insights Specification v2.0.0](https://github.com/ossf/security-insights).

If you are using a browser-based AI chat instead of an IDE assistant (for example, ChatGPT or Claude in a browser), use [LLM_PROMPT_BROWSER.md](LLM_PROMPT_BROWSER.md) instead.

## Before You Start

You will need:

- An IDE or editor with agent-style chat whose assistant can read GitHub repositories and create files in your workspace.
- Authenticated GitHub access in that environment. Without it, repository discovery, project-inventory lookup, and workflow inspection may be incomplete or rate-limited, and you should expect the run to say so explicitly.

Then prepare the prompt:

1. Start a fresh assistant chat in agent mode.
2. Copy the full prompt from the [Prompt Template](#prompt-template) section below.
3. At the top of the pasted prompt edit the parameter block:
   - Under `Required`, replace each `<...>` with your value. The assistant will refuse to run if any `<...>` placeholder is left unfilled.
   - Under `Optional`, the value `default` (or `auto-detect` / `auto-discover`) means "use the documented default". To override one, replace that keyword with your value. For the repository list, replace `auto-discover` with a YAML list of slugs, one per line, indented two spaces with a leading `-` (an example is shown directly below the line).
4. Send the prepared prompt as the first message in the new chat.

Leaving the optional fields alone is fine. The assistant will detect the default branch from the repository, use the documented project-level defaults, and discover the repository inventory from authoritative project evidence when possible.

## Prompt Template

```text
Required:
  REPOSITORY_SLUG: <your-project>/<your-repo>
  OUTPUT_FOLDER:   <your-output-folder>

Optional:
  DEFAULT_BRANCH:                auto-detect
  PROJECT_LEVEL_REPO_SLUG:       default
  PROJECT_LEVEL_FILE_PATH:       default
  PROJECT_LEVEL_BRANCH:          default
  VERIFIED_PROJECT_REPOSITORIES: auto-discover
    # Example override:
    # - <your-project>/<your-repo>
    # - <your-project>/<another-repo>

Before doing anything else, validate the parameter block above:
- If any Required value still contains an angle-bracket placeholder (for example, `<your-project>/<your-repo>` or any string of the form `<...>`), stop immediately. Do not attempt generation. Reply with a short message that lists which Required parameters are missing and ask the user to fill them in. Do not invent or guess values.
- Treat Optional values that still contain angle-bracket placeholders the same way: list them and ask the user to either fill them in or replace the placeholder with the documented default keyword (`default`, `auto-detect`, or `auto-discover`).

Resolve each Optional value as follows:
- The literal value `default` means: use the documented schema default for that field.
- For `DEFAULT_BRANCH`, the literal value `auto-detect` means: read the repository's actual default branch from its GitHub metadata. Use that detected branch when constructing `header.url` and any raw file URLs. Do not assume `main`.
- For `VERIFIED_PROJECT_REPOSITORIES`, the literal value `auto-discover` means: discover the inventory from the project-level Security Insights file, the org-level `.github` repository, project governance docs, or other authoritative project evidence.
- Default for `PROJECT_LEVEL_REPO_SLUG`  = `<owner>/.github` where `<owner>` is derived from `REPOSITORY_SLUG`.
- Default for `PROJECT_LEVEL_FILE_PATH`  = `.github/security-insights.yml`.
- Default for `PROJECT_LEVEL_BRANCH`     = `main`.

You are acting like a security-insights generator for a GitHub repository in an agent-capable IDE environment.

Task:
Inspect the repository `REPOSITORY_SLUG`, determine the project repository inventory, and generate Security Insights files that conform to the OSSF Security Insights Specification v2.0.0.

If this environment supports authenticated GitHub access, use it. If authenticated GitHub access is unavailable, say so explicitly before attempting generation and treat the results as potentially incomplete.

If `VERIFIED_PROJECT_REPOSITORIES` is provided, treat it as the authoritative repository inventory. Inspect each listed repository directly and generate one repository-scoped file for each of them. Do not rediscover, shrink, or skip that list unless the user explicitly asks you to.

If `VERIFIED_PROJECT_REPOSITORIES` is not provided, look for an authoritative repository list from an existing project-level Security Insights file, org-level `.github` repository, project governance repository, or clearly documented project inventory source.

If `PROJECT_LEVEL_REPO_SLUG`, `PROJECT_LEVEL_FILE_PATH`, or `PROJECT_LEVEL_BRANCH` are omitted, first try these defaults before giving up on project-level discovery:
- derive the repo owner from `REPOSITORY_SLUG` and try the owner-scoped `.github` repository, for example `<org-or-user>/.github`
- try `.github/security-insights.yml`
- try `main`, then the project-level repository's default branch if it can be discovered

If you find a verified project repository inventory, inspect each repository in that verified inventory one by one and generate one repository-scoped file for each of them. Do not stop after generating only the file for `REPOSITORY_SLUG` when additional verified repositories were found.

Write the generated files directly under `OUTPUT_FOLDER` so the user can edit them later.
Generate:
- one project-level file at `OUTPUT_FOLDER/project-security-insights.yml`
- one repository-scoped file per verified repository at `OUTPUT_FOLDER/repos/<owner>_<repo>.yml`

If you cannot create files in this environment, say so explicitly and then return the full YAML for each intended output path.

The generated files must be validated against the latest official Security Insights CUE schema before you report success when that validation is available in the environment.

How to work:
- First inspect the seed repository itself, its GitHub metadata, and its workflow files.
- Look for repository documentation such as SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md, GOVERNANCE.md, SUPPORT.md, ROADMAP.md, CHANGELOG.md, CODEOWNERS, and release-related files.
- Also inspect security-focused documentation pages and concept docs that may describe audits, reviews, threat models, or assessment history even when those details are not stored in dedicated audit files.
- Inspect GitHub Actions workflows to detect security tools, dependency tooling, attestations, and release automation.
- If you are using a discovered repository inventory, enumerate that list explicitly before generating output, then inspect each listed repository directly rather than inferring its contents from the seed repository.
- Use repository evidence first.
- You may use clearly related org-level sibling repositories for shared governance, code of conduct, release process, or threat model material, but prefer the main repo when both exist.
- Use only deterministic, evidence-backed facts.
- Do not guess, infer from weak signals, or fill fields with likely-but-unverified values.
- If multiple interpretations are possible and accessible evidence does not resolve them, omit the field instead of choosing one.
- Do not invent people, URLs, tools, dates, policies, assessments, or release processes.
- If evidence is missing, omit the optional field.
- If you cannot verify a value from accessible evidence, leave it out.
- If you cannot verify a multi-repo inventory and no verified repository list was supplied, generate only the repository-scoped file for `REPOSITORY_SLUG` and do not invent sibling repositories.
- Treat boolean negatives and priority markers conservatively. Only emit values such as `bug-bounty-available: false`, `accepts-automated-change-request: false`, `no-third-party-packages: true`, or `primary: true` when direct evidence supports that exact assertion; otherwise omit the field.

Required defaults and fallback rules:
- Output only YAML. No code fences.
- `header.schema-version` must be `2.0.0`.
- `header.last-updated` and `header.last-reviewed` should use today’s date.
- For repository-scoped files, `header.url` should be `https://github.com/<owner>/<repo>/blob/<default_branch>/security-insights.yml` using the repository's actual default branch (auto-detected from GitHub metadata when `DEFAULT_BRANCH` is `auto-detect`).
- For repository-scoped files, set `header.project-si-source` only when the published location of the project-level file can be derived from the provided project-level fields, from the default guesses above, or verified from accessible project evidence.
- For the project-level file, set `header.url` only when the published project-file URL can be derived from the provided project-level fields, from the default guesses above, or verified from accessible evidence. Do not invent a published URL.
- Repository status is `inactive` if the repo is archived, otherwise `active`.
- `accepts-change-request` is true unless the repository is archived.
- `accepts-automated-change-request` defaults to false unless explicit evidence says otherwise.
- `no-third-party-packages` is true only if there is evidence the repository has no third-party dependencies.
- The project-level file may contain `project.repositories`.
- Repository-scoped files must not contain `project.repositories`.
- When a verified multi-repo inventory exists, the output is incomplete unless there is one repository-scoped file for every repository in that verified inventory.
- If `project.vulnerability-reporting` is present because a security policy exists, include `bug-bounty-available: false` when no bug bounty program is verified.
- Before omitting project-level fields such as `funding`, `steward`, `bug-bounty-program`, `pgp-key`, `in-scope`, or `out-of-scope`, check repository docs, security docs, funding files, GitHub funding metadata, GitHub Sponsors pages, project websites, foundation or governance pages, and any explicitly linked bug bounty or disclosure pages.
- For `funding`, inspect GitHub Sponsors, funding metadata, FUNDING files, project websites, and foundation donation or sponsorship pages.
- For `steward`, inspect project governance docs, foundation affiliation pages, project websites, and community pages for explicit statements about the governing organization or foundation.
- For `in-scope` and `out-of-scope`, inspect the security reporting or disclosure policy page and preserve explicit scope statements when they are published there.
- For `bug-bounty-program`, inspect security policy pages, disclosure pages, HackerOne or Bugcrowd links, and project websites for explicit bounty program references.
- For `pgp-key`, inspect security reporting pages, SECURITY.md, disclosure instructions, and linked key material pages for an explicitly published PGP key.
- Detect `dependency-management-policy` conservatively. Check `DEPENDENCY_POLICY.md`, `.github/DEPENDENCY_POLICY.md`, `docs/DEPENDENCY_POLICY.md`, `docs/dependency-management.md`, `docs/dependencies.md`, `THIRD-PARTY-NOTICES.txt`, `THIRD-PARTY-NOTICES.md`, `NOTICE`, `NOTICE.txt`, and `NOTICE.md`.
- Before omitting repository-level fields such as `review-policy`, `changelog`, `champions`, `attestations`, or additional security tools, check related documentation, release pages, workflow files, PR templates, and security contact pages for direct evidence.
- For `review-policy`, also inspect CONTRIBUTING docs, PR templates, reviewer guidance, and governance docs when they explicitly describe review requirements.
- For `changelog`, also inspect release pages or release-process documentation when they explicitly point to release notes or a changelog location.
- For `changelog`, inspect GitHub Releases, release notes directories, release-process docs, and repository docs that explicitly point to release notes or changelog locations.
- For `champions`, inspect SECURITY.md, named security team pages, and clearly identified security contacts; do not infer champions from general maintainers unless the source explicitly identifies them as security contacts or champions.
- For `champions`, also inspect security reporting pages, linked maintainers or security team pages, and explicit security contact addresses before omitting the field.
- For `no-third-party-packages`, inspect dependency manifests, lockfiles, dependency policy docs, and release metadata. Set it to true only when direct evidence shows the repository has no third-party dependencies; otherwise omit it rather than guessing.
- For `review-policy`, prefer explicit PR workflow requirements such as required tests, maintainer review, approval rules, or merge prerequisites over generic contribution guidance.
- For `dependency-management-policy`, distinguish between a documented policy versus general evidence of dependency usage or updates. Only include the field when a repository or project source explicitly describes how dependencies are selected, reviewed, updated, approved, or governed.
- For `attestations`, require direct evidence of artifact attestations, provenance, signing artifacts, or published attestation workflows. Do not treat generic signed commits, DCO sign-off, or unrelated runtime signing features as release attestations.
- For CODEOWNERS-based maintainer extraction, only inspect these paths: `.github/CODEOWNERS`, `CODEOWNERS`, and `docs/CODEOWNERS`.
- From CODEOWNERS, only use global ownership lines that start with `*`. Ignore path-specific ownership lines.
- From those global CODEOWNERS lines, extract individual GitHub users written as `@user` and team references written as `@org/team`.
- Ignore `@UNOWNED`, bot accounts, and entries whose GitHub username matches the repository owner org.
- If CODEOWNERS contains team references and the repo owner is an org, resolve team members when possible. If multiple teams are listed, use only the first team that successfully resolves to members.
- Deduplicate maintainers gathered from CODEOWNERS before using them for `project.administrators` and `repository.core-team`.
- Do not add administrators from generic org pages, issue history, commit history summaries, or unverifiable profile associations.
- Do not infer affiliations unless a maintainer source explicitly provides them.
- Do not mirror the same long maintainer roster into both `project.administrators` and `repository.core-team` by default.
- Use `project.administrators` for the broader evidence-backed administrative or maintainer set when available, and use `repository.core-team` for a smaller operational subset only when the source supports that narrower group.
- If the evidence only supports one shared maintainer set, prefer keeping `repository.core-team` shorter rather than duplicating a large administrator roster into both sections.
- Cap `repository.core-team` at 5 entries.
- Use exact Security Insights schema field names. Do not invent alternative keys or near-miss spellings.
- For release metadata, the valid key is `changelog`. Never output `changangelog`.
- For security tools, use `rulesets: [default]` when rulesets are unknown.
- For each security tool include `results: {}` and an `integration` block.
- Set `integration.adhoc: true` when a workflow uses `schedule`, `cron`, or `workflow_dispatch`.
- Set `integration.ci: true` when a workflow uses `push` or `pull_request`.
- Set `integration.release: true` when the workflow is release-triggered or clearly a release workflow.
- Extract tool versions from pinned action references or inline version markers when present.
- Detect dependency tools separately from code scanning tools.
- If `.github/dependabot.yml` or `.github/dependabot.yaml` exists, include a tool entry for `Dependabot` with `type: SCA`, `rulesets: [default]`, `results: {}`, and `integration` set to `adhoc: false`, `ci: true`, `release: false`.
- Always include `repository.security.assessments.self`.
- For security assessments, inspect SECURITY.md, security concept pages, architecture or threat model docs, governance or security overview pages, and other narrative documentation for explicit statements about self-assessments, threat models, reviews, or third-party audits.
- If a documentation page explicitly mentions a third-party audit, security review, penetration test, or similar external assessment, treat that as valid evidence for `repository.security.assessments.third-party` and use the documentation URL as the evidence link when no better report URL is available.
- If a documentation page explicitly mentions a threat model, self-assessment, or internal security review, treat that as valid evidence for `repository.security.assessments.self`.
- When narrative documentation includes an assessment month or year, preserve that date detail. Normalize it into the assessment `date` field only when you can do so deterministically; otherwise preserve the timing in the assessment `comment` instead of dropping it.
- If no self-assessment evidence is found, use:
  `comment: Self assessment has not yet been completed.`
- If no third-party audit is found but a self-assessment exists, include one third-party entry with:
  `comment: No third-party assessment performed`
- If a security contact is discovered only as an email address in `SECURITY.md`, it is valid to emit a champion with an empty name and that email address.

Output requirements:
- Create the files at the intended output paths when file writing is available.
- Use 4-space indentation.
- Do not emit null values.
- Do not emit empty arrays or empty objects, except `results: {}` for tools.
- After writing the files, report the final output paths.
- When a verified multi-repo inventory exists, report the complete list of generated repository-scoped output paths and ensure the count matches the verified inventory.
- Before schema validation, first parse-check each generated YAML file and repair any indentation, nesting, quoting, or sequence formatting problems.
- Validate the generated YAML against the latest official Security Insights CUE schema before reporting success when that validation is available.
- If parsing fails, fix the YAML and parse-check again before attempting schema validation.
- If validation fails, fix the YAML and validate again when possible.
- If validation still fails, do not claim success. Report the validation errors clearly.
- If the environment cannot access or run the latest CUE schema validation, say so explicitly.

Before finalizing, self-check:
- Remove fields that are unsupported by accessible evidence.
- Ensure YAML keys use the security-insights schema naming style.
- Ensure exact field names are used for the 2.0.0 schema with no misspellings.
- Ensure dates and URLs are preserved exactly.
- Ensure repository-scoped files do not contain `project.repositories`.
- Ensure repository-scoped files use `header.project-si-source` only when a verified or derivable project-level file location is available, including the documented default guesses.
- Ensure that when a verified project repository inventory was found, a repository-scoped file was generated for every repository in that inventory, not just for `REPOSITORY_SLUG`.
- Verify that any CODEOWNERS-derived maintainers came only from `.github/CODEOWNERS`, `CODEOWNERS`, or `docs/CODEOWNERS`, and only from global `*` ownership lines.
- Verify that CODEOWNERS parsing ignored `@UNOWNED`, bot accounts, org-name placeholders, and unresolved extra teams beyond the first team that successfully resolves.
- Verify that boolean negatives and priority markers such as `bug-bounty-available: false`, `accepts-automated-change-request: false`, `no-third-party-packages: true`, and `primary: true` were emitted only when direct evidence supported them.
- Verify that `project.administrators` and `repository.core-team` were not populated by blindly duplicating the same large maintainer roster.
- Verify that `repository.core-team` remains a smaller operational subset when the evidence does not justify using the full administrator list.
- Verify that dependency management policy detection included `THIRD-PARTY-NOTICES.txt` and `NOTICE`-style files.
- Verify that dependency tooling detection included `Dependabot` when a dependabot config exists.
- Verify that `adhoc` is true for tools found in scheduled or manually dispatched workflows.
- Verify that tool versions were extracted when the workflow pins an action version.
- Verify that each generated YAML file was parse-checked successfully before schema validation was reported.
- Verify that narrative security documentation was checked for explicit assessment or audit evidence before using the default assessment placeholders.
- Verify that commonly omitted fields were checked against the most likely direct evidence sources before being left out.
- Verify that month-or-year assessment timing from narrative docs was preserved in either `date` or `comment` instead of being discarded.
- Verify that project-level `funding`, `steward`, `in-scope`, and `out-of-scope` were checked against funding, governance, foundation, and security reporting sources before being omitted.
- Verify that `review-policy`, `changelog`, and `champions` were checked against contribution guides, GitHub Releases or release notes, and security reporting or contact sources before being omitted.
- Verify that `dependency-management-policy` was included only when a documented policy was found, not merely because dependencies or dependency updates exist.
- Verify that `attestations` were included only when artifact or provenance attestation evidence was found.
```

## After The Run

When the AI assistant finishes, do a quick sanity check on its output:

- Files were actually written under `OUTPUT_FOLDER`.
- The assistant reported whether the official CUE schema validation ran (and what it said).
- Repository-scoped files do not contain `project.repositories` or a made-up `header.project-si-source`.

If the run did not produce usable output, the most common causes are:

- The AI assistant cannot read GitHub repositories or workflow files in your environment.
- The AI assistant cannot create files in the target output folder.
- The environment has no authenticated GitHub access, and the assistant did not say so.
- The assistant claimed success without running (or even mentioning) CUE validation.

If those look fine and the output is still wrong, try again with a smaller, explicit scope: fill in `VERIFIED_PROJECT_REPOSITORIES` yourself with the exact repositories you want covered, so the assistant cannot drift on inventory discovery.
