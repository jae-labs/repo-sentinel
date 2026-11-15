# Repo Sentinel

Repo Sentinel scans public third-party repositories for dependency vulnerabilities, insecure configuration, and source-code issues. It runs on a schedule or on demand using GitHub Actions and produces a combined report plus individual scan artifacts, including sanitized SARIF.

Add targets to an inventory under `inventories/` using GitHub `owner/repository` names and version tags or commits. Optionally set `image` and `platform` (for example `linux/arm64`) to scan a published image; an immutable digest is preferred. Workflows call the shared scanner with an inventory. If a requested revision cannot be resolved, the report identifies the default-branch fallback.

Trivy and OSV-Scanner check dependencies; Semgrep and Bandit check source code; Trivy and Hadolint check configuration and Dockerfiles. Checks run when relevant files are detected. The combined report highlights CISA known-exploited findings, groups matching advisory aliases, labels recognizable development and test paths, and shows scanner coverage limits. Unclassified dependencies may be used at runtime. Source snippets and raw Semgrep messages are excluded from saved reports; findings still require review. Go dependency analysis loads source and may download modules; project install and build scripts are not run. Image scans inspect configured registry images, not running containers.

The combined summary highlights CISA matches, high and critical findings, and coverage for each target. Individual summaries also show Semgrep ERROR results separately. Per-target JSON artifacts retain all findings emitted by the configured scans. SARIF is sanitized and uses existing scan results. OSV has a five-minute limit per repository. Timeouts appear as incomplete coverage.

Run tests with `python3 -m unittest discover -s tests -v`.
