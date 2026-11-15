# Repo Sentinel

Repo Sentinel scans public third-party repositories for dependency vulnerabilities, insecure configuration, source-code issues. It runs on a schedule or on demand using GitHub Actions and produces a combined report plus individual scan artifacts.

Add targets to an inventory under `inventories/` using GitHub `owner/repository` names and version tags or commits. Optionally set `image` and `platform` (for example `linux/arm64`) to scan a published image; an immutable digest is preferred. Workflows call the shared scanner with an inventory. If a requested revision cannot be resolved, the report identifies the default-branch fallback.

Trivy and OSV-Scanner check dependencies; Semgrep and Bandit check source code; Trivy and Hadolint check configuration and Dockerfiles. Checks run when relevant files are detected. The combined report highlights findings in CISA’s Known Exploited Vulnerabilities catalog and shows scanner failures and coverage limits. Source snippets and raw Semgrep messages are excluded from saved reports; findings still require review. Go dependency analysis loads source and may download modules; project install and build scripts are not run. Image scans inspect configured registry images, not running containers.

Run tests with `python3 -m unittest discover -s tests -v`.
