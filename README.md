# Repo Sentinel

Repo Sentinel scans public GitHub repositories and container images for dependency vulnerabilities, insecure configuration, and source-code issues. It uses Trivy, OSV-Scanner, Semgrep, Bandit, and Hadolint.

The active scan runs daily, on pushes to `main`, and on demand. Use **Generic repository scan** to run [`inventories/generic.json`](inventories/generic.json) on demand.

Targets require `repo` (`owner/repository`) and `version` (a tag or commit).

- `source_commit` pins a full commit SHA when the component version has no matching repository tag.
- `image` and `platform` select a published container image and architecture.
- `osv_resolve: false` skips transitive resolution for that target.

Unresolved versions fall back to the default branch. An unavailable `source_commit` fails the source checkout.

Each run publishes one summary with CISA KEV matches, grouped critical and high findings, and coverage gaps. Per-target Markdown, JSON, and SARIF artifacts are retained for 30 days.

Missing or invalid required reports fail the run after the combined summary is written.
Semgrep artifacts record the registry ruleset digest.

Use Python 3.14 for local checks.

```sh
python -m pip install --group dev
ruff check
ruff format --check
mypy
python -m unittest discover -s tests -v
```
