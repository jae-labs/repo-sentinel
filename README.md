# Repo Sentinel

Repo Sentinel scans public third-party GitHub repositories for dependency vulnerabilities and configuration issues. GitHub Actions runs scans on a schedule or on demand and displays findings in job summaries.

## Configuration

Target lists are JSON files in `inventories/`. Each entry specifies a public GitHub repository as `owner/name` and a version tag or commit:

```json
[
  {"repo": "example/project", "version": "v1.2.3"}
]
```

## Results and coverage

Each target has a separate job with a Markdown summary of high and critical findings, including advisory links, package versions and available fixes where the scanner provides them. Up to 200 findings are displayed per job; download its `scan-*` artifact for the full Trivy JSON report (`results.json`) and scanned revision (`revision.json`). Clone or scan failures fail the job. Findings do not fail it; review the report and decide how to respond. Warnings flag unmatched versions and errors flag scan failures.

The scanner tries the requested tag, then its equivalent with or without `v`, or a hexadecimal commit. If no revision matches, it scans the default branch and flags the mismatch. A short commit may be unavailable if it is not in the cloned history. `revision.json` records the actual scanned commit. A matching source tag does not establish that a deployed binary or container matches that source.

Trivy checks supported dependency manifests, lockfiles and configuration files, including Dockerfiles. It does not run project code, build images, inspect running containers or scan for secrets. Coverage depends on the files and ecosystems supported by the scanner; an empty report is not proof that a project is safe.

The workflow uses read-only repository permissions and does not persist checkout credentials. This repository, its target lists, and its Actions logs and artifacts may be public; do not add private URLs, credentials or sensitive inventory details. GitHub may delay scheduled runs or disable them after repository inactivity. Review scanner and action updates regularly.

## Development

Run the standard-library tests with `python3 -m unittest discover -s tests -v`. The scanner uses typed functions and requires no third-party Python packages.
