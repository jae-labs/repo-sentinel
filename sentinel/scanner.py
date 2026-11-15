"""Inventory validation, revision resolution, and Trivy reporting."""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')
VERSION = re.compile(r'[A-Za-z0-9_.-]+\Z')
COMMIT = re.compile(r'[0-9a-fA-F]{7,40}\Z')


@dataclass(frozen=True)
class Target:
    repo: str
    version: str


def parse_inventory(value: Any) -> list[Target]:
    if not isinstance(value, list):
        raise ValueError('Inventory must be a JSON array')
    targets: list[Target] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError('Each target must be an object')
        repo, version = item.get('repo'), item.get('version')
        if not isinstance(repo, str) or not REPO.fullmatch(repo) or any(part in ('.', '..') for part in repo.split('/')):
            raise ValueError(f'Invalid repository: {repo!r}')
        if repo.lower() in seen:
            raise ValueError(f'Duplicate repository: {repo}')
        if not isinstance(version, str) or not VERSION.fullmatch(version) or version in ('.', '..') or version.startswith('-'):
            raise ValueError(f'Invalid version: {version!r}')
        seen.add(repo.lower())
        targets.append(Target(repo, version))
    return targets


def run_git(path: Path | None, *args: str) -> subprocess.CompletedProcess[str]:
    command = ['git', '-c', 'core.hooksPath=/dev/null']
    if path is not None:
        command += ['-C', str(path)]
    return subprocess.run(command + list(args), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def resolve_revision(path: Path, version: str, git: Callable[..., subprocess.CompletedProcess[str]] = run_git) -> tuple[str, bool]:
    alternatives = [version, version[1:] if version.startswith('v') else 'v' + version]
    for ref in alternatives:
        result = git(path, 'rev-parse', '--verify', f'refs/tags/{ref}^{{commit}}')
        if result.returncode == 0:
            return result.stdout.strip(), True
    if COMMIT.fullmatch(version):
        result = git(path, 'rev-parse', '--verify', f'{version}^{{commit}}')
        if result.returncode == 0:
            return result.stdout.strip(), True
    result = git(path, 'rev-parse', '--verify', 'HEAD^{commit}')
    if result.returncode:
        raise RuntimeError('Unable to resolve default branch revision')
    return result.stdout.strip(), False


def clone_target(target: Target, path: Path) -> dict[str, Any]:
    result = run_git(None, 'clone', '--quiet', '--no-checkout', '--filter=blob:none', f'https://github.com/{target.repo}.git', str(path))
    if result.returncode:
        raise RuntimeError(f'Clone failed: {result.stderr.strip()}')
    commit, matched = resolve_revision(path, target.version)
    result = run_git(path, 'checkout', '--quiet', '--detach', commit)
    if result.returncode:
        raise RuntimeError(f'Checkout failed: {result.stderr.strip()}')
    return {'repository': target.repo, 'requested_version': target.version, 'commit': commit, 'matched_version': matched}


def findings(report: dict[str, Any]) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    for result in report.get('Results') or []:
        for key in ('Vulnerabilities', 'Misconfigurations'):
            for item in result.get(key) or []:
                severity = str(item.get('Severity', 'UNKNOWN')).upper()
                if severity not in {'HIGH', 'CRITICAL'}:
                    continue
                output.append({
                    'severity': severity, 'id': str(item.get('VulnerabilityID') or item.get('ID') or 'unknown'),
                    'package': str(item.get('PkgName') or result.get('Target') or 'unknown'),
                    'installed': str(item.get('InstalledVersion') or '—'),
                    'fixed': str(item.get('FixedVersion') or '—'),
                    'url': str(item.get('PrimaryURL') or ''),
                    'target': str(result.get('Target') or 'unknown'),
                    'title': str(item.get('Title') or item.get('Message') or ''),
                })
    return sorted(output, key=lambda x: (x['severity'] != 'CRITICAL', x['id'], x['package']))


def cell(value: str) -> str:
    return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\n', ' ').replace('\r', ' ')


def render_summary(repo: str, version: str, revision: dict[str, Any] | None, report: dict[str, Any] | None, status: str, limit: int = 200) -> str:
    lines = [f'## {cell(repo)}', f'Requested version: `{cell(version)}`']
    if revision:
        match = 'matched requested version' if revision['matched_version'] else 'default branch; requested version not matched'
        lines.append(f"Scanned commit: `{cell(str(revision['commit']))}` ({match})")
    if status != 'success' or report is None:
        lines.append('**Scan failed or did not produce a report. Check the job logs.**')
        return '\n\n'.join(lines) + '\n'
    rows = findings(report)
    lines.append(f'**{len(rows)} high or critical findings.** Full JSON report is available in the job artifact.')
    if rows:
        lines.append('| Severity | Advisory | Package or target | Version | Fixed |\n| --- | --- | --- | --- | --- |')
        for item in rows[:limit]:
            ident = cell(item['id'])
            url = item['url']
            if url.startswith('https://') and not re.search(r'[\s()<>]', url):
                ident = f'[{ident}]({quote(url, safe=":/#?&=%._~-+;")})'
            lines.append(f"| {cell(item['severity'])} | {ident} | {cell(item['package'])} | {cell(item['installed'])} | {cell(item['fixed'])} |")
        if len(rows) > limit:
            lines.append(f'\nShowing {limit} of {len(rows)} findings; see the JSON artifact for the full report.')
    return '\n'.join(lines) + '\n'
