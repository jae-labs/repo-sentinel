"""Inventory validation, revision resolution, and Trivy reporting."""
from __future__ import annotations

import json
import os
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
    image: str = ''
    platform: str = ''
    osv_resolve: bool = True
    source_commit: str = ''


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
        image, platform = item.get('image', ''), item.get('platform', '')
        if not isinstance(image, str) or (image and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}', image)):
            raise ValueError(f'Invalid image: {image!r}')
        if '@sha256:' in image and not re.search(r'@sha256:[0-9a-fA-F]{64}$', image):
            raise ValueError('Image digest must be a complete SHA-256')
        if not isinstance(platform, str) or (platform and not re.fullmatch(r'[a-z0-9_]+/[a-z0-9_]+(?:/[a-z0-9_]+)?', platform)):
            raise ValueError(f'Invalid image platform: {platform!r}')
        if platform and not image:
            raise ValueError('An image platform requires an image')
        osv_resolve = item.get('osv_resolve', True)
        if not isinstance(osv_resolve, bool):
            raise ValueError('osv_resolve must be a boolean')
        source_commit = item.get('source_commit', '')
        if not isinstance(source_commit, str) or (source_commit and not re.fullmatch(r'[0-9a-fA-F]{40}', source_commit)):
            raise ValueError('source_commit must be a full Git commit SHA')
        seen.add(repo.lower())
        targets.append(Target(repo, version, image, platform, osv_resolve, source_commit.lower()))
    return targets


def run_git(path: Path | None, *args: str) -> subprocess.CompletedProcess[str]:
    command = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'credential.helper=']
    if path is not None:
        command += ['-C', str(path)]
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_LFS_SKIP_SMUDGE='1', GIT_ALLOW_PROTOCOL='https')
    return subprocess.run(command + list(args), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=env, timeout=900)


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
        if len(version) == 40:
            fetched = git(path, 'fetch', '--no-tags', 'origin', version)
            if fetched.returncode == 0:
                verified = git(path, 'rev-parse', '--verify', 'FETCH_HEAD^{commit}')
                if verified.returncode == 0 and verified.stdout.strip().lower() == version.lower():
                    return verified.stdout.strip(), True
    result = git(path, 'rev-parse', '--verify', 'HEAD^{commit}')
    if result.returncode:
        raise RuntimeError('Unable to resolve default branch revision')
    return result.stdout.strip(), False


def clone_target(target: Target, path: Path) -> dict[str, Any]:
    result = run_git(None, 'clone', '--quiet', '--no-checkout', '--filter=blob:none', f'https://github.com/{target.repo}.git', str(path))
    if result.returncode:
        raise RuntimeError(f'Clone failed: {result.stderr.strip()}')
    warnings: list[str] = []
    try:
        tag_fetch = run_git(path, 'fetch', '--tags', 'origin')
        if tag_fetch.returncode:
            warnings.append('Tag fetch failed.')
    except subprocess.TimeoutExpired:
        warnings.append('Tag fetch timed out.')
    commit, matched = resolve_revision(path, target.source_commit or target.version)
    if target.source_commit and (not matched or commit != target.source_commit):
        raise RuntimeError(f'Unable to resolve pinned source commit for {target.repo}')
    result = run_git(path, 'checkout', '--quiet', '--detach', commit)
    if result.returncode:
        raise RuntimeError(f'Checkout failed: {result.stderr.strip()}')
    if (path / '.gitmodules').exists():
        try:
            submodules = run_git(path, 'submodule', 'update', '--init', '--recursive')
            if submodules.returncode:
                warnings.append('Submodule fetch failed.')
            else:
                warnings.append('Submodule Git LFS coverage is unverified.')
        except subprocess.TimeoutExpired:
            warnings.append('Submodule fetch timed out.')
    try:
        lfs = run_git(path, 'lfs', 'ls-files', '--name-only')
        if lfs.returncode:
            warnings.append('Git LFS status unavailable.')
        elif lfs.stdout.strip():
            pulled = run_git(path, 'lfs', 'pull')
            if pulled.returncode:
                warnings.append('Git LFS fetch failed.')
    except subprocess.TimeoutExpired:
        warnings.append('Git LFS operation timed out.')
    for _, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [directory for directory in dirs if directory != '.git']
        if '.semgrepignore' in files:
            warnings.append('Semgrep ignore files detected.')
            break
    return {'repository': target.repo, 'requested_version': target.version, 'commit': commit, 'matched_version': matched, 'source_warnings': warnings}



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
                    'kind': 'advisory' if key == 'Vulnerabilities' else 'rule',
                    'installed': str(item.get('InstalledVersion') or '—'),
                    'fixed': str(item.get('FixedVersion') or '—'),
                    'url': str(item.get('PrimaryURL') or ''),
                    'target': str(result.get('Target') or 'unknown'),
                    'title': str((item.get('Message') if key == 'Misconfigurations' else item.get('Title')) or item.get('Description') or item.get('Title') or item.get('Message') or 'No description provided'),
                })
    return sorted(output, key=lambda x: (x['severity'] != 'CRITICAL', x['id'], x['package']))


def priority_severity(value: Any) -> str:
    severity = str(value).upper()
    return severity if severity in {'CRITICAL', 'HIGH'} else ''


def short_description(value: str, limit: int = 240) -> str:
    text = ' '.join(value.split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + '…'


def cell(value: str) -> str:
    return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\n', ' ').replace('\r', ' ')


def scan_diagnostics(log: str | None) -> dict[str, Any]:
    if log is None:
        return {'available': False, 'errors': [], 'dependency_files': None}
    errors = []
    file_count = None
    for line in log.splitlines():
        if re.search(r'\bERROR\b', line):
            errors.append(line.strip())
        if 'Number of language-specific files' in line:
            match = re.search(r'\bnum[=:]\s*(\d+)', line)
            if match:
                file_count = int(match.group(1))
    return {'available': True, 'errors': errors, 'dependency_files': file_count}


def diagnostics_summary(info: dict[str, Any]) -> str:
    if not info.get('available'):
        return '**Trivy diagnostics unavailable.**'
    lines = []
    errors = info.get('errors', [])
    if errors:
        lines.append(f'**Partial scan. Trivy logged {len(errors)} errors.**')
        for error in errors[:5]:
            lines.append(f'- {cell(short_description(error, 350))}')
        if len(errors) > 5:
            lines.append(f'- {len(errors) - 5} additional errors in scan.log.')
    count = info.get('dependency_files')
    if count is None:
        lines.append('Trivy dependency file count unavailable.')
    elif count == 0:
        lines.append('Trivy detected no dependency files.')
    else:
        lines.append(f'Trivy detected {count} dependency files.')
    return '\n'.join(lines)


def render_summary(repo: str, version: str, revision: dict[str, Any] | None, report: dict[str, Any] | None, status: str, limit: int = 12, *, image: bool = False) -> str:
    label = 'Platform' if image else 'Requested version'
    lines = [f'## {cell(repo)}', '', f'{label}: `{cell(version)}`']
    if revision:
        match = 'requested revision' if revision['matched_version'] else 'default branch fallback'
        lines.append(f"Scanned commit: `{cell(str(revision['commit']))}` ({match})")
        for warning in revision.get('source_warnings', []):
            lines.append('**Source coverage:** ' + cell(str(warning)))
    if status != 'success' or report is None:
        lines.append('**Scan failed or produced no report.** See job logs.')
        return '\n\n'.join(lines) + '\n'
    rows = findings(report)
    scan = 'image scan' if image else 'source scan'
    lines.append(f'\n**Trivy {scan} reported {len(rows)} high or critical findings.**\n')
    if rows:
        lines.append('| Severity | Advisory | Finding | Package or target | Version | Fixed |\n| --- | --- | --- | --- | --- | --- |')
        for item in rows[:limit]:
            ident = cell(item['id'])
            url = item['url']
            if url.startswith('https://') and not re.search(r'[\s()<>]', url):
                ident = f'[{ident}]({quote(url, safe=":/#?&=%._~-+;")})'
            lines.append(f"| {cell(item['severity'])} | {ident} | {cell(short_description(item['title']))} | {cell(item['package'])} | {cell(item['installed'])} | {cell(item['fixed'])} |")
        if len(rows) > limit:
            lines.append(f'\nShowing {limit} of {len(rows)} findings. See the JSON report for all results.')
    return '\n'.join(lines) + '\n'
