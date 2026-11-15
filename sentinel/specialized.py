"""Detect source types and run targeted security scanners without project scripts."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


OSV_TIMEOUT_SECONDS = 300


def detect(root: Path) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {'python': [], 'docker': [], 'go': [], 'dependencies': []}
    dependency_names = {'requirements.txt', 'requirements-dev.txt', 'pyproject.toml', 'poetry.lock', 'uv.lock', 'Pipfile.lock', 'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'go.mod', 'Cargo.lock', 'Gemfile.lock', 'composer.lock'}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {'.git', 'node_modules', '.venv', 'venv', '__pycache__'})
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink():
                continue
            if name.endswith('.py'):
                found['python'].append(path)
            if name == 'Dockerfile' or name.startswith('Dockerfile.') or name.endswith('.dockerfile'):
                if not name.endswith(('.dockerignore', '.nanorc')):
                    found['docker'].append(path)
            if name == 'go.mod':
                found['go'].append(path)
            if name in dependency_names:
                found['dependencies'].append(path)
    return found


def run(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False)



def diagnostic_category(stderr: str) -> str:
    """Classify diagnostics without persisting untrusted paths or scanner text."""
    text = stderr.lower()
    labels = []
    for words, label in ((('timeout', 'timed out', 'deadline exceeded'), 'timeout'), (('429', 'rate limit'), 'rate limiting'), (('network', 'connection', 'dns', 'no such host'), 'network or DNS'), (('parse', 'parsing', 'invalid format'), 'input parsing'), (('permission denied', 'access denied'), 'access denied')):
        if any(word in text for word in words):
            labels.append(label)
    return ', '.join(labels) if labels else 'unclassified; raw output withheld'


def timed_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    start = time.monotonic()
    try:
        return run(args, **kwargs)
    finally:
        print(f"{args[0]} elapsed: {time.monotonic() - start:.1f}s", flush=True)


def fixed_versions(vulnerability: dict[str, Any], package: dict[str, Any]) -> list[str]:
    """Return matching ecosystem version fixes only; never infer from Git ranges."""
    ecosystem = str(package.get('ecosystem') or '').casefold()
    name = str(package.get('name') or '').casefold()
    if not ecosystem or not name:
        return []
    versions: set[str] = set()
    for affected in vulnerability.get('affected') or []:
        if not isinstance(affected, dict):
            continue
        candidate = affected.get('package') or {}
        if not isinstance(candidate, dict) or str(candidate.get('ecosystem') or '').casefold() != ecosystem or str(candidate.get('name') or '').casefold() != name:
            continue
        for interval in affected.get('ranges') or []:
            if not isinstance(interval, dict) or interval.get('type') not in ('ECOSYSTEM', 'SEMVER'):
                continue
            for event in interval.get('events') or []:
                if isinstance(event, dict) and isinstance(event.get('fixed'), str):
                    versions.add(event['fixed'])
    return sorted(versions)

def advisory_severity(vulnerability: dict[str, Any]) -> str:
    metadata = vulnerability.get('database_specific')
    value = str(metadata.get('severity', '')).upper() if isinstance(metadata, dict) else ''
    if value in {'CRITICAL', 'HIGH', 'MEDIUM', 'MODERATE', 'LOW'}:
        return value
    return 'UNRATED'


def scan(root: Path, *, resolve_osv: bool = True) -> dict[str, Any]:
    files = detect(root)
    findings: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    # OSV also performs Go call analysis by default, where Go modules are detected.
    if not shutil.which('osv-scanner'):
        coverage.append({'scanner': 'OSV-Scanner', 'status': 'incomplete', 'detail': 'Scanner unavailable.'})
    else:
        try:
            env = dict(os.environ, CGO_ENABLED='0', GOWORK='off', GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org')
            # Do not let the target's own configuration suppress vulnerabilities.
            with tempfile.NamedTemporaryFile(mode='w', suffix='.toml') as config:
                config.flush()
                args = ['osv-scanner', 'scan', 'source', '-r', '--no-ignore', '--config', config.name, '--format', 'json']
                if not resolve_osv:
                    args.append('--no-resolve')
                result = timed_run([*args, str(root)], env=env, timeout=OSV_TIMEOUT_SECONDS)
            data = json.loads(result.stdout) if result.stdout.strip() else {}
            if result.returncode not in (0, 1, 128):
                raise ValueError(f'scanner exited {result.returncode}')
            if result.returncode in (0, 1) and not isinstance(data.get('results'), list):
                raise ValueError('missing results')
            for group in data.get('results', []):
                source = str(group.get('source', {}).get('path', 'unknown'))
                for package in group.get('packages', []):
                    pkg = package.get('package') or {}
                    for vuln in package.get('vulnerabilities', []):
                        findings.append({'scanner': 'OSV-Scanner', 'rule': str(vuln.get('id') or 'unknown'), 'path': source, 'line': None, 'severity': advisory_severity(vuln), 'description': str(pkg.get('name') or 'unknown') + '@' + str(pkg.get('version') or 'unknown') + ': ' + str(vuln.get('summary') or 'Known dependency vulnerability'), 'package': str(pkg.get('name') or 'unknown'), 'ecosystem': str(pkg.get('ecosystem') or ''), 'version': str(pkg.get('version') or 'unknown'), 'aliases': [str(a) for a in vuln.get('aliases', []) if isinstance(a, str)], 'url': 'https://osv.dev/vulnerability/' + str(vuln.get('id') or ''), 'fixed': fixed_versions(vuln, pkg)})
            warnings = sum(1 for line in result.stderr.splitlines() if any(word in line.lower() for word in ('warning', 'warn ', 'error', 'failed', 'unable to')))
            detail = 'No packages found.' if result.returncode == 128 else 'Dependency advisories checked.'
            if not resolve_osv:
                detail += ' OSV transitive resolution disabled. Results use dependency versions extracted from source files.'
            if warnings:
                detail += f' Scanner reported {warnings} warning/error line(s); category: {diagnostic_category(result.stderr)}; some checks may be incomplete.'
            if files['go']:
                detail += ' Go call analysis is attempted; review scanner output for unsupported modules and build configurations.'
            coverage.append({'scanner': 'OSV-Scanner', 'status': 'partial' if warnings else ('no packages' if result.returncode == 128 else 'completed'), 'detail': detail, 'transitive_resolution': resolve_osv})
        except subprocess.TimeoutExpired:
            coverage.append({'scanner': 'OSV-Scanner', 'status': 'incomplete', 'detail': f'Dependency scan timed out after {OSV_TIMEOUT_SECONDS // 60} minutes.'})
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            coverage.append({'scanner': 'OSV-Scanner', 'status': 'incomplete', 'detail': f'Unable to finish or parse report: {type(exc).__name__}.'})
    if not files['python']:
        coverage.append({'scanner': 'Bandit', 'status': 'not applicable', 'detail': 'No Python files detected.'})
    elif not shutil.which('bandit'):
        coverage.append({'scanner': 'Bandit', 'status': 'incomplete', 'detail': 'Scanner unavailable.'})
    else:
        errors = 0
        reasons: list[str] = []
        successful_batches = 0
        python_files = files['python']
        # Bound memory and command size; preserve findings from successful batches.
        for offset in range(0, len(python_files), 100):
            batch = python_files[offset:offset + 100]
            try:
                result = timed_run(['bandit', '--quiet', '-f', 'json', '--exit-zero', '--ignore-nosec', *(str(path) for path in batch)])
                if result.returncode != 0:
                    raise ValueError(f'exit {result.returncode}; {diagnostic_category(result.stderr)}')
                data = json.loads(result.stdout)
                if not isinstance(data, dict) or not isinstance(data.get('results'), list):
                    raise ValueError('invalid JSON report')
                for item in data['results']:
                    findings.append({'scanner': 'Bandit', 'rule': str(item.get('test_id') or 'unknown'), 'path': str(item.get('filename') or 'unknown'), 'line': item.get('line_number'), 'severity': str(item.get('issue_severity') or 'unknown'), 'description': re.sub(r'[^a-zA-Z0-9_-]', '', str(item.get('test_name') or 'Python security issue')).replace('_', ' ')})
                errors += len(data.get('errors') or [])
                successful_batches += 1
            except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired) as exc:
                errors += len(batch)
                if isinstance(exc, subprocess.TimeoutExpired):
                    reasons.append('batch timed out')
                elif isinstance(exc, json.JSONDecodeError):
                    reasons.append('invalid or empty JSON output')
                elif isinstance(exc, ValueError):
                    reasons.append(str(exc))
                else:
                    reasons.append(type(exc).__name__)
        detail = f"{len(python_files)} Python files detected; {errors} file or scanner error(s)."
        if reasons:
            detail += ' ' + '; '.join(sorted(set(reasons))) + '.'
        coverage.append({'scanner': 'Bandit', 'status': ('partial' if successful_batches else 'incomplete') if errors else 'completed', 'detail': detail})
    if not files['docker']:
        coverage.append({'scanner': 'Hadolint', 'status': 'not applicable', 'detail': 'No Dockerfiles detected.'})
    elif not shutil.which('hadolint'):
        coverage.append({'scanner': 'Hadolint', 'status': 'incomplete', 'detail': 'Scanner unavailable.'})
    else:
        errors = 0
        for path in files['docker']:
            try:
                result = timed_run(['hadolint', '--no-fail', '--disable-ignore-pragma', '--format', 'json', str(path)], timeout=120)
                data = json.loads(result.stdout)
                if result.returncode != 0 or not isinstance(data, list):
                    raise ValueError('Hadolint failed')
                for item in data:
                    findings.append({'scanner': 'Hadolint', 'rule': str(item.get('code') or 'unknown'), 'path': str(path), 'line': item.get('line'), 'severity': str(item.get('level') or 'unknown'), 'description': 'Dockerfile lint rule; see linked documentation', 'url': 'https://github.com/hadolint/hadolint/wiki/' + str(item.get('code') or '')})
            except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError, subprocess.TimeoutExpired):
                errors += 1
        coverage.append({'scanner': 'Hadolint', 'status': 'partial' if errors else 'completed', 'detail': f'{len(files["docker"])} Dockerfile(s) detected; {errors} could not be checked.'})
    return {'scanner': 'specialized', 'coverage': coverage, 'findings': findings}
