"""Detect source types and run targeted security scanners without project scripts."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


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


def scan(root: Path) -> dict[str, Any]:
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
                result = run(['osv-scanner', 'scan', 'source', '-r', '--no-ignore', '--config', config.name, '--format', 'json', str(root)], env=env)
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
                        findings.append({'scanner': 'OSV-Scanner', 'rule': str(vuln.get('id') or 'unknown'), 'path': source, 'line': None, 'severity': 'advisory', 'description': str(pkg.get('name') or 'unknown') + '@' + str(pkg.get('version') or 'unknown') + ': ' + str(vuln.get('summary') or 'Known dependency vulnerability'), 'package': str(pkg.get('name') or 'unknown'), 'version': str(pkg.get('version') or 'unknown'), 'aliases': [str(a) for a in vuln.get('aliases', []) if isinstance(a, str)], 'url': 'https://osv.dev/vulnerability/' + str(vuln.get('id') or ''), 'fixed': sorted({str(event['fixed']) for affected in (vuln.get('affected') or []) for interval in (affected.get('ranges') or []) for event in (interval.get('events') or []) if event.get('fixed')})})
            warnings = sum(1 for line in result.stderr.splitlines() if any(word in line.lower() for word in ('warning', 'warn ', 'error', 'failed', 'unable to')))
            detail = 'No packages found.' if result.returncode == 128 else 'Dependency advisories checked.'
            if warnings:
                detail += f' Scanner reported {warnings} warning/error line(s); some checks may be incomplete.'
            if files['go']:
                detail += ' Go call analysis is attempted; review scanner output for unsupported modules and build configurations.'
            coverage.append({'scanner': 'OSV-Scanner', 'status': 'partial' if warnings else ('no packages' if result.returncode == 128 else 'completed'), 'detail': detail})
        except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            coverage.append({'scanner': 'OSV-Scanner', 'status': 'incomplete', 'detail': f'Unable to finish or parse report: {type(exc).__name__}.'})
    if not files['python']:
        coverage.append({'scanner': 'Bandit', 'status': 'not applicable', 'detail': 'No Python files detected.'})
    elif not shutil.which('bandit'):
        coverage.append({'scanner': 'Bandit', 'status': 'incomplete', 'detail': 'Scanner unavailable.'})
    else:
        try:
            result = run(['bandit', '-r', str(root), '-f', 'json', '--exit-zero', '--ignore-nosec'])
            data = json.loads(result.stdout)
            if result.returncode != 0 or not isinstance(data.get('results'), list):
                raise ValueError('Bandit failed')
            for item in data['results']:
                findings.append({'scanner': 'Bandit', 'rule': str(item.get('test_id') or 'unknown'), 'path': str(item.get('filename') or 'unknown'), 'line': item.get('line_number'), 'severity': str(item.get('issue_severity') or 'unknown'), 'description': re.sub(r'[^a-zA-Z0-9_-]', '', str(item.get('test_name') or 'Python security issue')).replace('_', ' ')})
            errors = data.get('errors') or []
            coverage.append({'scanner': 'Bandit', 'status': 'partial' if errors else 'completed', 'detail': f"{len(files['python'])} Python files detected; {len(errors)} scanner errors."})
        except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            coverage.append({'scanner': 'Bandit', 'status': 'incomplete', 'detail': f'Unable to finish or parse report: {type(exc).__name__}.'})
    if not files['docker']:
        coverage.append({'scanner': 'Hadolint', 'status': 'not applicable', 'detail': 'No Dockerfiles detected.'})
    elif not shutil.which('hadolint'):
        coverage.append({'scanner': 'Hadolint', 'status': 'incomplete', 'detail': 'Scanner unavailable.'})
    else:
        errors = 0
        for path in files['docker']:
            try:
                result = run(['hadolint', '--no-fail', '--disable-ignore-pragma', '--format', 'json', str(path)], timeout=120)
                data = json.loads(result.stdout)
                if result.returncode != 0 or not isinstance(data, list):
                    raise ValueError('Hadolint failed')
                for item in data:
                    findings.append({'scanner': 'Hadolint', 'rule': str(item.get('code') or 'unknown'), 'path': str(path), 'line': item.get('line'), 'severity': str(item.get('level') or 'unknown'), 'description': 'Dockerfile lint rule; see linked documentation', 'url': 'https://github.com/hadolint/hadolint/wiki/' + str(item.get('code') or '')})
            except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError, subprocess.TimeoutExpired):
                errors += 1
        coverage.append({'scanner': 'Hadolint', 'status': 'partial' if errors else 'completed', 'detail': f'{len(files["docker"])} Dockerfile(s) detected; {errors} could not be checked.'})
    return {'scanner': 'specialized', 'coverage': coverage, 'findings': findings}
