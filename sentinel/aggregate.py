"""Summarize scan evidence and coverage across every target."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote

from sentinel.extra_scanners import dependency_scope, grouped_findings
from sentinel.kev import kev_section
from sentinel.scanner import Target, cell, findings, priority_severity, scan_diagnostics, short_description

PRIORITY_LIMIT = 30
SARIF_FILES = ('results.sarif', 'image-results.sarif', 'semgrep.sarif', 'osv.sarif', 'bandit.sarif')


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ValueError(f'{path.name} must contain an object')
    return value


def available_report(path: Path) -> dict[str, Any]:
    try:
        return read_object(path)
    except (OSError, ValueError):
        return {}


def trivy_findings(directory: Path, filename: str) -> list[dict[str, str]]:
    report = read_object(directory / filename)
    if report.get('SchemaVersion') != 2 or not isinstance(report.get('Results', []), list):
        raise ValueError('Invalid Trivy report')
    return findings(report)


def priority_table(rows: list[dict[str, str]]) -> str:
    if not rows:
        return '## High and critical findings\n\nNo high or critical results reported by the available scanners. See coverage below.\n\n'
    ordered = sorted(rows, key=lambda row: (
        row['severity'] != 'CRITICAL', dependency_scope(row['target']) == 'development/test',
        row['repo'], row['scanner'], row['id'], row['package'],
    ))
    selected: list[dict[str, str]] = []
    per_target: Counter[tuple[str, str]] = Counter()
    for row in ordered:
        key = row['repo'], row['severity']
        if per_target[key] < 3:
            selected.append(row)
            per_target[key] += 1
        if len(selected) == PRIORITY_LIMIT:
            break
    lines = ['## High and critical findings', '',
             f'Showing {len(selected)} of {len(rows)} reported rows, up to three per repository and severity. Open the individual scan artifact for full findings.',
             '', '| Severity | Repository | Scanner | Advisory | Finding | Package or file | Version → fix |',
             '| --- | --- | --- | --- | --- | --- | --- |']
    for row in selected:
        advisory = cell(row['id'])
        url = row.get('url', '')
        if url.startswith('https://') and not any(c.isspace() for c in url):
            advisory = f'[{advisory}]({quote(url, safe=":/#?&=%._~-+;")})'
        fields = (row['severity'], row['repo'], row['scanner'])
        location = cell(short_description(row['package'], 100))
        version = cell(short_description(row['installed'] + ' → ' + row['fixed'], 120))
        lines.append('| ' + ' | '.join([*(cell(c) for c in fields), advisory,
                     cell(short_description(row['title'], 150)), location, version]) + ' |')
    return '\n'.join(lines) + '\n\n'


def combined_report(targets: list[Target], artifacts: Path, catalog_path: Path | None = None) -> str:
    overview: list[str] = []
    priority: list[dict[str, str]] = []
    available = partial = unmatched = unknown_semgrep = 0
    for index, target in enumerate(targets):
        directory = artifacts / f'scan-{index}'
        status = available_report(directory / 'status.json')
        revision = available_report(directory / 'revision.json')
        identity = status.get('repository') == target.repo and status.get('version') == target.version
        revision_valid = (identity and status.get('clone_outcome') == 'success'
                          and revision.get('repository') == target.repo
                          and revision.get('requested_version') == target.version
                          and bool(revision.get('commit')) and isinstance(revision.get('matched_version'), bool))
        gaps: list[str] = []
        notes: list[str] = []
        source_count = image_count = other_count = '—'
        if not revision_valid:
            gaps.append('revision unavailable')
        elif not revision['matched_version']:
            unmatched += 1
            gaps.append('default branch fallback')
        if revision_valid and revision.get('source_warnings'):
            gaps.append('source coverage warning')
        if revision_valid and status.get('scan_outcome') == 'success':
            try:
                rows = trivy_findings(directory, 'results.json')
                available += 1
                source_count = str(len(rows))
                priority.extend(dict(row, repo=target.repo, scanner='Trivy source') for row in rows)
                diagnostics = available_report(directory / 'diagnostics.json')
                if not diagnostics.get('available') or diagnostics.get('errors'):
                    gaps.append('Trivy source errors or missing diagnostics')
                if diagnostics.get('dependency_files') == 0:
                    notes.append('Trivy detected no dependency files')
            except (OSError, ValueError, TypeError, AttributeError):
                gaps.append('Trivy source report invalid')
        else:
            gaps.append('Trivy source unavailable')

        if not target.image:
            notes.append('image not configured')
        elif (identity and status.get('image') == target.image and status.get('platform') == target.platform
              and status.get('image_outcome') == 'success'):
            try:
                rows = trivy_findings(directory, 'image-results.json')
                image_count = str(len(rows))
                priority.extend(dict(row, repo=target.repo, scanner='Trivy image') for row in rows)
                log = (directory / 'image-scan.log').read_text(encoding='utf-8', errors='replace')
                if scan_diagnostics(log)['errors']:
                    gaps.append('Trivy image scanner errors')
            except (OSError, ValueError, TypeError, AttributeError):
                gaps.append('Trivy image report or diagnostics unavailable')
            if '@sha256:' not in target.image:
                notes.append('mutable image tag')
        else:
            gaps.append('Trivy image unavailable')

        semgrep = available_report(directory / 'semgrep.json') if identity else {}
        if status.get('semgrep_outcome') != 'success' or semgrep.get('scanner') != 'semgrep' or not isinstance(semgrep.get('findings'), list):
            gaps.append('Semgrep unavailable')
        else:
            if semgrep.get('errors') or semgrep.get('skipped_files') or semgrep.get('skipped_rules'):
                gaps.append('Semgrep partial')
            if semgrep.get('skipped_files') is None:
                unknown_semgrep += 1
            errors = sum(str(row.get('severity')).upper() == 'ERROR' for row in semgrep['findings'])
            if errors:
                notes.append(f'{errors} Semgrep ERROR results')

        specialized = available_report(directory / 'specialized.json') if identity else {}
        if (status.get('specialized_outcome') != 'success' or specialized.get('scanner') != 'specialized'
                or not isinstance(specialized.get('findings'), list)):
            gaps.append('specialized scans unavailable')
        else:
            for entry in specialized.get('coverage', []):
                if entry.get('status') in {'incomplete', 'partial'}:
                    scanner = str(entry.get('scanner', 'scanner'))
                    detail = str(entry.get('detail', ''))
                    issue = 'timed out' if 'timed out' in detail.lower() or 'TimeoutExpired' in detail else entry['status']
                    gaps.append(f'{scanner} {issue}')
            rows = specialized['findings']
            unrated = sum(row.get('scanner') == 'OSV-Scanner' and str(row.get('severity', '')).upper() in {'ADVISORY', 'UNRATED', ''} for row in rows)
            if unrated:
                notes.append(f'{unrated} unrated OSV entries')
            selected = grouped_findings([row for row in rows if priority_severity(row.get('severity'))])
            other_count = str(len(selected))
            for row in selected:
                path = str(row.get('path') or '—')
                fixed = row.get('fixed') or []
                priority.append({
                    'repo': target.repo, 'scanner': str(row.get('scanner', 'specialized')),
                    'severity': priority_severity(row.get('severity')), 'id': str(row.get('rule', 'unknown')),
                    'title': str(row.get('description') or 'See rule identifier'),
                    'package': str(row.get('package') or path), 'target': path,
                    'installed': str(row.get('version') or '—'), 'fixed': ', '.join(fixed) or '—',
                    'url': str(row.get('url') or ''),
                })
        expected_sarif: set[str] = set()
        if source_count != '—':
            expected_sarif.add('results.sarif')
        if image_count != '—':
            expected_sarif.add('image-results.sarif')
        if semgrep.get('scanner') == 'semgrep' and status.get('semgrep_outcome') == 'success':
            expected_sarif.add('semgrep.sarif')
        for entry in specialized.get('coverage', []):
            if entry.get('status') in {'completed', 'partial'}:
                filename = {'OSV-Scanner': 'osv.sarif', 'Bandit': 'bandit.sarif'}.get(entry.get('scanner'))
                if filename:
                    expected_sarif.add(filename)
        missing = sorted(name for name in expected_sarif if not (directory / name).is_file())
        if missing:
            notes.append('SARIF missing: ' + ', '.join(missing))
        if gaps:
            partial += 1
        coverage = '**' + cell(', '.join(gaps)) + '**' if gaps else 'Scans reported'
        if notes:
            coverage += ' · ' + cell(', '.join(notes))
        sarif = ', '.join(name.removesuffix('.sarif') for name in SARIF_FILES if (directory / name).is_file())
        overview.append(f'| {cell(target.repo)} | {cell(target.version)} | {coverage} | {source_count} | {image_count} | {other_count} | {sarif or "—"} |')

    heading = (f'# Combined scan report\n\n'
               f'**{available}/{len(targets)} Trivy source reports available. '
               f'{partial} targets have coverage gaps, including {unmatched} source version fallbacks.**\n\n')
    if unknown_semgrep:
        heading += f'Semgrep skipped-file counts unavailable for {unknown_semgrep} targets.\n\n'
    counts = Counter(row['severity'] for row in priority)
    heading += (f'**{counts["CRITICAL"]} critical and {counts["HIGH"]} high finding rows** across available scans. '
                'A vulnerability can appear in more than one scanner, package, or image. '
                'Semgrep ERROR and unrated OSV advisories use separate labels.\n\n')
    table = ('## Repository coverage\n\n'
             'Counts are high and critical rows. A dash means unavailable or inapplicable.\n\n'
             '| Repository | Requested version | Coverage and notes | Source | Image | Other | SARIF |\n'
             '| --- | --- | --- | ---: | ---: | ---: | --- |\n')
    return heading + kev_section(targets, artifacts, catalog_path) + priority_table(priority) + table + '\n'.join(overview or ['| No targets configured | — | — | — | — | — | — |']) + '\n'


def summary_excerpt(report: str, byte_limit: int = 900_000) -> str:
    encoded = report.encode('utf-8')
    if len(encoded) <= byte_limit:
        return report
    notice = '\n\n**Summary truncated. Download the combined report artifact for the complete report.**\n'
    excerpt = encoded[:byte_limit - len(notice.encode('utf-8'))].decode('utf-8', errors='ignore')
    return excerpt.rsplit('\n', 1)[0] + notice
