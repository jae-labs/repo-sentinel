"""Aggregate findings and scanner coverage."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from sentinel.extra_scanners import dependency_scope
from sentinel.kev import finding_cves, kev_section
from sentinel.reports import parse_semgrep, parse_specialized, valid_trivy_report
from sentinel.scanner import Target, cell, findings, priority_severity, scan_diagnostics, short_description

PRIORITY_LIMIT_PER_SEVERITY = 8
EVIDENCE_ORDER = {'Image': 0, 'Source': 1, 'Dev/test': 2}
SARIF_FILES = ('results.sarif', 'image-results.sarif', 'semgrep.sarif', 'osv.sarif', 'bandit.sarif')


@dataclass(frozen=True)
class AggregateResult:
    markdown: str
    incomplete_targets: int


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ValueError(f'{path.name} must contain an object')
    return value


def available_report(path: Path) -> dict[str, Any]:
    try:
        return read_object(path)
    except OSError, ValueError:
        return {}


def trivy_findings(directory: Path, filename: str) -> list[dict[str, str]]:
    report = read_object(directory / filename)
    if not valid_trivy_report(report):
        raise ValueError('Invalid Trivy report')
    return findings(report)


def group_priorities(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Group advisories by repository and evidence, and rules by file."""
    groups: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        evidence = 'Image' if row['scanner'] == 'Trivy image' else 'Source'
        if evidence == 'Source' and dependency_scope(row['target']) == 'development/test':
            evidence = 'Dev/test'
        key: tuple[str, ...]
        if row['kind'] == 'advisory':
            key = row['repo'], evidence, 'advisory', row.get('advisory_key', row['id']).upper()
        else:
            key = row['repo'], evidence, 'rule', row['scanner'], row['id'], row['target']
        groups[key].append(row)

    grouped = []
    for key, matches in groups.items():
        representative = min(matches, key=lambda row: (row['severity'] != 'CRITICAL', row['fixed'] == '—'))
        variants = {(row['package'], row['installed'], row['fixed']) for row in matches}
        package = representative['package']
        if len(variants) > 1:
            package += f' (+{len(variants) - 1})'
        grouped.append(dict(representative, evidence=key[1], package=package))
    return grouped


def priority_table(rows: list[dict[str, str]]) -> str:
    if not rows:
        return '## Critical and high findings\n\nNo critical or high findings reported.\n\n'
    ordered = sorted(
        rows,
        key=lambda row: (
            row['severity'] != 'CRITICAL',
            EVIDENCE_ORDER[row['evidence']],
            row['repo'],
            row['id'],
            row['package'],
        ),
    )
    selected: list[dict[str, str]] = []
    per_target: Counter[tuple[str, str]] = Counter()
    per_severity: Counter[str] = Counter()
    for row in ordered:
        severity = row['severity']
        key = row['repo'], severity
        if per_target[key] < 2 and per_severity[severity] < PRIORITY_LIMIT_PER_SEVERITY:
            selected.append(row)
            per_target[key] += 1
            per_severity[severity] += 1
    lines = [
        '## Critical and high findings',
        '',
        f'Showing {len(selected)} of {len(rows)} grouped findings. See scan artifacts for details.',
        '',
        '| Severity | Repository | Evidence | Advisory or rule | Finding | Package or file | Version → fix |',
        '| --- | --- | --- | --- | --- | --- | --- |',
    ]
    for row in selected:
        advisory = cell(row['id'])
        url = row.get('url', '')
        if url.startswith('https://') and not any(c.isspace() for c in url):
            advisory = f'[{advisory}]({quote(url, safe=":/#?&=%._~-+;")})'
        fields = (row['severity'], row['repo'], row['evidence'])
        location = cell(short_description(row['package'], 100))
        version = cell(short_description(row['installed'] + ' → ' + row['fixed'], 120))
        lines.append(
            '| '
            + ' | '.join(
                [*(cell(c) for c in fields), advisory, cell(short_description(row['title'], 150)), location, version]
            )
            + ' |'
        )
    return '\n'.join(lines) + '\n\n'


def aggregate_reports(targets: list[Target], artifacts: Path, catalog_path: Path | None = None) -> AggregateResult:
    if not targets:
        return AggregateResult('# Combined scan report\n\nNo targets configured.\n', 0)

    overview: list[str] = []
    priority: list[dict[str, str]] = []
    available = partial = unmatched = unknown_semgrep = incomplete = 0
    for index, target in enumerate(targets):
        directory = artifacts / f'scan-{index}'
        status = available_report(directory / 'status.json')
        revision = available_report(directory / 'revision.json')
        identity = status.get('repository') == target.repo and status.get('version') == target.version
        revision_valid = (
            identity
            and status.get('clone_outcome') == 'success'
            and revision.get('repository') == target.repo
            and revision.get('requested_version') == target.version
            and bool(revision.get('commit'))
            and isinstance(revision.get('matched_version'), bool)
            and (
                not target.source_commit or (revision['matched_version'] and revision['commit'] == target.source_commit)
            )
        )
        gaps: list[str] = []
        missing_reports: list[str] = []
        notes: list[str] = []
        source_count = image_count = other_count = '—'
        if not revision_valid:
            missing_reports.append('revision unavailable')
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
                if diagnostics.get('available') is not True:
                    missing_reports.append('Trivy source diagnostics unavailable')
                elif diagnostics.get('errors'):
                    gaps.append('Trivy source scanner errors')
                if diagnostics.get('dependency_files') == 0:
                    notes.append('Trivy detected no dependency files')
            except OSError, ValueError, TypeError, AttributeError:
                missing_reports.append('Trivy source report missing or invalid')
        else:
            missing_reports.append('Trivy source unavailable')

        if (
            target.image
            and identity
            and status.get('image') == target.image
            and status.get('platform') == target.platform
            and status.get('image_outcome') == 'success'
        ):
            try:
                rows = trivy_findings(directory, 'image-results.json')
                image_count = str(len(rows))
                priority.extend(dict(row, repo=target.repo, scanner='Trivy image') for row in rows)
                log = (directory / 'image-scan.log').read_text(encoding='utf-8', errors='replace')
                if scan_diagnostics(log)['errors']:
                    gaps.append('Trivy image scanner errors')
            except OSError, ValueError, TypeError, AttributeError:
                missing_reports.append('Trivy image report or diagnostics unavailable')
            if '@sha256:' not in target.image:
                notes.append('mutable image tag')
        elif target.image:
            missing_reports.append('Trivy image unavailable')

        source_eligible = identity and (not target.source_commit or revision_valid)
        semgrep = parse_semgrep(available_report(directory / 'semgrep.json')) if source_eligible else None
        if status.get('semgrep_outcome') != 'success' or semgrep is None:
            missing_reports.append('Semgrep unavailable')
        else:
            if semgrep.get('errors') or semgrep.get('skipped_files') or semgrep.get('skipped_rules'):
                gaps.append('Semgrep partial')
            if semgrep.get('skipped_files') is None:
                unknown_semgrep += 1
            errors = sum(str(row.get('severity')).upper() == 'ERROR' for row in semgrep['findings'])
            if errors:
                notes.append(f'{errors} Semgrep ERROR results')

        specialized = parse_specialized(available_report(directory / 'specialized.json')) if source_eligible else None
        if status.get('specialized_outcome') != 'success' or specialized is None:
            missing_reports.append('specialized scans unavailable')
        else:
            for entry in specialized['coverage']:
                if entry['status'] in {'incomplete', 'partial'}:
                    scanner = entry['scanner']
                    detail = entry['detail']
                    issue = (
                        'timed out' if 'timed out' in detail.lower() or 'TimeoutExpired' in detail else entry['status']
                    )
                    (missing_reports if entry['status'] == 'incomplete' else gaps).append(f'{scanner} {issue}')
                if entry.get('scanner') == 'OSV-Scanner' and entry.get('transitive_resolution') is False:
                    gaps.append('OSV transitive resolution disabled')
            specialized_findings = specialized['findings']
            unrated = sum(
                row.get('scanner') == 'OSV-Scanner'
                and str(row.get('severity', '')).upper() in {'ADVISORY', 'UNRATED', ''}
                for row in specialized_findings
            )
            if unrated:
                notes.append(f'{unrated} unrated OSV entries')
            selected = [row for row in specialized_findings if priority_severity(row['severity'])]
            other_count = str(len(selected))
            for item in selected:
                path = item['path'] or '—'
                rule = item['rule'] or 'unknown'
                cves = finding_cves([rule, *item.get('aliases', [])])
                priority.append(
                    {
                        'repo': target.repo,
                        'scanner': item.get('scanner', 'specialized'),
                        'severity': priority_severity(item['severity']),
                        'id': rule,
                        'kind': 'advisory' if item.get('scanner') == 'OSV-Scanner' else 'rule',
                        'advisory_key': next(iter(cves)) if len(cves) == 1 else rule,
                        'title': item.get('description') or 'See advisory or rule',
                        'package': item.get('package') or path,
                        'target': path,
                        'installed': item.get('version') or '—',
                        'fixed': ', '.join(item.get('fixed', [])) or '—',
                        'url': item.get('url', ''),
                    }
                )
        expected_sarif: set[str] = set()
        if source_count != '—':
            expected_sarif.add('results.sarif')
        if image_count != '—':
            expected_sarif.add('image-results.sarif')
        if semgrep is not None and status.get('semgrep_outcome') == 'success':
            expected_sarif.add('semgrep.sarif')
        for entry in specialized['coverage'] if specialized is not None else []:
            if entry.get('status') in {'completed', 'partial'}:
                filename = {'OSV-Scanner': 'osv.sarif', 'Bandit': 'bandit.sarif'}.get(entry.get('scanner'))
                if filename:
                    expected_sarif.add(filename)
        missing = sorted(name for name in expected_sarif if not (directory / name).is_file())
        if missing:
            notes.append('SARIF missing: ' + ', '.join(missing))
        if missing_reports:
            incomplete += 1
        gaps = missing_reports + gaps
        if gaps:
            partial += 1
        coverage = '**' + cell(', '.join(gaps)) + '**' if gaps else 'Scans reported'
        if notes:
            coverage += ' · ' + cell(', '.join(notes))
        artifact = f'`scan-{index}`' if directory.is_dir() else '—'
        overview.append(
            f'| {cell(target.repo)} | {cell(target.version)} | {coverage} | {source_count} | {image_count} | {other_count} | {artifact} |'
        )

    priority = group_priorities(priority)
    counts = Counter(row['severity'] for row in priority)
    heading = (
        f'# Combined scan report\n\n'
        f'**{counts["CRITICAL"]} critical and {counts["HIGH"]} high grouped findings**\n\n'
        f'{available}/{len(targets)} Trivy source reports · {partial} targets with coverage gaps '
        f'· default branch used for {unmatched}\n\n'
    )
    if incomplete:
        heading += f'**{incomplete}/{len(targets)} target scans incomplete.**\n\n'
    table = (
        '<details>\n<summary>Repository coverage</summary>\n\n'
        'Counts show critical and high scanner records. A dash indicates no report.\n\n'
    )
    if unknown_semgrep:
        table += f'Semgrep skip counts unavailable for {unknown_semgrep} targets.\n\n'
    table += (
        '| Repository | Version | Coverage | Source | Image | Other | Artifact |\n'
        '| --- | --- | --- | ---: | ---: | ---: | --- |\n'
    )
    markdown = (
        heading
        + kev_section(targets, artifacts, catalog_path)
        + priority_table(priority)
        + table
        + '\n'.join(overview)
        + '\n\n</details>\n'
    )
    return AggregateResult(markdown, incomplete)


def combined_report(targets: list[Target], artifacts: Path, catalog_path: Path | None = None) -> str:
    return aggregate_reports(targets, artifacts, catalog_path).markdown


def summary_excerpt(report: str, byte_limit: int = 900_000) -> str:
    encoded = report.encode('utf-8')
    if len(encoded) <= byte_limit:
        return report
    notice = '\n\n**Summary truncated. Download the combined report artifact for the complete report.**\n'
    excerpt = encoded[: byte_limit - len(notice.encode('utf-8'))].decode('utf-8', errors='ignore')
    return excerpt.rsplit('\n', 1)[0] + notice
