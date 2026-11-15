"""Combine scan artifacts without treating missing or invalid reports as clean."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from sentinel.extra_scanners import render_extra
from sentinel.kev import kev_section
from sentinel.scanner import Target, cell, diagnostics_summary, findings, render_summary


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ValueError(f'{path.name} must contain an object')
    return value


def combined_report(targets: list[Target], artifacts: Path, catalog_path: Path | None = None) -> str:
    overview: list[str] = []
    details: list[str] = []
    completed = failed = unmatched = partial = unknown_semgrep = no_dependencies = high = critical = 0
    scanner_counts: Counter[str] = Counter({'Trivy': 0, 'Trivy image': 0, 'semgrep': 0, 'OSV-Scanner': 0, 'Bandit': 0, 'Hadolint': 0})
    possible_duplicates = 0
    for index, target in enumerate(targets):
        directory = artifacts / f'scan-{index}'
        status: dict[str, Any] = {}
        try:
            status = read_object(directory / 'status.json')
            revision = read_object(directory / 'revision.json')
            report = read_object(directory / 'results.json')
            diagnostics = read_object(directory / 'diagnostics.json')
            if not isinstance(diagnostics.get('available'), bool) or not isinstance(diagnostics.get('errors'), list):
                raise ValueError('invalid diagnostics')
            if status.get('repository') != target.repo or status.get('version') != target.version:
                raise ValueError('status does not match inventory')
            if status.get('scan_outcome') != 'success' or status.get('clone_outcome') != 'success':
                raise ValueError('clone or scan did not succeed')
            if revision.get('repository') != target.repo or revision.get('requested_version') != target.version:
                raise ValueError('revision does not match inventory')
            if not isinstance(revision.get('matched_version'), bool) or not revision.get('commit'):
                raise ValueError('invalid revision metadata')
            if report.get('SchemaVersion') != 2 or not isinstance(report.get('Results', []), list):
                raise ValueError('invalid report results')
            rows = findings(report)
            scanner_counts['Trivy'] += len(rows)
            h = sum(row['severity'] == 'HIGH' for row in rows)
            c = sum(row['severity'] == 'CRITICAL' for row in rows)
            high += h
            critical += c
            completed += 1
            match = 'matched' if revision['matched_version'] else 'default branch (unmatched)'
            if not revision['matched_version']:
                unmatched += 1
            target_partial = bool(revision.get('source_warnings'))
            if target_partial:
                match += '; source coverage warning'
            if not diagnostics['available'] or diagnostics['errors']:
                target_partial = True
                match += '; partial/unknown diagnostics'
            if diagnostics.get('dependency_files') == 0:
                no_dependencies += 1
                match += '; no dependency files'
            elif diagnostics.get('dependency_files') is None:
                match += '; dependency coverage unknown'
            overview.append(f'| {cell(target.repo)} | {cell(target.version)} | {match} | {c} | {h} |')
            extra_sections = []
            for name in ('semgrep', 'specialized'):
                outcome = status.get(name + '_outcome', 'missing')
                valid_extra = True
                try:
                    extra = read_object(directory / (name + '.json'))
                    extra_sections.append(render_extra(name.title(), outcome, extra, limit=len(extra.get('findings', []))))
                    if outcome == 'success':
                        for item in extra.get('findings', []):
                            scanner_counts[str(item.get('scanner') or name)] += 1
                            if name == 'specialized' and item.get('scanner') == 'OSV-Scanner':
                                aliases = {str(item.get('rule', '')).lower(), *(str(a).lower() for a in item.get('aliases', []))}
                                if any(row['id'].lower() in aliases and row['package'].lower() == str(item.get('package', '')).lower() and row['installed'] == str(item.get('version', '')) for row in rows):
                                    possible_duplicates += 1
                    if name == 'semgrep' and extra.get('skipped_files') is None:
                        unknown_semgrep += 1
                        match += '; semgrep skipped-file coverage unknown'
                    if extra.get('errors') or extra.get('skipped_files') or extra.get('skipped_rules') or any(item.get('status') in ('partial', 'incomplete') for item in extra.get('coverage', [])):
                        target_partial = True
                        match += '; ' + name + ' partial'
                except (OSError, ValueError, TypeError, AttributeError):
                    valid_extra = False
                    extra_sections.append(render_extra(name.title(), 'failure', None))
                if outcome != 'success' or not valid_extra:
                    target_partial = True
                    match += '; ' + name + ' incomplete'
            if not target.image:
                match += '; image not configured'
                extra_sections.append('### Container image\n\nNot scanned: no image configured.\n')
            else:
                try:
                    image_report = read_object(directory / 'image-results.json')
                    if status.get('image') != target.image or status.get('platform') != target.platform or status.get('image_outcome') != 'success' or image_report.get('SchemaVersion') != 2:
                        raise ValueError('image scan incomplete')
                    image_rows = findings(image_report)
                    scanner_counts['Trivy image'] += len(image_rows)
                    metadata = image_report.get('Metadata') or {}
                    digests = metadata.get('RepoDigests') or []
                    resolved_image = ', '.join(str(digest) for digest in digests) if isinstance(digests, list) and digests else 'not provided by scanner'
                    extra_sections.append('Resolved image digest(s): ' + cell(resolved_image) + '. This does not prove the image matches a running deployment.\n')
                    image_log = directory / 'image-scan.log'
                    if not image_log.exists() or 'ERROR' in image_log.read_text(encoding='utf-8', errors='replace'):
                        target_partial = True
                        match += '; image scan diagnostics incomplete'
                    extra_sections.append('### Container image\n\n' + render_summary(target.image, target.platform or 'runner default platform', None, image_report, 'success', limit=len(image_rows)))
                    if '@sha256:' not in target.image:
                        match += '; image tag mutable'
                except (OSError, ValueError, TypeError, AttributeError):
                    target_partial = True
                    match += '; image scan incomplete'
                    extra_sections.append('### Container image\n\n**Image scan incomplete.**\n')
            if target_partial:
                partial += 1
            overview[-1] = f'| {cell(target.repo)} | {cell(target.version)} | {match} | {c} | {h} |'
            details.append(render_summary(target.repo, target.version, revision, report, 'success', limit=len(rows)) + '\n' + diagnostics_summary(diagnostics) + '\n' + '\n'.join(extra_sections))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            failed += 1
            overview.append(f'| {cell(target.repo)} | {cell(target.version)} | **Incomplete** | — | — |')
            detail = f'## {cell(target.repo)}\n\n**Trivy or target incomplete:** {cell(str(exc))}. Check the job logs and individual artifact.\n'
            try:
                status = read_object(directory / 'status.json')
                for name in ('semgrep', 'specialized'):
                    try:
                        extra = read_object(directory / (name + '.json'))
                    except (OSError, ValueError):
                        extra = None
                    outcome = status.get(name + '_outcome', 'missing')
                    detail += '\n' + render_extra(name.title(), outcome, extra)
                    if outcome == 'success' and extra:
                        for item in extra.get('findings', []):
                            scanner_counts[str(item.get('scanner') or name)] += 1
            except (OSError, ValueError):
                pass
            if target.image:
                try:
                    image_report = read_object(directory / 'image-results.json')
                    if status.get('image_outcome') != 'success' or image_report.get('SchemaVersion') != 2:
                        raise ValueError('image scan incomplete')
                    image_rows = findings(image_report)
                    scanner_counts['Trivy image'] += len(image_rows)
                    detail += '\n### Container image\n\n' + render_summary(target.image, target.platform or 'runner default platform', None, image_report, 'success', limit=len(image_rows))
                except (OSError, ValueError, TypeError, AttributeError, UnboundLocalError):
                    detail += '\n### Container image\n\n**Image scan incomplete.**\n'
            details.append(detail)
    heading = (f'# Combined scan report\n\n'
               f'**{completed}/{len(targets)} scan reports available; {failed} incomplete; '
               f'{unmatched} used an unmatched default branch; {partial} have partial scans or unavailable diagnostics; '
               f'{unknown_semgrep} have unknown Semgrep skipped-file coverage; {no_dependencies} detected no Trivy dependency files.**\n\n'
               f'**Trivy findings:** {critical} critical, {high} high. Counts are findings, not unique vulnerabilities.\n\n'
               f'**Findings by scanner:** {cell(", ".join(f"{name}: {count}" for name, count in sorted(scanner_counts.items())) or "none reported")}. '
               f'{possible_duplicates} potential Trivy/OSV duplicate(s) match by advisory, package and version; results are retained for review. '
               'Trivy counts include high and critical findings only; other scanners use their own severity scales. Counts include only available reports and do not prove missing scans were clean.\n\n'
               'Successful scanner execution does not guarantee complete coverage; inspect logs for scanner warnings or errors.\n\n'
               '| Repository | Requested version | Status | Trivy critical | Trivy high |\n'
               '| --- | --- | --- | ---: | ---: |\n')
    if not targets:
        heading += '| No targets configured | — | — | — | — |\n'
    return heading + '\n'.join(overview) + '\n\n' + kev_section(targets, artifacts, catalog_path) + '\n'.join(details)


def summary_excerpt(report: str, byte_limit: int = 900_000) -> str:
    encoded = report.encode('utf-8')
    if len(encoded) <= byte_limit:
        return report
    notice = '\n\n**Summary truncated. Download the combined report artifact for the complete report.**\n'
    excerpt = encoded[:byte_limit - len(notice.encode('utf-8'))].decode('utf-8', errors='ignore')
    return excerpt.rsplit('\n', 1)[0] + notice
