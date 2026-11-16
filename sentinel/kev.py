"""Match scanner findings against CISA KEV."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from sentinel.extra_scanners import dependency_scope
from sentinel.reports import parse_specialized, valid_trivy_report
from sentinel.scanner import Target, cell

CVE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
CATALOG_URL = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'


def load_catalog(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list) or not data['vulnerabilities']:
        raise ValueError('Invalid or empty CISA catalog')
    entries: dict[str, dict[str, Any]] = {}
    for entry in data['vulnerabilities']:
        if not isinstance(entry, dict) or not isinstance(entry.get('cveID'), str) or not CVE.fullmatch(entry['cveID']):
            raise ValueError('Invalid CISA catalog entry')
        entries[entry['cveID'].upper()] = entry
    if not isinstance(data.get('dateReleased'), str) or not data['dateReleased']:
        raise ValueError('Missing CISA catalog release date')
    return entries, data['dateReleased']


def finding_cves(identifiers: list[Any]) -> set[str]:
    return {value.upper() for value in identifiers if isinstance(value, str) and CVE.fullmatch(value)}


def kev_section(targets: list[Target], artifacts: Path, catalog_path: Path | None) -> str:
    heading = '## CISA known exploited vulnerabilities\n\n'
    try:
        if catalog_path is None:
            raise ValueError('No catalog configured')
        catalog, released = load_catalog(catalog_path)
    except OSError, ValueError, TypeError:
        return heading + '**CISA catalog unavailable.**\n\n'
    evidence: dict[tuple[str, str], set[tuple[str, str, str, str, str]]] = defaultdict(set)
    for index, target in enumerate(targets):
        directory = artifacts / f'scan-{index}'
        try:
            status = json.loads((directory / 'status.json').read_text(encoding='utf-8'))
            if (
                not isinstance(status, dict)
                or status.get('repository') != target.repo
                or status.get('version') != target.version
            ):
                continue
        except OSError, ValueError:
            continue
        pinned_source = True
        if target.source_commit:
            try:
                revision = json.loads((directory / 'revision.json').read_text(encoding='utf-8'))
                pinned_source = (
                    revision.get('repository') == target.repo
                    and revision.get('requested_version') == target.version
                    and revision.get('commit') == target.source_commit
                    and revision.get('matched_version') is True
                )
            except OSError, ValueError, AttributeError:
                pinned_source = False
        for filename, outcome, label in (
            ('results.json', 'scan_outcome', 'Source'),
            ('image-results.json', 'image_outcome', 'Image'),
        ):
            if status.get(outcome) != 'success':
                continue
            if label == 'Source' and not pinned_source:
                continue
            if label == 'Image' and (status.get('image') != target.image or status.get('platform') != target.platform):
                continue
            try:
                report = json.loads((directory / filename).read_text(encoding='utf-8'))
                if not isinstance(report, dict) or not valid_trivy_report(report):
                    continue
                for result in report.get('Results') or []:
                    for item in result.get('Vulnerabilities') or []:
                        if str(item.get('Severity', '')).upper() not in {'HIGH', 'CRITICAL'}:
                            continue
                        ids = [item.get('VulnerabilityID')]
                        for field in ('Aliases', 'CveIDs'):
                            if isinstance(item.get(field), list):
                                ids.extend(item[field])
                        for cve in finding_cves(ids) & catalog.keys():
                            evidence[(target.repo, cve)].add(
                                (
                                    label,
                                    str(result.get('Target') or '—'),
                                    str(item.get('PkgName') or '—'),
                                    str(item.get('InstalledVersion') or '—'),
                                    str(item.get('FixedVersion') or '—'),
                                )
                            )
            except OSError, ValueError, TypeError, AttributeError:
                continue
        if pinned_source and status.get('specialized_outcome') == 'success':
            try:
                raw = json.loads((directory / 'specialized.json').read_text(encoding='utf-8'))
                specialized = parse_specialized(raw) if isinstance(raw, dict) else None
                if specialized is None:
                    continue
                for item in specialized['findings']:
                    if item.get('scanner') != 'OSV-Scanner':
                        continue
                    aliases = item.get('aliases', [])
                    for cve in finding_cves([item.get('rule'), *aliases]) & catalog.keys():
                        evidence[(target.repo, cve)].add(
                            (
                                'Source',
                                str(item.get('path') or '—'),
                                str(item.get('package') or '—'),
                                str(item.get('version') or '—'),
                                ', '.join(item.get('fixed', [])) or '—',
                            )
                        )
            except OSError, ValueError, TypeError, AttributeError:
                continue
    text = heading + f'[CISA catalog]({CATALOG_URL}) · {cell(released.partition("T")[0])}\n\n'
    if not evidence:
        return text + '**No CISA matches in the available findings.**\n\n'
    text += f'**Repository/CVE matches: {len(evidence)}**\n\n| Repository | CVE | Evidence | Package and version → fix |\n| --- | --- | --- | --- |\n'
    ordered = sorted(evidence, key=lambda key: (all(row[0] != 'Image' for row in evidence[key]), key))
    for repo, cve in ordered:
        packages_by_version: dict[tuple[str, str], set[str]] = defaultdict(set)
        sources = set()
        for label, source, package, version, fixed in evidence[(repo, cve)]:
            if package != '—':
                packages_by_version[version, fixed].add(package)
            location = source.split('/target/', 1)[-1].removeprefix('target/')
            if label == 'Source' and dependency_scope(location) == 'development/test':
                label = 'Dev/test'
            sources.add(label if location == '—' else f'{label} · {location}')
        packages = (
            '<br>'.join(
                cell(f'{", ".join(sorted(names))} {version} → {fixed}')
                for (version, fixed), names in sorted(packages_by_version.items())
            )
            or '—'
        )
        locations = '<br>'.join(cell(source) for source in sorted(sources))
        text += f'| {cell(repo)} | [{cve}](https://www.cve.org/CVERecord?id={cve}) | {locations} | {packages} |\n'
    return text + '\n'
