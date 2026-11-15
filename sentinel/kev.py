"""Correlate available scanner results with CISA's known-exploited catalog."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

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
    except (OSError, ValueError, TypeError):
        return heading + '**CISA catalog unavailable or invalid. Exploitation status is unknown.**\n\n'
    matches: dict[tuple[str, str], set[str]] = defaultdict(set)
    for index, target in enumerate(targets):
        directory = artifacts / f'scan-{index}'
        try:
            status = json.loads((directory / 'status.json').read_text(encoding='utf-8'))
            if not isinstance(status, dict) or status.get('repository') != target.repo or status.get('version') != target.version:
                continue
        except (OSError, ValueError):
            continue
        for filename, outcome, scanner in (('results.json', 'scan_outcome', 'Trivy'), ('image-results.json', 'image_outcome', 'Trivy image')):
            if status.get(outcome) != 'success':
                continue
            if scanner == 'Trivy image' and (status.get('image') != target.image or status.get('platform') != target.platform):
                continue
            try:
                report = json.loads((directory / filename).read_text(encoding='utf-8'))
                if report.get('SchemaVersion') != 2 or not isinstance(report.get('Results', []), list):
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
                            matches[(target.repo, cve)].add(scanner)
            except (OSError, ValueError, TypeError, AttributeError):
                continue
        if status.get('specialized_outcome') == 'success':
            try:
                report = json.loads((directory / 'specialized.json').read_text(encoding='utf-8'))
                if report.get('scanner') != 'specialized' or not isinstance(report.get('findings'), list):
                    continue
                for item in report['findings']:
                    if item.get('scanner') != 'OSV-Scanner':
                        continue
                    aliases = item.get('aliases') if isinstance(item.get('aliases'), list) else []
                    for cve in finding_cves([item.get('rule'), *aliases]) & catalog.keys():
                        matches[(target.repo, cve)].add('OSV-Scanner')
            except (OSError, ValueError, TypeError, AttributeError):
                continue
    text = heading + f'[CISA catalog]({CATALOG_URL}) released {cell(released)}. '
    text += 'Matches identify known exploitation in the wild; they do not establish exploitation or applicability in your environment. '
    text += 'Only available findings with CVE identifiers or aliases are matched; missing results or aliases limit coverage.\n\n'
    if not matches:
        return text + '**No CISA matches in the available findings.**\n\n'
    text += f'**{len(matches)} repository/CVE match(es).**\n\n| Repository | CVE | Scanner(s) | CISA date added |\n| --- | --- | --- | --- |\n'
    for (repo, cve), scanners in sorted(matches.items()):
        added = str(catalog[cve].get('dateAdded') or 'unknown')
        text += f'| {cell(repo)} | [{cve}](https://www.cve.org/CVERecord?id={cve}) | {cell(", ".join(sorted(scanners)))} | {cell(added)} |\n'
    return text + '\n'
