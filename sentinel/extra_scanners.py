"""Normalize scanner output without retaining matched source or secret values."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import quote
from typing import Any

from sentinel.scanner import cell, short_description


def normalize_gitleaks(raw: Any, scanner: str = 'gitleaks') -> dict[str, Any]:
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ValueError('Gitleaks report must be an array')
    results = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError('Invalid Gitleaks finding')
        commit = str(item.get('Commit') or '')
        if not re.fullmatch(r'[0-9a-fA-F]{40,64}', commit):
            commit = ''
        results.append({'rule': str(item.get('RuleID') or 'unknown'), 'path': str(item.get('File') or 'unknown'), 'line': item.get('StartLine'), 'commit': commit})
    return {'scanner': scanner, 'findings': results}


def normalize_semgrep(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get('results'), list) or not isinstance(raw.get('errors'), list):
        raise ValueError('Invalid Semgrep report')
    results = []
    for item in raw['results']:
        if not isinstance(item, dict):
            raise ValueError('Invalid Semgrep finding')
        extra = item.get('extra') or {}
        start = item.get('start') or {}
        rule_id = str(item.get('check_id') or 'unknown')
        rule_title = re.sub(r'[^A-Za-z0-9_-]', '', rule_id.rsplit('.', 1)[-1]).replace('-', ' ').replace('_', ' ')
        results.append({'rule': rule_id, 'description': rule_title or 'See rule identifier', 'path': str(item.get('path') or 'unknown'), 'line': start.get('line'), 'severity': str(extra.get('severity') or 'UNKNOWN')})
    # Messages and source snippets can interpolate sensitive values; do not persist them.
    paths = raw.get('paths') or {}
    scanned = paths.get('scanned') if isinstance(paths, dict) else None
    skipped = paths.get('skipped') if isinstance(paths, dict) else None
    skipped_rules = raw.get('skipped_rules')
    return {'scanner': 'semgrep', 'findings': results, 'errors': len(raw['errors']), 'scanned_files': len(scanned) if isinstance(scanned, list) else None, 'skipped_files': len(skipped) if isinstance(skipped, list) else None, 'skipped_rules': len(skipped_rules) if isinstance(skipped_rules, list) else None}


def normalize_file(scanner: str, source: Path, destination: Path) -> None:
    raw = json.loads(source.read_text(encoding='utf-8'))
    report = normalize_gitleaks(raw, scanner) if scanner in ('gitleaks', 'gitleaks_history') else normalize_semgrep(raw)
    destination.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


def render_extra(name: str, status: str, report: dict[str, Any] | None, limit: int = 200) -> str:
    if status != 'success' or report is None:
        return f'### {name}\n\n**Incomplete or unavailable.** Check the scanner job logs.\n'
    rows = report.get('findings')
    if report.get('scanner') != name.lower() or not isinstance(rows, list):
        raise ValueError(f'Invalid {name} report')
    message = f'### {name}\n\n**{len(rows)} finding(s).**'
    if name.lower() == 'specialized':
        for entry in report.get('coverage', []):
            message += f"\n- **{cell(str(entry.get('scanner', 'unknown')))}:** {cell(str(entry.get('status', 'unknown')))} — {cell(str(entry.get('detail', '')))}"
        if report.get('coverage'):
            message += '\n'
    if name.lower() == 'semgrep':
        for key, label in (('scanned_files', 'files scanned'), ('skipped_files', 'files skipped'), ('skipped_rules', 'rules skipped')):
            count = report.get(key)
            message += f" {label}: {count if count is not None else 'unknown'}."
    if report.get('errors'):
        message += f" **Partial: {report['errors']} scanner error(s).**"
    if rows:
        message += '\n\n| Scanner | Rule | Finding | Location | Severity |\n| --- | --- | --- | --- | --- |\n'
        for item in rows[:limit]:
            line = item.get('line') or '—'
            revision = f" @ {str(item['commit'])[:12]}" if item.get('commit') else ''
            rule = cell(short_description(str(item.get('rule') or 'unknown')))
            url = str(item.get('url') or '')
            if url.startswith(('https://osv.dev/vulnerability/', 'https://github.com/hadolint/hadolint/wiki/')) and not re.search(r'[\s()<>]', url):
                rule = f'[{rule}]({quote(url, safe=":/#?&=%._~-+;")})'
            description = str(item.get('description') or 'See rule identifier')
            fixed = item.get('fixed')
            if isinstance(fixed, list) and fixed:
                description += '; advisory fixed version(s): ' + ', '.join(str(x) for x in fixed)
            message += f"| {cell(str(item.get('scanner') or name))} | {rule} | {cell(short_description(description))} | {cell(short_description(str(item.get('path') or 'unknown')))}:{cell(str(line))}{cell(revision)} | {cell(str(item.get('severity') or 'not rated'))} |\n"
        if len(rows) > limit:
            message += f'\nShowing {limit} of {len(rows)} findings; see the JSON artifact.\n'
    return message + '\n'
