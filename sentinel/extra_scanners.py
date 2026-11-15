"""Normalize scanner output without retaining matched source or secret values."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import quote
from typing import Any

from sentinel.scanner import cell, priority_severity, short_description


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
    if scanner != 'semgrep':
        raise ValueError(f'Unsupported scanner: {scanner}')
    report = normalize_semgrep(raw)
    destination.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')



def dependency_scope(path: str) -> str:
    """Classify only clear development/test paths; otherwise make no runtime claim."""
    parts = path.lower().replace('\\', '/').split('/')
    filename = parts[-1]
    if any(part in {'test', 'tests', 'testing', 'dev', 'development', 'docs', 'examples'} for part in parts[:-1]):
        return 'development/test'
    if re.search(r'(^|[._-])(dev|test|testing|docs)([._-]|$)', filename):
        return 'development/test'
    return 'unclassified'


def grouped_findings(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge OSV aliases only for the same package, version and source path."""
    output: list[dict[str, Any]] = []
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for item in rows:
        if item.get('scanner') != 'OSV-Scanner' or not item.get('package') or not item.get('version'):
            output.append(dict(item))
            continue
        key = tuple(str(item.get(field, '')).lower() for field in ('ecosystem', 'package', 'version', 'path'))
        ids = {str(item.get('rule', '')).upper(), *(str(a).upper() for a in item.get('aliases', []) if isinstance(a, str))}
        matches = [group for group in groups.get(key, []) if ids & group['_ids']]
        if matches:
            group = matches[0]
            group['_ids'].update(ids)
            for other in matches[1:]:
                group['_ids'].update(other['_ids'])
                group['_rules'].update(other['_rules'])
                groups[key].remove(other)
                output.remove(other)
            group['_rules'].add(str(item.get('rule', '')))
        else:
            group = dict(item, _ids=ids, _rules={str(item.get('rule', ''))})
            groups.setdefault(key, []).append(group)
            output.append(group)
    for item in output:
        if '_rules' in item:
            rules = sorted(item.pop('_rules'))
            item.pop('_ids')
            if len(rules) > 1:
                item['description'] = str(item.get('description', '')) + '; grouped advisories: ' + ', '.join(rules)
    return output

def render_extra(name: str, status: str, report: dict[str, Any] | None, limit: int = 12) -> str:
    if status != 'success' or report is None:
        return f'### {name}\n\n**Incomplete or unavailable.** Check the scanner job logs.\n'
    rows = report.get('findings')
    if report.get('scanner') != name.lower() or not isinstance(rows, list):
        raise ValueError(f'Invalid {name} report')
    message = f'### {name}\n\n'
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
    if name.lower() == 'semgrep':
        display_rows = [item for item in rows if str(item.get('severity')).upper() == 'ERROR']
        message += f'\n\n**{len(display_rows)} Semgrep ERROR results.**'
        hidden = len(rows) - len(display_rows)
    else:
        high_rows = [item for item in rows if priority_severity(item.get('severity'))]
        display_rows = grouped_findings(high_rows)
        display_rows.sort(key=lambda item: (item['severity'].upper() != 'CRITICAL', dependency_scope(str(item.get('path', ''))) == 'development/test'))
        unrated = sum(item.get('scanner') == 'OSV-Scanner' and str(item.get('severity', '')).upper() in {'UNRATED', 'ADVISORY', ''} for item in rows)
        message += f'\n\n**{len(display_rows)} high or critical results after alias grouping.** {unrated} OSV advisory entries without a severity label.'
        hidden = len(rows) - len(display_rows)
    if hidden:
        message += f' {hidden} additional entries in the JSON artifact.'
    if display_rows:
        message += '\n\n| Scanner | Rule | Finding | Location | Severity |\n| --- | --- | --- | --- | --- |\n'
        for item in display_rows[:limit]:
            line = item.get('line') or '—'
            revision = f" @ {str(item['commit'])[:12]}" if item.get('commit') else ''
            rule = cell(short_description(str(item.get('rule') or 'unknown')))
            url = str(item.get('url') or '')
            if url.startswith(('https://osv.dev/vulnerability/', 'https://github.com/hadolint/hadolint/wiki/')) and not re.search(r'[\s()<>]', url):
                rule = f'[{rule}]({quote(url, safe=":/#?&=%._~-+;")})'
            description = str(item.get('description') or 'See rule identifier')
            if item.get('scanner') == 'OSV-Scanner':
                description += '; scope: ' + dependency_scope(str(item.get('path') or ''))
            fixed = item.get('fixed')
            if isinstance(fixed, list) and fixed:
                description += '; advisory fixed version(s): ' + ', '.join(str(x) for x in fixed)
            message += f"| {cell(str(item.get('scanner') or name))} | {rule} | {cell(short_description(description))} | {cell(short_description(str(item.get('path') or 'unknown')))}:{cell(str(line))}{cell(revision)} | {cell(str(item.get('severity') or 'not rated'))} |\n"
        if len(display_rows) > limit:
            message += f'\nShowing {limit} of {len(display_rows)} displayed findings; see the JSON artifact.\n'
    return message + '\n'
