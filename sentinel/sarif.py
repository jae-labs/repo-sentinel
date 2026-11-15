"""Produce a conservative SARIF artifact without scanner-provided source text."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

SAFE_ID = re.compile(r'[A-Za-z0-9_.:/+-]{1,250}\Z')


def sanitized_sarif(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get('version') != '2.1.0' or not isinstance(value.get('runs'), list):
        raise ValueError('Invalid SARIF 2.1.0 document')
    runs = []
    for run in value['runs']:
        if not isinstance(run, dict) or not isinstance(run.get('results', []), list):
            raise ValueError('Invalid SARIF run')
        tool = (run.get('tool') or {}).get('driver') or {}
        name = str(tool.get('name') or 'scanner')
        if not SAFE_ID.fullmatch(name):
            name = 'scanner'
        source_rules = tool.get('rules') if isinstance(tool.get('rules'), list) else []
        rules: dict[str, dict[str, str]] = {}
        results: list[dict[str, Any]] = []
        for item in run.get('results', []):
            if not isinstance(item, dict):
                raise ValueError('Invalid SARIF result')
            rule = item.get('ruleId')
            index = item.get('ruleIndex')
            if not rule and isinstance(index, int) and 0 <= index < len(source_rules) and isinstance(source_rules[index], dict):
                rule = source_rules[index].get('id')
            rule = str(rule or 'unknown')
            if not SAFE_ID.fullmatch(rule):
                rule = 'unknown'
            rules[rule] = {'id': rule}
            result: dict[str, Any] = {'ruleId': rule, 'message': {'text': f'Finding {rule}; see the scanner report for details.'}}
            if item.get('level') in ('error', 'warning', 'note', 'none'):
                result['level'] = item['level']
            locations = []
            for location in item.get('locations') or []:
                if not isinstance(location, dict):
                    continue
                physical = location.get('physicalLocation') or {}
                if not isinstance(physical, dict):
                    continue
                artifact = physical.get('artifactLocation') or {}
                if not isinstance(artifact, dict):
                    continue
                uri = unquote(str(artifact.get('uri') or '')).replace('\\', '/')
                if '/target/' in uri:
                    uri = uri.split('/target/', 1)[1]
                elif uri.startswith('target/'):
                    uri = uri[7:]
                elif uri.startswith('/') or '://' in uri:
                    continue
                if not uri or any(part in ('', '.', '..') for part in uri.split('/')) or not re.fullmatch(r'[A-Za-z0-9_./+@-]+', uri):
                    continue
                out: dict[str, Any] = {'artifactLocation': {'uri': uri}}
                region = physical.get('region') or {}
                if isinstance(region, dict) and isinstance(region.get('startLine'), int) and not isinstance(region['startLine'], bool) and region['startLine'] > 0:
                    out['region'] = {'startLine': region['startLine']}
                locations.append({'physicalLocation': out})
            if locations:
                result['locations'] = locations
            results.append(result)
        runs.append({'tool': {'driver': {'name': name, 'rules': list(rules.values())}}, 'results': results})
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': runs}


def sanitize_file(source: Path, destination: Path) -> None:
    value = json.loads(source.read_text(encoding='utf-8'))
    destination.write_text(json.dumps(sanitized_sarif(value), indent=2) + '\n', encoding='utf-8')


def export_specialized_sarif(report: dict[str, Any], destination: Path) -> None:
    """Export existing normalized findings without executing a scanner again."""
    for scanner, filename in (('OSV-Scanner', 'osv.sarif'), ('Bandit', 'bandit.sarif')):
        coverage = next((entry for entry in report['coverage'] if entry['scanner'] == scanner), None)
        if not coverage or coverage['status'] not in {'completed', 'partial'}:
            continue
        rows = []
        for item in report['findings']:
            if item['scanner'] != scanner:
                continue
            path = str(item.get('path') or '').removeprefix('./')
            severity = str(item.get('severity') or '').upper()
            row: dict[str, Any] = {
                'ruleId': item['rule'],
                'locations': [{'physicalLocation': {
                    'artifactLocation': {'uri': path},
                    'region': {'startLine': item.get('line')},
                }}],
            }
            level = {'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning',
                     'MODERATE': 'warning', 'LOW': 'note'}.get(severity)
            row['level'] = level or 'none'
            rows.append(row)
        safe = sanitized_sarif({'version': '2.1.0', 'runs': [
            {'tool': {'driver': {'name': scanner}}, 'results': rows},
        ]})
        (destination / filename).write_text(json.dumps(safe, separators=(',', ':')) + '\n', encoding='utf-8')
