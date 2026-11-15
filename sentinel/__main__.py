"""GitHub Actions CLI."""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from sentinel.specialized import scan as specialized_scan
from sentinel.sarif import export_specialized_sarif, sanitize_file
from sentinel.extra_scanners import normalize_file, render_extra
from sentinel.aggregate import SARIF_FILES, combined_report, summary_excerpt
from sentinel.scanner import clone_target, diagnostics_summary, parse_inventory, render_summary, scan_diagnostics


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    inventory = sub.add_parser('inventory')
    inventory.add_argument('path', type=Path)
    sub.add_parser('clone')
    sub.add_parser('summary')
    specialized = sub.add_parser('specialized')
    specialized.add_argument('path', type=Path)
    normalize = sub.add_parser('normalize')
    normalize.add_argument('scanner', choices=['semgrep'])
    normalize.add_argument('source', type=Path)
    normalize.add_argument('destination', type=Path)
    sarif = sub.add_parser('sanitize-sarif')
    sarif.add_argument('source', type=Path)
    sarif.add_argument('destination', type=Path)
    export = sub.add_parser('export-specialized-sarif')
    export.add_argument('source', type=Path)
    aggregate = sub.add_parser('aggregate')
    aggregate.add_argument('inventory', type=Path)
    aggregate.add_argument('artifacts', type=Path)
    aggregate.add_argument('--cisa-catalog', type=Path)
    args = parser.parse_args()
    if args.command == 'inventory':
        targets = parse_inventory(json.loads(args.path.read_text(encoding='utf-8')))
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as out:
            print('targets=' + json.dumps([asdict(t) for t in targets], separators=(',', ':')), file=out)
            print('has_targets=' + str(bool(targets)).lower(), file=out)
    elif args.command == 'specialized':
        result = specialized_scan(args.path, resolve_osv=os.environ.get('OSV_RESOLVE') != 'false')
        Path('specialized.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        if any(entry['status'] in ('incomplete', 'partial') for entry in result['coverage']):
            print('::warning::Incomplete scanner coverage. See the scan report.')
    elif args.command == 'normalize':
        normalize_file(args.scanner, args.source, args.destination)
    elif args.command == 'sanitize-sarif':
        sanitize_file(args.source, args.destination)
    elif args.command == 'export-specialized-sarif':
        export_specialized_sarif(json.loads(args.source.read_text(encoding='utf-8')), Path('.'))
    elif args.command == 'clone':
        target = parse_inventory([{
            'repo': os.environ['TARGET_REPO'],
            'version': os.environ['TARGET_VERSION'],
            'source_commit': os.environ.get('SOURCE_COMMIT', ''),
        }])[0]
        revision = clone_target(target, Path('target'))
        Path('revision.json').write_text(json.dumps(revision, indent=2) + '\n', encoding='utf-8')
        if revision.get('source_warnings'):
            print('::warning::Source coverage warning. See the scan report.')
        if not revision['matched_version']:
            print(f'::warning::Requested version unavailable for {target.repo}. Scanning the default branch.')
    elif args.command == 'aggregate':
        targets = parse_inventory(json.loads(args.inventory.read_text(encoding='utf-8')))
        report = combined_report(targets, args.artifacts, args.cisa_catalog)
        Path('combined-report.md').write_text(report, encoding='utf-8')
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as out:
            out.write(summary_excerpt(report))
    else:
        Path('status.json').write_text(json.dumps({'repository': os.environ['TARGET_REPO'], 'version': os.environ['TARGET_VERSION'], 'clone_outcome': os.environ['CLONE_OUTCOME'], 'scan_outcome': os.environ['SCAN_OUTCOME'], 'semgrep_outcome': os.environ['SEMGREP_OUTCOME'], 'specialized_outcome': os.environ['SPECIALIZED_OUTCOME'], 'image_outcome': os.environ['IMAGE_OUTCOME'], 'image': os.environ['IMAGE_REF'], 'platform': os.environ['IMAGE_PLATFORM']}) + '\n', encoding='utf-8')
        revision_path, report_path = Path('revision.json'), Path('results.json')
        revision = json.loads(revision_path.read_text(encoding='utf-8')) if revision_path.exists() else None
        report = json.loads(report_path.read_text(encoding='utf-8')) if report_path.exists() else None
        log_path = Path('scan.log')
        diagnostics = scan_diagnostics(log_path.read_text(encoding='utf-8', errors='replace') if log_path.exists() else None)
        Path('diagnostics.json').write_text(json.dumps(diagnostics, indent=2) + '\n', encoding='utf-8')
        summary = render_summary(os.environ['TARGET_REPO'], os.environ['TARGET_VERSION'], revision, report, os.environ['SCAN_OUTCOME'])
        scanner_reports = {}
        for name in ('semgrep', 'specialized'):
            path = Path(name + '.json')
            scanner_reports[name] = json.loads(path.read_text(encoding='utf-8')) if path.exists() else None
        coverage_notes = []
        for name, scanner_report in scanner_reports.items():
            if os.environ[name.upper() + '_OUTCOME'] != 'success' or scanner_report is None:
                coverage_notes.append(f'{name.title()} report unavailable')
                continue
            if name == 'semgrep' and scanner_report.get('errors'):
                coverage_notes.append('Semgrep reported scan errors')
            for entry in scanner_report.get('coverage', []):
                if entry['status'] in ('incomplete', 'partial'):
                    coverage_notes.append(f"{entry['scanner']} {entry['status']}")
        if coverage_notes:
            summary = summary.replace('\n\n', '\n\n**Coverage needs review:** ' + ', '.join(coverage_notes) + '.\n\n', 1)
        with Path('scan-report.md').open('w', encoding='utf-8') as out:
            out.write(summary + '\n' + diagnostics_summary(diagnostics) + '\n')
            image = os.environ['IMAGE_REF']
            if image:
                image_path = Path('image-results.json')
                image_report = json.loads(image_path.read_text(encoding='utf-8')) if image_path.exists() else None
                out.write('\n### Container image\n\n' + render_summary(image, os.environ['IMAGE_PLATFORM'] or 'runner default platform', None, image_report, os.environ['IMAGE_OUTCOME'], image=True))
                image_log = Path('image-scan.log')
                if not image_log.exists() or scan_diagnostics(image_log.read_text(encoding='utf-8', errors='replace'))['errors']:
                    out.write('\n**Image scan diagnostics are incomplete or contain errors.**\n')
            else:
                out.write('\n### Container image\n\nNot scanned: no image configured.\n')
            available = [name for name in SARIF_FILES if Path(name).is_file()]
            out.write('\n### SARIF\n\n' + (', '.join(available) if available else 'None available') + '\n')
            for name, scanner_report in scanner_reports.items():
                out.write('\n' + render_extra(name.title(), os.environ[name.upper() + '_OUTCOME'], scanner_report))
        if diagnostics['errors']:
            print('::warning::Trivy reported scan errors. See the scan report.')
        if os.environ['SCAN_OUTCOME'] != 'success' or report is None:
            print('::error::Scan did not complete successfully; see job logs.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, RuntimeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        raise SystemExit(1)
