"""Command-line interface used by GitHub Actions."""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from sentinel.scanner import clone_target, parse_inventory, render_summary


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    inventory = sub.add_parser('inventory')
    inventory.add_argument('path', type=Path)
    sub.add_parser('clone')
    sub.add_parser('summary')
    args = parser.parse_args()
    if args.command == 'inventory':
        targets = parse_inventory(json.loads(args.path.read_text(encoding='utf-8')))
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as out:
            print('targets=' + json.dumps([asdict(t) for t in targets], separators=(',', ':')), file=out)
            print('has_targets=' + str(bool(targets)).lower(), file=out)
        if not targets:
            with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as out:
                out.write('No scan targets configured.\n')
    elif args.command == 'clone':
        target = parse_inventory([{'repo': os.environ['TARGET_REPO'], 'version': os.environ['TARGET_VERSION']}])[0]
        revision = clone_target(target, Path('target'))
        Path('revision.json').write_text(json.dumps(revision, indent=2) + '\n', encoding='utf-8')
        if not revision['matched_version']:
            print(f'::warning::Requested version not found for {target.repo}; scanning default branch.')
    else:
        revision_path, report_path = Path('revision.json'), Path('results.json')
        revision = json.loads(revision_path.read_text(encoding='utf-8')) if revision_path.exists() else None
        report = json.loads(report_path.read_text(encoding='utf-8')) if report_path.exists() else None
        summary = render_summary(os.environ['TARGET_REPO'], os.environ['TARGET_VERSION'], revision, report, os.environ['SCAN_OUTCOME'])
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as out:
            out.write(summary)
        if os.environ['SCAN_OUTCOME'] != 'success' or report is None:
            print('::error::Scan did not complete successfully; see job logs.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, RuntimeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        raise SystemExit(1)
