import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ReportPipelineTests(unittest.TestCase):
    def test_reports_are_combined_without_secret_values(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / 'target'
            target.mkdir()
            bins = root / 'bin'
            bins.mkdir()
            (target / 'code.py').write_text('eval(input())\n')
            (target / 'Dockerfile').write_text('FROM ubuntu:latest\n')
            (target / 'requirements.txt').write_text('example==1\n')
            fake = {
                'osv-scanner': {'results': [{'source': {'path': 'requirements.txt'}, 'packages': [{'package': {'name': 'example', 'version': '1'}, 'vulnerabilities': [{'id': 'CVE-2026-1000', 'summary': 'Example advisory'}]}]}]},
                'bandit': {'results': [{'test_id': 'B307', 'test_name': 'blacklist', 'filename': 'code.py', 'line_number': 1, 'issue_severity': 'HIGH'}], 'errors': []},
                'hadolint': [{'code': 'DL3007', 'line': 1, 'level': 'warning'}],
            }
            for name, data in fake.items():
                executable = bins / name
                executable.write_text('#!/usr/bin/env python3\nimport json\nprint(' + repr(json.dumps(data)) + ')\n')
                executable.chmod(0o755)
            env = dict(os.environ, PYTHONPATH=str(source), PATH=str(bins) + os.pathsep + os.environ['PATH'], PYTHONDONTWRITEBYTECODE='1')
            def cli(*args, extra=None):
                return subprocess.run([sys.executable, '-m', 'sentinel', *map(str, args)], cwd=root, env=dict(env, **(extra or {})), text=True, capture_output=True, check=True)
            cli('specialized', target)
            self.assertEqual(len(json.loads((root / 'specialized.json').read_text())['findings']), 3)
            raw = root / 'semgrep-raw.json'
            raw.write_text(json.dumps({'results': [{'check_id': 'python.security.example', 'path': 'code.py', 'start': {'line': 1}, 'extra': {'severity': 'ERROR', 'message': 'redaction-sentinel'}}], 'errors': [], 'paths': {'scanned': ['code.py']}}))
            cli('normalize', 'semgrep', raw, root / 'semgrep.json')
            self.assertNotIn('redaction-sentinel', (root / 'semgrep.json').read_text())
            (root / 'revision.json').write_text(json.dumps({'repository': 'a/b', 'requested_version': 'v1', 'commit': 'abcdef', 'matched_version': True, 'source_warnings': []}))
            (root / 'results.json').write_text(json.dumps({'SchemaVersion': 2, 'Results': [{'Target': 'requirements.txt', 'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1000', 'Severity': 'HIGH', 'PkgName': 'example', 'InstalledVersion': '1'}]}]}))
            (root / 'scan.log').write_text('INFO Number of language-specific files num=1\n')
            summary = root / 'summary.md'
            status = {'TARGET_REPO': 'a/b', 'TARGET_VERSION': 'v1', 'SCAN_OUTCOME': 'success', 'CLONE_OUTCOME': 'success', 'SEMGREP_OUTCOME': 'success', 'SPECIALIZED_OUTCOME': 'success', 'IMAGE_OUTCOME': 'skipped', 'IMAGE_REF': '', 'IMAGE_PLATFORM': '', 'GITHUB_STEP_SUMMARY': str(summary)}
            cli('summary', extra=status)
            inventory = root / 'inventory.json'
            inventory.write_text(json.dumps([{'repo': 'a/b', 'version': 'v1'}]))
            artifact = root / 'artifacts' / 'scan-0'
            artifact.mkdir(parents=True)
            for name in ('revision.json', 'results.json', 'status.json', 'diagnostics.json', 'specialized.json', 'semgrep.json'):
                (artifact / name).write_bytes((root / name).read_bytes())
            catalog = root / 'cisa.json'
            catalog.write_text(json.dumps({'dateReleased': '2026-11-15', 'vulnerabilities': [{'cveID': 'CVE-2026-1000', 'dateAdded': '2026-01-01'}]}))
            cli('aggregate', inventory, root / 'artifacts', '--cisa-catalog', catalog, extra={'GITHUB_STEP_SUMMARY': str(summary)})
            combined = (root / 'combined-report.md').read_text()
            for expected in ('Trivy: 1', 'OSV-Scanner: 1', 'Bandit: 1', 'Hadolint: 1', 'semgrep: 1', '1 potential Trivy/OSV duplicate', 'image not configured', '1 repository/CVE match(es)', 'OSV-Scanner, Trivy'):
                self.assertIn(expected, combined)
            self.assertNotIn('redaction-sentinel', combined)


if __name__ == '__main__':
    unittest.main()
