import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sentinel.scanner import findings, parse_inventory, render_summary, resolve_revision


class InventoryTests(unittest.TestCase):
    def test_valid_and_empty(self):
        self.assertEqual(parse_inventory([]), [])
        self.assertEqual(parse_inventory([{'repo': 'owner/repo', 'version': 'v1'}])[0].repo, 'owner/repo')

    def test_invalid_and_duplicate(self):
        for value in ({}, [None], [{'repo': '../x', 'version': 'v1'}],
                      [{'repo': 'a/b', 'version': '--evil'}],
                      [{'repo': 'a/b', 'version': ''}],
                      [{'repo': 'A/b', 'version': '1'}, {'repo': 'a/B', 'version': '2'}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_inventory(value)

    def test_empty_inventory_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'inventory.json').write_text('[]')
            env = dict(os.environ, GITHUB_OUTPUT=str(root / 'output'), GITHUB_STEP_SUMMARY=str(root / 'summary'))
            subprocess.run([sys.executable, '-m', 'sentinel', 'inventory', str(root / 'inventory.json')], env=env, check=True)
            self.assertIn('has_targets=false', (root / 'output').read_text())
            self.assertIn('No scan targets', (root / 'summary').read_text())


class RevisionTests(unittest.TestCase):
    def test_resolves_tags_commits_and_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            def git(*args):
                return subprocess.run(['git', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', '-C', str(path), *args], check=True, text=True, capture_output=True).stdout.strip()
            git('init', '-q')
            git('config', 'user.email', 'tests@example.invalid')
            git('config', 'user.name', 'Test')
            (path / 'test').write_text('example')
            git('add', 'test')
            git('commit', '-qm', 'initial')
            commit = git('rev-parse', 'HEAD')
            git('tag', 'v1.2.3')
            for version in ('v1.2.3', '1.2.3', commit[:10]):
                self.assertEqual(resolve_revision(path, version), (commit, True))
            self.assertEqual(resolve_revision(path, 'not-a-tag'), (commit, False))


class ReportTests(unittest.TestCase):
    def test_findings_and_render(self):
        report = {'Results': [{'Target': 'package-lock.json', 'Vulnerabilities': [
            {'VulnerabilityID': 'CVE-1', 'Severity': 'HIGH', 'PkgName': 'a|b', 'InstalledVersion': '1', 'FixedVersion': '2', 'PrimaryURL': 'https://example.org/CVE-1'},
            {'VulnerabilityID': 'CVE-2', 'Severity': 'LOW'}],
            'Misconfigurations': [{'ID': 'DS-1', 'Severity': 'CRITICAL'}]}]}
        rows = findings(report)
        self.assertEqual([row['id'] for row in rows], ['DS-1', 'CVE-1'])
        summary = render_summary('owner/repo', 'v1', {'commit': 'abc', 'matched_version': False}, report, 'success')
        self.assertIn('2 high or critical', summary)
        self.assertIn('a&#124;b', summary)
        self.assertIn('requested version not matched', summary)
        self.assertIn('[CVE-1](https://example.org/CVE-1)', summary)
        self.assertIn('Showing 1 of 2', render_summary('o/r', 'v', None, report, 'success', limit=1))

    def test_scan_failure_not_clean(self):
        self.assertIn('Scan failed', render_summary('o/r', 'v', None, None, 'failure'))
        self.assertIn('Scan failed', render_summary('o/r', 'v', None, {'Results': []}, 'failure'))
        self.assertIn('0 high or critical', render_summary('o/r', 'v', None, {'Results': []}, 'success'))


if __name__ == '__main__':
    unittest.main()
