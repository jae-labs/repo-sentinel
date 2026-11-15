import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.scanner import Target, clone_target, findings, parse_inventory, render_summary, resolve_revision, scan_diagnostics, diagnostics_summary


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

    def test_optional_image_and_platform_validation(self):
        target = parse_inventory([{'repo': 'a/b', 'version': 'v1', 'image': 'ghcr.io/a/b@sha256:' + 'a' * 64, 'platform': 'linux/arm64'}])[0]
        self.assertEqual(target.platform, 'linux/arm64')
        for extra in ({'image': 'bad image'}, {'image': 'a/b@sha256:abcd'}, {'platform': 'linux/arm64'}, {'image': 'a/b', 'platform': '../../x'}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                parse_inventory([{'repo': 'a/b', 'version': 'v1', **extra}])

    def test_osv_resolution_defaults_on_and_accepts_boolean_override(self):
        target = {'repo': 'a/b', 'version': 'v1'}
        self.assertTrue(parse_inventory([target])[0].osv_resolve)
        self.assertFalse(parse_inventory([dict(target, osv_resolve=False)])[0].osv_resolve)
        with self.assertRaises(ValueError):
            parse_inventory([dict(target, osv_resolve='false')])

    def test_source_commit_requires_full_sha(self):
        target = {'repo': 'a/b', 'version': 'v1'}
        self.assertEqual(parse_inventory([dict(target, source_commit='A' * 40)])[0].source_commit, 'a' * 40)
        with self.assertRaises(ValueError):
            parse_inventory([dict(target, source_commit='a' * 7)])

    def test_empty_inventory_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'inventory.json').write_text('[]')
            env = dict(os.environ, GITHUB_OUTPUT=str(root / 'output'), GITHUB_STEP_SUMMARY=str(root / 'summary'))
            subprocess.run([sys.executable, '-m', 'sentinel', 'inventory', str(root / 'inventory.json')], env=env, check=True)
            self.assertIn('has_targets=false', (root / 'output').read_text())
            self.assertFalse((root / 'summary').exists())
            env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
            subprocess.run([sys.executable, '-m', 'sentinel', 'aggregate', 'inventory.json', 'artifacts'], cwd=root, env=env, check=True)
            self.assertIn('No targets configured', (root / 'summary').read_text())


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

    def test_clone_fetches_tags_before_resolving_and_warns_on_missing_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'target'
            calls = []
            def fake_git(where, *args):
                calls.append(args)
                if args[0] == 'clone':
                    path.mkdir(); (path / '.gitmodules').write_text('[submodule]')
                code = 1 if args[:2] == ('submodule', 'update') or args[:2] == ('lfs', 'ls-files') else 0
                return subprocess.CompletedProcess(args, code, '', '')
            def fake_resolve(where, version):
                self.assertIn(('fetch', '--tags', 'origin'), calls)
                return 'abc', True
            with patch('sentinel.scanner.run_git', side_effect=fake_git), patch('sentinel.scanner.resolve_revision', side_effect=fake_resolve):
                revision = clone_target(Target('owner/repo', 'v1'), path)
            self.assertTrue(any('Submodule' in x for x in revision['source_warnings']))
            self.assertTrue(any('LFS' in x for x in revision['source_warnings']))

    def test_source_pin_preserves_version_and_rejects_fallback(self):
        source_commit = 'a' * 40
        target = Target('owner/repo', 'v1', source_commit=source_commit)
        with tempfile.TemporaryDirectory() as tmp, patch('sentinel.scanner.run_git') as git, patch('sentinel.scanner.resolve_revision') as resolve:
            git.return_value = subprocess.CompletedProcess([], 0, '', '')
            path = Path(tmp)
            resolve.return_value = (source_commit, True)
            revision = clone_target(target, path)
            resolve.assert_called_once_with(path, source_commit)
            self.assertEqual(revision['requested_version'], 'v1')
            self.assertEqual(revision['commit'], source_commit)
            resolve.return_value = ('b' * 40, False)
            with self.assertRaisesRegex(RuntimeError, 'Unable to resolve pinned source commit'):
                clone_target(target, path)


class ReportTests(unittest.TestCase):
    def test_findings_and_render(self):
        report = {'Results': [{'Target': 'package-lock.json', 'Vulnerabilities': [
            {'VulnerabilityID': 'CVE-1', 'Severity': 'HIGH', 'PkgName': 'a|b', 'Title': 'Request smuggling | issue', 'InstalledVersion': '1', 'FixedVersion': '2', 'PrimaryURL': 'https://example.org/CVE-1'},
            {'VulnerabilityID': 'CVE-2', 'Severity': 'LOW'}],
            'Misconfigurations': [{'ID': 'DS-1', 'Severity': 'CRITICAL', 'Title': 'Missing USER', 'Message': 'Container runs as root'}]}]}
        rows = findings(report)
        self.assertEqual([row['id'] for row in rows], ['DS-1', 'CVE-1'])
        summary = render_summary('owner/repo', 'v1', {'commit': 'abc', 'matched_version': False}, report, 'success')
        self.assertIn('2 high or critical', summary)
        self.assertIn('a&#124;b', summary)
        self.assertIn('Request smuggling &#124; issue', summary)
        self.assertIn('Container runs as root', summary)
        self.assertIn('default branch fallback', summary)
        self.assertIn('[CVE-1](https://example.org/CVE-1)', summary)
        self.assertIn('Showing 1 of 2', render_summary('o/r', 'v', None, report, 'success', limit=1))

    def test_trivy_diagnostics_and_unknown_coverage(self):
        log = '2026-11-15T14:54:35Z\tERROR\t[dockerfile scanner] Failed to parse file\n2026-11-15T14:54:37Z\tINFO\tNumber of language-specific files\tnum=0\n'
        result = scan_diagnostics(log)
        self.assertEqual(result['dependency_files'], 0)
        self.assertEqual(len(result['errors']), 1)
        self.assertIn('Partial scan', diagnostics_summary(result))
        self.assertIn('no dependency files', diagnostics_summary(result))
        self.assertIn('file count unavailable', diagnostics_summary(scan_diagnostics('INFO scan started')))
        self.assertIn('unavailable', diagnostics_summary(scan_diagnostics(None)))

    def test_scan_failure_not_clean(self):
        self.assertIn('Scan failed', render_summary('o/r', 'v', None, None, 'failure'))
        self.assertIn('Scan failed', render_summary('o/r', 'v', None, {'Results': []}, 'failure'))
        self.assertIn('0 high or critical', render_summary('o/r', 'v', None, {'Results': []}, 'success'))


if __name__ == '__main__':
    unittest.main()
