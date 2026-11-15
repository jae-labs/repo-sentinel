import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.specialized import detect, fixed_versions, scan


class SpecializedTests(unittest.TestCase):
    def test_detects_nested_files_and_skips_ignored_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'app').mkdir(); (root / 'node_modules').mkdir()
            for name in ('app/main.py', 'app/go.mod', 'app/package-lock.json', 'app/Dockerfile', 'app/Dockerfile.dockerignore', 'node_modules/skip.py'):
                (root / name).write_text('test')
            (root / 'link.py').symlink_to(root / 'app/main.py')
            items = detect(root)
            self.assertEqual(len(items['python']), 1)
            self.assertEqual(len(items['docker']), 1)
            self.assertEqual(len(items['go']), 1)
            self.assertEqual(len(items['dependencies']), 2)

    def test_scanners_process_findings_and_track_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'app.py').write_text('pass')
            (root / 'requirements.txt').write_text('example==1')
            (root / 'Dockerfile').write_text('FROM example:1')
            def fake_run(args, **kwargs):
                if args[0] == 'osv-scanner':
                    data = {'results': [{'source': {'path': 'requirements.txt'}, 'packages': [{'package': {'name': 'example', 'version': '1'}, 'vulnerabilities': [{'id': 'CVE-TEST', 'summary': 'Affected package'}]}]}]}
                    return subprocess.CompletedProcess(args, 1, json.dumps(data), '')
                if args[0] == 'bandit':
                    return subprocess.CompletedProcess(args, 0, json.dumps({'results': [{'test_id': 'B101', 'filename': 'app.py', 'line_number': 1, 'issue_severity': 'LOW', 'issue_text': 'test'}], 'errors': []}), '')
                return subprocess.CompletedProcess(args, 1, 'not json', '')
            with patch('sentinel.specialized.shutil.which', return_value='/bin/tool'), patch('sentinel.specialized.run', side_effect=fake_run):
                result = scan(root)
            self.assertEqual([item['status'] for item in result['coverage']], ['completed', 'completed', 'partial'])
            self.assertEqual({item['rule'] for item in result['findings']}, {'CVE-TEST', 'B101'})

    def test_bandit_batches_preserve_successes_when_one_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for n in range(101):
                (root / f'file{n:03}.py').write_text('pass')
            calls = []
            def fake_run(args, **kwargs):
                if args[0] == 'osv-scanner':
                    return subprocess.CompletedProcess(args, 128, '', '')
                calls.append(args)
                if len(calls) == 2:
                    return subprocess.CompletedProcess(args, -9, '', 'sensitive diagnostic')
                return subprocess.CompletedProcess(args, 0, json.dumps({'results': [{'test_id': 'B101', 'filename': 'file.py'}], 'errors': []}), '')
            with patch('sentinel.specialized.shutil.which', return_value='/bin/tool'), patch('sentinel.specialized.run', side_effect=fake_run):
                result = scan(root)
            self.assertEqual(len(calls), 2)
            self.assertEqual(result['coverage'][1]['status'], 'partial')
            self.assertIn('exit -9', result['coverage'][1]['detail'])
            self.assertNotIn('sensitive diagnostic', str(result))
            self.assertEqual(len(result['findings']), 1)

    def test_fixed_versions_match_package_and_ecosystem(self):
        vuln = {'affected': [
            {'package': {'name': 'pillow', 'ecosystem': 'PyPI'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'fixed': '10.0.1'}]}, {'type': 'GIT', 'events': [{'fixed': 'abcdef123'}]}]},
            {'package': {'name': 'pillow', 'ecosystem': 'Go'}, 'ranges': [{'type': 'SEMVER', 'events': [{'fixed': '99.0'}]}]},
        ]}
        self.assertEqual(fixed_versions(vuln, {'name': 'pillow', 'ecosystem': 'PyPI'}), ['10.0.1'])
        self.assertEqual(fixed_versions(vuln, {'name': 'pillow'}), [])

    @unittest.skipUnless(shutil.which('bandit'), 'Bandit CLI not installed')
    def test_real_bandit_large_batch_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(101):
                (root / f'file{i:03}.py').write_text('assert True\n')
            bandit_path = shutil.which('bandit')
            with patch('sentinel.specialized.shutil.which', side_effect=lambda name: bandit_path if name == 'bandit' else None):
                result = scan(root)
            bandit = next(row for row in result['coverage'] if row['scanner'] == 'Bandit')
            self.assertEqual(bandit['status'], 'completed')
            self.assertTrue(any(row['rule'] == 'B101' for row in result['findings']))

    def test_osv_timeout_keeps_other_scanner_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'main.py').write_text('pass')

            def fake_run(args, **kwargs):
                if args[0] == 'osv-scanner':
                    self.assertEqual(kwargs['timeout'], 300)
                    raise subprocess.TimeoutExpired(args, kwargs['timeout'])
                return subprocess.CompletedProcess(args, 0, json.dumps({
                    'results': [{'test_id': 'B608', 'issue_severity': 'HIGH'}], 'errors': [],
                }), '')

            with patch('sentinel.specialized.shutil.which', return_value='/bin/tool'), patch('sentinel.specialized.run', side_effect=fake_run) as runner:
                result = scan(root)
            self.assertEqual(result['coverage'][0]['status'], 'incomplete')
            self.assertIn('timed out after 5 minutes', result['coverage'][0]['detail'])
            self.assertEqual([call.args[0][0] for call in runner.call_args_list], ['osv-scanner', 'bandit'])
            self.assertEqual([row['rule'] for row in result['findings']], ['B608'])

    def test_empty_target_is_not_a_clean_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = scan(Path(tmp))
        self.assertIn(result['coverage'][0]['status'], ('no packages', 'incomplete'))
        self.assertTrue(all(item['status'] == 'not applicable' for item in result['coverage'][1:]))

    def test_osv_scans_without_hardcoded_manifest_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'pom.xml').write_text('<project/>')
            calls = []
            def fake_run(args, **kwargs):
                calls.append(args)
                return subprocess.CompletedProcess(args, 128, '', '')
            with patch('sentinel.specialized.shutil.which', return_value='/bin/tool'), patch('sentinel.specialized.run', side_effect=fake_run):
                result = scan(root)
            self.assertEqual(calls[0][0], 'osv-scanner')
            self.assertEqual(result['coverage'][0]['status'], 'no packages')

    def test_missing_tool_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'main.py').write_text('pass')
            with patch('sentinel.specialized.shutil.which', return_value=None):
                result = scan(Path(tmp))
        self.assertEqual(result['coverage'][1]['status'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
