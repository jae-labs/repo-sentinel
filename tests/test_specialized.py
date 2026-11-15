import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.specialized import detect, scan


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
