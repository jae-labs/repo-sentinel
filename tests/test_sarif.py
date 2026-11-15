import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from sentinel.sarif import sanitized_sarif


class SarifTests(unittest.TestCase):
    def test_removes_source_and_untrusted_messages(self):
        raw = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'Semgrep', 'rules': [{'id': 'rule.id', 'help': {'text': 'secret-value'}}]}}, 'results': [{'ruleId': 'rule.id', 'level': 'warning', 'message': {'text': 'secret-value'}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': '/home/runner/work/target/code.py', 'contents': {'text': 'secret-value'}}, 'region': {'startLine': 5, 'snippet': {'text': 'secret-value'}}}}]}]}]}
        safe = sanitized_sarif(raw)
        self.assertNotIn('secret-value', str(safe))
        self.assertEqual(safe['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'code.py')
        self.assertEqual(safe['runs'][0]['results'][0]['level'], 'warning')

    @unittest.skipUnless(shutil.which('bandit'), 'Bandit CLI not installed')
    def test_real_bandit_sarif_can_be_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'sample.py').write_text('assert True\n')
            output = root / 'result.sarif'
            subprocess.run(['bandit', '--quiet', '-f', 'sarif', '-o', str(output), '--exit-zero', str(root / 'sample.py')], check=True, capture_output=True)
            safe = sanitized_sarif(json.loads(output.read_text()))
            self.assertTrue(any(run['results'] for run in safe['runs']))

    def test_rejects_invalid_or_traversing_locations(self):
        with self.assertRaises(ValueError):
            sanitized_sarif({'version': '2.0'})
        raw = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'tool'}}, 'results': [{'ruleId': 'R1', 'locations': [{'physicalLocation': {'artifactLocation': {'uri': '../secret.py'}}}]}]}]}
        self.assertNotIn('locations', sanitized_sarif(raw)['runs'][0]['results'][0])
