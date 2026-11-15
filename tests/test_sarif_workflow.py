import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class SarifWorkflowTests(unittest.TestCase):
    def test_exports_available_findings_without_rerunning_scanners(self):
        repo = Path(__file__).resolve().parents[1]
        workflow = (repo / '.github/workflows/reusable-scan.yml').read_text()
        step = workflow.split('      - name: Export sanitized SARIF\n', 1)[1].split('      - name: Write scan report\n', 1)[0]
        block = step.split('        run: |\n', 1)[1]
        script = '\n'.join(line[10:] for line in block.splitlines() if line.startswith('          ')) + '\n'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bins = root / 'bin'
            bins.mkdir()
            (root / 'script.sh').write_text(script)
            for name in ('osv-scanner', 'bandit'):
                executable = bins / name
                executable.write_text('#!/bin/bash\ntouch unexpectedly-reran\nexit 127\n')
                executable.chmod(0o755)
            env = dict(os.environ, PATH=str(bins) + os.pathsep + os.environ['PATH'],
                       PYTHONPATH=str(repo), RUNNER_TEMP=str(root), PYTHONDONTWRITEBYTECODE='1')
            for osv_status in ('completed', 'incomplete'):
                with self.subTest(osv_status=osv_status):
                    (root / 'osv.sarif').unlink(missing_ok=True)
                    (root / 'specialized.json').write_text(json.dumps({
                        'coverage': [{'scanner': 'OSV-Scanner', 'status': osv_status},
                                     {'scanner': 'Bandit', 'status': 'completed'}],
                        'findings': [{'scanner': 'Bandit', 'rule': 'B101', 'path': './target/test_sample.py',
                                      'line': 7, 'severity': 'LOW', 'description': 'omitted scan text'},
                                     {'scanner': 'OSV-Scanner', 'rule': 'GHSA-test', 'severity': 'HIGH'}],
                    }))
                    subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', str(root / 'script.sh')],
                                   cwd=root, env=env, text=True, capture_output=True, check=True)
                    self.assertFalse((root / 'unexpectedly-reran').exists())
                    self.assertEqual((root / 'osv.sarif').exists(), osv_status == 'completed')
                    payload = (root / 'bandit.sarif').read_text()
                    self.assertNotIn('omitted scan text', payload)
                    result = json.loads(payload)['runs'][0]['results'][0]
                    self.assertEqual(result['ruleId'], 'B101')
                    self.assertEqual(result['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'test_sample.py')
