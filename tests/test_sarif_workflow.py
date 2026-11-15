import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class SarifWorkflowTests(unittest.TestCase):
    def test_osv_exit_codes_do_not_abort_following_scanners(self):
        repo = Path(__file__).resolve().parents[1]
        workflow = (repo / '.github/workflows/reusable-scan.yml').read_text()
        step = workflow.split('      - name: Generate sanitized SARIF artifacts\n', 1)[1].split('      - name: Summarize findings\n', 1)[0]
        block = step.split('        run: |\n', 1)[1]
        script = '\n'.join(line[10:] for line in block.splitlines() if line.startswith('          ')) + '\n'
        document = json.dumps({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'mock'}}, 'results': []}]})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bins = root / 'bin'; bins.mkdir()
            (root / 'target').mkdir()
            (root / 'results.json').write_text('{}')
            (root / 'script.sh').write_text(script)
            (bins / 'trivy').write_text('#!/bin/bash\nprintf %s ' + repr(document) + ' > "$5"\n')
            (bins / 'osv-scanner').write_text('#!/bin/bash\nprintf %s ' + repr(document) + '\nexit "$OSV_FAKE_EXIT"\n')
            (bins / 'bandit').write_text('#!/bin/bash\nwhile [[ $# -gt 0 ]]; do if [[ "$1" == --output ]]; then shift; printf %s ' + repr(document) + ' > "$1"; break; fi; shift; done\n')
            for executable in bins.iterdir():
                executable.chmod(0o755)
            for code in (0, 1, 128, 127):
                for path in root.glob('*.sarif'):
                    path.unlink()
                env = dict(os.environ, PATH=str(bins) + os.pathsep + os.environ['PATH'], PYTHONPATH=str(repo), RUNNER_TEMP=str(root), OSV_FAKE_EXIT=str(code), PYTHONDONTWRITEBYTECODE='1')
                result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', str(root / 'script.sh')], cwd=root, env=env, text=True, capture_output=True)
                with self.subTest(code=code):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue((root / 'results.sarif').exists(), result.stdout + result.stderr)
                    self.assertTrue((root / 'bandit.sarif').exists(), result.stdout + result.stderr)
                    self.assertEqual((root / 'osv.sarif').exists(), code in (0, 1))
                    if code == 127:
                        self.assertIn('OSV SARIF scan failed', result.stdout)
