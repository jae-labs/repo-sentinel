import json
import tempfile
import unittest
from pathlib import Path

from sentinel.aggregate import combined_report, summary_excerpt
from sentinel.scanner import Target


class CombinedReportTests(unittest.TestCase):
    def test_results_incomplete_mismatch_and_details(self):
        targets = [Target('a/one', 'v1'), Target('b/two', 'v2'), Target('c/three', 'v3')]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in (0, 1):
                folder = root / f'scan-{index}'
                folder.mkdir()
                target = targets[index]
                (folder / 'status.json').write_text(json.dumps({'repository': target.repo, 'version': target.version, 'clone_outcome': 'success', 'scan_outcome': 'success'}))
                (folder / 'diagnostics.json').write_text(json.dumps({'available': True, 'errors': ['scanner ERROR test'] if index == 0 else [], 'dependency_files': 0 if index == 0 else 3}))
                (folder / 'revision.json').write_text(json.dumps({'repository': target.repo, 'requested_version': target.version, 'commit': 'abcd', 'matched_version': index == 0}))
                (folder / 'results.json').write_text(json.dumps({'SchemaVersion': 2, 'Results': [{'Target': 'Dockerfile', 'Misconfigurations': [{'ID': 'DS-1', 'Severity': 'HIGH', 'Message': 'Container runs as root'}]}]}))
            report = combined_report(targets, root)
            self.assertIn('2/3 scan reports available; 1 incomplete; 1 used an unmatched', report)
            self.assertIn('0 critical, 2 high', report)
            self.assertIn('2 have partial scans', report)
            self.assertIn('1 detected no dependency files', report)
            self.assertIn('scanner ERROR test', report)
            self.assertIn('Container runs as root', report)
            self.assertIn('| c/three | v3 | **Incomplete**', report)
            (root / 'scan-1' / 'results.json').write_text('{broken')
            self.assertIn('1/3 scan reports available; 2 incomplete', combined_report(targets, root))

    def test_scanner_counts_image_and_advisory_aliases(self):
        target = Target('a/b', 'v1', 'example/image:1', 'linux/arm64')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); folder = root / 'scan-0'; folder.mkdir()
            status = {'repository': 'a/b', 'version': 'v1', 'clone_outcome': 'success', 'scan_outcome': 'success', 'image_outcome': 'success', 'image': target.image, 'platform': target.platform, 'specialized_outcome': 'success'}
            (folder / 'status.json').write_text(json.dumps(status))
            (folder / 'revision.json').write_text(json.dumps({'repository': 'a/b', 'requested_version': 'v1', 'commit': 'abc', 'matched_version': True, 'source_warnings': ['LFS unknown']}))
            (folder / 'diagnostics.json').write_text(json.dumps({'available': True, 'errors': [], 'dependency_files': 1}))
            finding = {'VulnerabilityID': 'CVE-2026-1234', 'Severity': 'HIGH', 'PkgName': 'pkg', 'InstalledVersion': '1'}
            (folder / 'results.json').write_text(json.dumps({'SchemaVersion': 2, 'Results': [{'Target': 'lock', 'Vulnerabilities': [finding]}]}))
            (folder / 'image-results.json').write_text(json.dumps({'SchemaVersion': 2, 'Results': [{'Target': 'image', 'Vulnerabilities': [finding]}]}))
            (folder / 'image-scan.log').write_text('INFO complete')
            extra = {'scanner': 'specialized', 'coverage': [], 'findings': [{'scanner': 'OSV-Scanner', 'rule': 'GHSA-test', 'aliases': ['CVE-2026-1234'], 'package': 'pkg', 'version': '1', 'path': 'lock'}]}
            (folder / 'specialized.json').write_text(json.dumps(extra))
            report = combined_report([target], root)
            self.assertIn('OSV-Scanner: 1', report)
            self.assertIn('Trivy image: 1', report)
            self.assertIn('1 potential Trivy/OSV duplicate', report)
            self.assertIn('image tag mutable', report)
            self.assertIn('source coverage warning', report)

    def test_other_scanners_survive_trivy_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'scan-0'
            folder.mkdir()
            (folder / 'status.json').write_text(json.dumps({'repository': 'a/b', 'version': 'v1', 'clone_outcome': 'success', 'scan_outcome': 'failure', 'gitleaks_outcome': 'success', 'semgrep_outcome': 'failure'}))
            (folder / 'gitleaks.json').write_text(json.dumps({'scanner': 'gitleaks', 'findings': [{'rule': 'test-rule', 'path': 'file', 'line': 2}]}))
            report = combined_report([Target('a/b', 'v1')], Path(tmp))
            self.assertIn('Incomplete', report)
            self.assertIn('test-rule', report)
            self.assertIn('### Semgrep', report)

    def test_status_failure_not_treated_as_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'scan-0'
            folder.mkdir()
            (folder / 'status.json').write_text(json.dumps({'repository': 'a/b', 'version': 'v1', 'clone_outcome': 'success', 'scan_outcome': 'failure'}))
            (folder / 'revision.json').write_text(json.dumps({'repository': 'a/b', 'requested_version': 'v1', 'commit': 'abcd', 'matched_version': True}))
            (folder / 'results.json').write_text(json.dumps({'Results': []}))
            self.assertIn('0/1 scan reports available; 1 incomplete', combined_report([Target('a/b', 'v1')], Path(tmp)))

    def test_excerpt_is_bounded_and_utf8_safe(self):
        excerpt = summary_excerpt(('hello é\n' * 100), byte_limit=200)
        self.assertLessEqual(len(excerpt.encode()), 200)
        self.assertIn('Summary truncated', excerpt)

    def test_empty_inventory(self):
        self.assertIn('No targets configured', combined_report([], Path('/nonexistent')))


if __name__ == '__main__':
    unittest.main()
