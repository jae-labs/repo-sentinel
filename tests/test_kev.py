import json
import tempfile
import unittest
from pathlib import Path

from sentinel.kev import kev_section, load_catalog
from sentinel.scanner import Target


class KevTests(unittest.TestCase):
    def test_matches_cve_and_aliases_across_scanners_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            catalog = root / 'catalog.json'
            catalog.write_text(json.dumps({'dateReleased': '2026-11-15T00:00:00Z', 'vulnerabilities': [{'cveID': 'CVE-2024-12345', 'dateAdded': '2024-02-01'}, {'cveID': 'CVE-2025-54321', 'dateAdded': '2025-03-02'}]}))
            target = Target('a/b', 'v1', 'example:1', 'linux/arm64')
            artifact = root / 'scan-0'
            artifact.mkdir()
            (artifact / 'status.json').write_text(json.dumps({'repository': 'a/b', 'version': 'v1', 'scan_outcome': 'success', 'image_outcome': 'success', 'image': target.image, 'platform': target.platform, 'specialized_outcome': 'success'}))
            (artifact / 'results.json').write_text(json.dumps({'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [{'VulnerabilityID': 'CVE-2024-12345', 'Severity': 'HIGH'}, {'VulnerabilityID': 'CVE-2025-54321', 'Severity': 'LOW'}]}]}))
            (artifact / 'image-results.json').write_text(json.dumps({'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [{'VulnerabilityID': 'CVE-2024-12345', 'Severity': 'CRITICAL'}]}]}))
            (artifact / 'specialized.json').write_text(json.dumps({'scanner': 'specialized', 'findings': [{'scanner': 'OSV-Scanner', 'rule': 'GHSA-example', 'aliases': ['CVE-2024-12345', 'CVE-2025-54321']}, {'scanner': 'Bandit', 'rule': 'CVE-2024-12345'}]}))
            result = kev_section([target], root, catalog)
            self.assertIn('2 repository/CVE match(es)', result)
            self.assertIn('OSV-Scanner, Trivy, Trivy image', result)
            self.assertIn('2024-02-01', result)
            self.assertNotIn('Bandit', result)
            self.assertIn('CVE-2025-54321', result)
            (artifact / 'status.json').write_text(json.dumps({'repository': 'a/b', 'version': 'wrong', 'scan_outcome': 'success'}))
            self.assertIn('No CISA matches in the available findings', kev_section([target], root, catalog))

    def test_unavailable_or_invalid_catalog_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertIn('status is unknown', kev_section([], root, root / 'missing'))
            for data in ({}, {'dateReleased': 'now', 'vulnerabilities': []}, {'dateReleased': 'now', 'vulnerabilities': [{'cveID': 'bad'}]}):
                path = root / 'catalog'
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    load_catalog(path)
                self.assertIn('status is unknown', kev_section([], root, path))


if __name__ == '__main__':
    unittest.main()
