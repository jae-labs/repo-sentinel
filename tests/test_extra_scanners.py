import unittest

from sentinel.extra_scanners import dependency_scope, grouped_findings, normalize_semgrep, render_extra


class ExtraScannerTests(unittest.TestCase):
    def test_sast_results_drop_source_and_note_errors(self):
        raw = {'results': [{'check_id': 'rule.id', 'path': 'a.py', 'start': {'line': 8}, 'extra': {'severity': 'ERROR', 'message': 'sensitive-value', 'lines': 'sensitive-value'}}], 'errors': [{'message': 'sensitive-value'}]}
        result = normalize_semgrep(raw)
        self.assertNotIn('sensitive-value', str(result))
        rendered = render_extra('Semgrep', 'success', result)
        self.assertIn('a.py:8', rendered)
        self.assertIn('Partial: 1 scanner error', rendered)

    def test_scope_and_alias_grouping_preserve_source_boundaries(self):
        self.assertEqual(dependency_scope('target/requirements_dev.txt'), 'development/test')
        self.assertEqual(dependency_scope('target/requirements.txt'), 'unclassified')
        base = {'scanner': 'OSV-Scanner', 'package': 'pkg', 'version': '1', 'path': 'requirements.txt'}
        rows = [dict(base, rule='GHSA-one', aliases=['CVE-2026-1234']), dict(base, rule='CVE-2026-1234', aliases=[]), dict(base, rule='CVE-2026-1234', aliases=[], path='tests/requirements.txt')]
        grouped = grouped_findings(rows)
        self.assertEqual(len(grouped), 2)
        self.assertIn('GHSA-one', grouped[0]['description'])
        self.assertEqual(len(rows), 3)

    def test_invalid_and_missing(self):
        with self.assertRaises(ValueError):
            normalize_semgrep({'results': []})
        self.assertIn('Incomplete', render_extra('Semgrep', 'failure', None))


if __name__ == '__main__':
    unittest.main()
