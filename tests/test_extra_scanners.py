import unittest

from sentinel.extra_scanners import normalize_semgrep, render_extra


class ExtraScannerTests(unittest.TestCase):
    def test_sast_results_drop_source_and_note_errors(self):
        raw = {'results': [{'check_id': 'rule.id', 'path': 'a.py', 'start': {'line': 8}, 'extra': {'severity': 'ERROR', 'message': 'sensitive-value', 'lines': 'sensitive-value'}}], 'errors': [{'message': 'sensitive-value'}]}
        result = normalize_semgrep(raw)
        self.assertNotIn('sensitive-value', str(result))
        rendered = render_extra('Semgrep', 'success', result)
        self.assertIn('a.py:8', rendered)
        self.assertIn('Partial: 1 scanner error', rendered)

    def test_invalid_and_missing(self):
        with self.assertRaises(ValueError):
            normalize_semgrep({'results': []})
        self.assertIn('Incomplete', render_extra('Semgrep', 'failure', None))


if __name__ == '__main__':
    unittest.main()
