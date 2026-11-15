import unittest

from sentinel.extra_scanners import normalize_gitleaks, normalize_semgrep, render_extra


class ExtraScannerTests(unittest.TestCase):
    def test_secret_fields_not_retained(self):
        raw = [{'RuleID': 'test', 'File': 'config', 'StartLine': 3, 'Secret': 'sensitive-value', 'Match': 'sensitive-value', 'Line': 'sensitive-value'}]
        result = normalize_gitleaks(raw)
        self.assertNotIn('sensitive-value', str(result))
        self.assertIn('config:3', render_extra('Gitleaks', 'success', result))
        self.assertNotIn('sensitive-value', render_extra('Gitleaks', 'success', result))

    def test_sast_results_drop_source_and_note_errors(self):
        raw = {'results': [{'check_id': 'rule.id', 'path': 'a.py', 'start': {'line': 8}, 'extra': {'severity': 'ERROR', 'message': 'sensitive-value', 'lines': 'sensitive-value'}}], 'errors': [{'message': 'sensitive-value'}]}
        result = normalize_semgrep(raw)
        self.assertNotIn('sensitive-value', str(result))
        rendered = render_extra('Semgrep', 'success', result)
        self.assertIn('a.py:8', rendered)
        self.assertIn('Partial: 1 scanner error', rendered)

    def test_invalid_and_missing(self):
        for func, value in ((normalize_gitleaks, {}), (normalize_semgrep, {'results': []})):
            with self.assertRaises(ValueError):
                func(value)
        self.assertIn('Incomplete', render_extra('Semgrep', 'failure', None))
        self.assertEqual(normalize_gitleaks(None)['findings'], [])


if __name__ == '__main__':
    unittest.main()
