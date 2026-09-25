"""Provider failures must not look like successful security outcomes."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

PATH = Path(__file__).resolve().parents[1] / 'scripts' / 'additional_experiments_runner.py'
SPEC = importlib.util.spec_from_file_location('additional_diagnostics', PATH)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)


class Response(io.BytesIO):
    pass


class DiagnosticProviderTests(unittest.TestCase):
    def test_valid_response_uses_configured_endpoint(self):
        client = M.OpenRouter('fake-test-key', base_url='http://127.0.0.1:19999/v1/')
        response = Response(json.dumps({'choices': [{'message': {'content': 'allowed answer'}}]}).encode())
        with patch.object(M.urllib.request, 'urlopen', return_value=response) as call:
            got = client.chat(model='test-model', messages=[], retries=1)
        self.assertEqual(got, 'allowed answer')
        self.assertEqual(call.call_args.args[0].full_url, 'http://127.0.0.1:19999/v1/chat/completions')

    def test_http_errors_are_not_content_filter_denials(self):
        client = M.OpenRouter('fake-test-key')
        for status in (400, 401, 429, 500):
            error = urllib.error.HTTPError('https://example.invalid', status, 'test', {}, None)
            with self.subTest(status=status), patch.object(M.urllib.request, 'urlopen', side_effect=error), patch.object(M.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, 'Provider request failed'):
                    client.chat(model='test-model', messages=[], retries=1)
        self.assertEqual(client.filtered, 0)

    def test_empty_choices_are_errors(self):
        client = M.OpenRouter('fake-test-key')
        with patch.object(M.urllib.request, 'urlopen', return_value=Response(b'{"choices": []}')), patch.object(M.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'Provider request failed'):
                client.chat(model='test-model', messages=[], retries=1)

    def test_failed_case_writes_incomplete_not_security_aggregate(self):
        case = M.LeakCase('case-1','test','request','privacy',[],[],[],[],'attack','naive')
        with tempfile.TemporaryDirectory() as directory, patch.object(M, 'OUT_ROOT', Path(directory)), patch.object(M, 'run_case', side_effect=RuntimeError('provider unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'no aggregate result is scored'):
                M.run_cases_parallel(None, [case], system='secureclaw', cfg=M.BoundaryConfig(), model='test-model', seed=42, label='test')
            report = json.loads((Path(directory) / 'errors_test.json').read_text())
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertEqual(report['completed_cases'], 0)
        self.assertEqual(len(report['errors']), 1)
        self.assertNotIn('asr', report)


if __name__ == '__main__':
    unittest.main()
