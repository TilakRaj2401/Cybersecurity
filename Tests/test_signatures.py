"""Tests for the signature detection engine component.

These tests are import-safe: if the `signature_engine` module isn't
available in the environment, the tests will be skipped to avoid
import-time failures in CI or developer setups.
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'Backend')
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

try:
    from signature_engine import SignatureDetectionEngine
    _SIG_ENGINE_MISSING = None
except ImportError as _err:
    SignatureDetectionEngine = None
    _SIG_ENGINE_MISSING = str(_err)


class TestSignatureEngine(unittest.TestCase):
    """Unit tests for `SignatureDetectionEngine` behaviour."""

    def setUp(self):
        """Create a fresh engine instance for each test."""
        self.engine = SignatureDetectionEngine()

    @unittest.skipIf(_SIG_ENGINE_MISSING, f"signature_engine missing: {_SIG_ENGINE_MISSING}")
    def test_telnet_signature_match(self):
        """A telnet packet should match the Telnet signature rule."""
        packet = {'protocol': 'tcp', 'src_port': 23, 'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.1'}
        result = self.engine.inspect(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result['rule_id'], 'SIG-101')

    @unittest.skipIf(_SIG_ENGINE_MISSING, f"signature_engine missing: {_SIG_ENGINE_MISSING}")
    def test_payload_signature_match(self):
        """A packet payload containing a known bad pattern should trigger a signature alert."""
        packet = {
            'protocol': 'tcp',
            'src_port': 50000,
            'dst_port': 80,
            'src_ip': '10.0.0.5',
            'dst_ip': '10.0.0.1',
            'payload': 'telnet login attempt with admin credentials',
        }
        result = self.engine.inspect(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result['rule_id'], 'SIG-200')

    @unittest.skipIf(_SIG_ENGINE_MISSING, f"signature_engine missing: {_SIG_ENGINE_MISSING}")
    def test_json_rules_are_loaded(self):
        """The engine should load rule metadata from the JSON signature file."""
        tmp_path = os.path.join(PROJECT_ROOT, 'Backend', 'sig.json')
        self.engine.signatures = {}
        self.engine.load_rules_from_file(tmp_path)
        self.assertIn(('tcp', 23), self.engine.signatures)
        self.assertEqual(self.engine.signatures[('tcp', 23)]['rule_id'], 'SIG-101')
        packet = {'protocol': 'tcp', 'src_port': 23, 'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.1'}
        result = self.engine.inspect(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result['rule_id'], 'SIG-101')

    @unittest.skipIf(_SIG_ENGINE_MISSING, f"signature_engine missing: {_SIG_ENGINE_MISSING}")
    def test_all_configured_signatures_are_detectable(self):
        """Every configured protocol and port pair should produce an alert."""
        self.assertEqual(len(self.engine.signatures), 30)

        for index, ((protocol, port), rule) in enumerate(self.engine.signatures.items()):
            with self.subTest(rule_id=rule['rule_id']):
                packet = {
                    'protocol': protocol,
                    'src_port': 40000 + index,
                    'dst_port': port,
                    'src_ip': '10.0.0.5',
                    'dst_ip': '10.0.0.1',
                }
                result = self.engine.inspect(packet)
                self.assertIsNotNone(result)
                self.assertEqual(result['rule_id'], rule['rule_id'])
                self.assertTrue(self.engine.has_known_signature(packet))

    @unittest.skipIf(_SIG_ENGINE_MISSING, f"signature_engine missing: {_SIG_ENGINE_MISSING}")
    def test_inspect_all_returns_every_matching_signature(self):
        """A packet touching multiple known ports should surface every signature match."""
        packet = {
            'protocol': 'tcp',
            'src_port': 23,
            'dst_port': 21,
            'src_ip': '10.0.0.5',
            'dst_ip': '10.0.0.1',
        }
        matches = self.engine.inspect_all(packet)
        self.assertEqual({match['rule_id'] for match in matches}, {'SIG-101', 'SIG-104'})

    @unittest.skipIf(_SIG_ENGINE_MISSING, f"signature_engine missing: {_SIG_ENGINE_MISSING}")
    def test_json_file_is_merged_without_losing_default_rules(self):
        """Loading JSON rules should add or override entries without discarding defaults."""
        engine = SignatureDetectionEngine()
        engine.signatures = {
            ('tcp', 23): {
                'rule_id': 'SIG-101',
                'msg': 'Telnet',
                'severity': 'Medium',
            }
        }
        engine.load_rules_from_file(
            os.path.join(PROJECT_ROOT, 'Backend', 'sig.json')
        )
        self.assertIn(('tcp', 23), engine.signatures)
        self.assertIn(('tcp', 22), engine.signatures)

    @unittest.skipIf(_SIG_ENGINE_MISSING, f"signature_engine missing: {_SIG_ENGINE_MISSING}")
    def test_list_all_signatures_returns_every_rule(self):
        """The engine should expose the full signature catalog, not only a sample match."""
        signatures = self.engine.list_all_signatures()
        self.assertEqual(len(signatures), 30)
        self.assertEqual(signatures[0]['rule_id'], 'SIG-101')
        self.assertEqual(signatures[-1]['rule_id'], 'SIG-133')


if __name__ == '__main__':
    unittest.main()
