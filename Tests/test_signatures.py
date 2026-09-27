"""Tests for the signature detection engine component.

These tests are import-safe: if the `signature_engine` module isn't
available in the environment, the tests will be skipped to avoid
import-time failures in CI or developer setups.
"""

import unittest

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


if __name__ == '__main__':
    unittest.main()
