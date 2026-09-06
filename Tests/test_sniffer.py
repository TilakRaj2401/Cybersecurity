# Module docstring
"""Tests for the `PacketSniffer` implementation in Backend/sniffer_engine.

This module runs a small unit test to verify captured packet structure.
"""

# pylint: disable=import-error,wrong-import-position
import os
import sys
import unittest

# Ensure Backend package is importable when running tests from the Tests folder
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Backend'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from sniffer_engine import PacketSniffer

class TestSniffer(unittest.TestCase):
    """Unit tests for the `PacketSniffer` class.

    Verifies basic packet capture behavior and packet structure keys.
    """

    def test_packet_structure(self):
        """Verify PacketSniffer captures three packets with expected keys.

        Ensures the capture callback receives three packets and that each
        packet includes `src_ip` and `protocol` keys.
        """
        packets = []
        sniffer = PacketSniffer()
        sniffer.start_capture(packets.append, max_packets=3)
        self.assertEqual(len(packets), 3)
        self.assertIn('src_ip', packets[0])
        self.assertIn('protocol', packets[0])

if __name__ == '__main__':
    unittest.main()
