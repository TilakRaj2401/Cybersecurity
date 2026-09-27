"""Tests for the ONNX export pipeline used by the edge model."""

import os
import unittest

from onnx_exporter import export_to_onnx


class TestEdgeModel(unittest.TestCase):
    """Verify that the edge model can be exported to an ONNX file."""

    def test_onnx_export_file_creation(self):
        """Ensure the export creates a file and removes the temporary artifact."""
        file_path = "test_iot_model.onnx"
        export_to_onnx(file_path)
        self.assertTrue(os.path.exists(file_path))
        if os.path.exists(file_path):
            os.remove(file_path)

if __name__ == '__main__':
    unittest.main()
