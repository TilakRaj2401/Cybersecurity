"""Tests for the ML anomaly detection engine.

These tests skip cleanly when the `ml_anomaly_engine` package is not
installed in the current environment to avoid import-time failures.
"""

import unittest
import numpy as np

try:
    from ml_anomaly_engine import AnomalyDetector
    _ML_ENGINE_MISSING = None
except ImportError as _err:
    AnomalyDetector = None
    _ML_ENGINE_MISSING = str(_err)


class TestMLEngine(unittest.TestCase):
    """Unit tests for `AnomalyDetector` training and inference."""

    @unittest.skipIf(_ML_ENGINE_MISSING, f"ml_anomaly_engine missing: {_ML_ENGINE_MISSING}")
    def test_model_training_and_inference(self):
        """Train a baseline and run a prediction, validating output keys."""
        data = np.random.rand(50, 6)
        detector = AnomalyDetector()
        detector.train_baseline(data)

        res = detector.predict(data[0:1])
        self.assertIn('is_anomaly', res)
        self.assertIn('anomaly_score', res)


if __name__ == '__main__':
    unittest.main()
