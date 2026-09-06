"""Combines signature-based and ML-based engines into a hybrid pipeline.

`HybridNIDSPipeline` runs a signature inspection first, and if no rule
matches, uses an IsolationForest-based detector to flag anomalies.
"""

import numpy as np

from signature_engine import SignatureDetectionEngine
from ml_anomaly_engine import AnomalyDetector
from feature_extractor import extract_iot_features

class HybridNIDSPipeline:
    """Hybrid pipeline combining signature rules with an ML anomaly detector.

    The pipeline runs signature-based inspection first; if no signature
    matches, it extracts features and asks the ML `AnomalyDetector` for a
    behavioral decision.
    """

    def __init__(self):
        self.sig_engine = SignatureDetectionEngine()
        self.ml_engine = AnomalyDetector()
        # Train ML with synthetic baseline
        self.ml_engine.train_baseline(np.random.normal(loc=10, scale=2, size=(100, 6)))

    def train_ml_baseline(self, normal_features: np.ndarray):
        """Retrain the ML baseline model with provided normal feature vectors.

        This public helper exists so callers can refresh the ML baseline at
        runtime without recreating the pipeline instance.
        """
        self.ml_engine.train_baseline(normal_features)

    def process_packet(self, packet: dict) -> dict:
        """Process a packet through signature rules then ML anomaly detector.

        Returns a detection dictionary when a signature or ML rule triggers,
        otherwise returns None.
        """

        # Step 1: Signature check
        sig_match = self.sig_engine.inspect(packet)
        if sig_match:
            sig_match['detection_type'] = 'Signature'
            return sig_match

        # Step 2: ML Anomaly check
        features = extract_iot_features(packet)
        ml_res = self.ml_engine.predict(features)

        if ml_res['is_anomaly']:
            return {
                'rule_id': 'ML-ANOMALY',
                'message': f"Behavioral Anomaly (Score: {ml_res['anomaly_score']})",
                'severity': 'High' if ml_res['anomaly_score'] > 0.5 else 'Medium',
                'src_ip': packet.get('src_ip'),
                'dst_ip': packet.get('dst_ip'),
                'detection_type': 'Machine Learning'
            }
        return None
