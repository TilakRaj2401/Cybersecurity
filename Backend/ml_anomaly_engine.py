"""IsolationForest-based anomaly detector for IoT feature vectors.

Provides a small wrapper around scikit-learn's IsolationForest used by
the project to score and flag anomalous network flow feature vectors.
"""

import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    """Wrapper around scikit-learn's IsolationForest for anomaly detection.

    Provides `train_baseline` to fit a model on normal traffic and `predict`
    to score incoming feature vectors for anomalous behavior.
    """

    def __init__(self):
        self.model = IsolationForest(n_estimators=50, contamination=0.1, random_state=42)
        self._is_trained = False

    def train_baseline(self, normal_features: np.ndarray):
        """Train isolation forest baseline using normal traffic features."""
        self.model.fit(normal_features)
        self._is_trained = True

    def predict(self, feature_vector: np.ndarray) -> dict:
        """Return a dict with anomaly decision and anomaly score for the
        provided feature vector.

        Raises:
            RuntimeError: if the detector has not been trained yet.
        """
        if not self._is_trained:
            raise RuntimeError("Model is not trained.")

        # Isolation Forest returns -1 for anomaly, 1 for normal
        pred = self.model.predict(feature_vector)[0]
        score = self.model.score_samples(feature_vector)[0]

        return {
            'is_anomaly': bool(pred == -1),
            'anomaly_score': round(float(-score), 4) # Higher score = higher anomaly
        }

if __name__ == '__main__':
    normal_data = np.random.normal(loc=100, scale=10, size=(200, 6))
    detector = AnomalyDetector()
    detector.train_baseline(normal_data)

    test_normal = np.random.normal(loc=100, scale=10, size=(1, 6))
    test_anomaly = np.array([[500, 10, 0, 80, 10.0, 7.9]])

    print("Normal Test:", detector.predict(test_normal))
    print("Anomaly Test:", detector.predict(test_anomaly))
