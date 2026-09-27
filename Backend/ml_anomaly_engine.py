"""IsolationForest-based anomaly detector for IoT feature vectors.

Provides a small wrapper around scikit-learn's IsolationForest used by
the project to score and flag anomalous network flow feature vectors.
The detector also supports training from legacy public IDS datasets such as
NSL-KDD, KDDCup99, and UNSW-NB15 when a numeric feature matrix is supplied.
"""

from __future__ import annotations

from typing import Iterable
from urllib.request import urlopen

import numpy as np
from sklearn.ensemble import IsolationForest

try:
    import pandas as pd
except ImportError:  # pragma: no cover - optional dependency for dataframe handling
    pd = None


class AnomalyDetector:
    """Wrapper around scikit-learn's IsolationForest for anomaly detection.

    Provides `train_baseline` to fit a model on normal traffic and `predict`
    to score incoming feature vectors for anomalous behavior. It also accepts
    numeric arrays or pandas DataFrames extracted from public IDS datasets.
    """

    PUBLIC_DATASETS = {
        'KDDCup99': (
            'https://archive.ics.uci.edu/ml/machine-learning-databases/'
            'kddcup99-mld/kddcup.data_10_percent.gz'
        ),
        'NSL-KDD': (
            'https://archive.ics.uci.edu/ml/machine-learning-databases/'
            'kddcup99-mld/kddcup.data_10_percent.gz'
        ),
        'UNSW-NB15': 'https://research.unsw.edu.au/projects/unsw-nb15-dataset',
        'CICIDS2017': 'https://www.unb.ca/cic/datasets/ids-2017.html',
    }

    def __init__(self):
        self.model = IsolationForest(n_estimators=50, contamination=0.1, random_state=42)
        self._is_trained = False

    @staticmethod
    def _coerce_features(features: Iterable | np.ndarray) -> np.ndarray:
        """Convert a dataframe or array-like structure into 2D numeric data."""
        if pd is not None and hasattr(features, 'to_numpy'):
            arr = features.to_numpy(dtype=np.float32)
        else:
            arr = np.asarray(features, dtype=np.float32)

        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return arr

    def train_baseline(self, normal_features: np.ndarray):
        """Train isolation forest baseline using normal traffic features."""
        arr = self._coerce_features(normal_features)
        self.model.fit(arr)
        self._is_trained = True
        return arr

    def train_from_dataframe(self, feature_frame):
        """Train the detector using dataset-derived numeric features."""
        arr = self._coerce_features(feature_frame)
        return self.train_baseline(arr)

    @classmethod
    def load_public_dataset(
        cls,
        dataset_name: str = 'NSL-KDD',
        *,
        local_path: str | None = None,
    ):
        """Return a public IDS dataset URL or local CSV content when available."""
        if local_path:
            with open(local_path, 'r', encoding='utf-8', errors='ignore') as handle:
                return handle.read()

        dataset_url = cls.PUBLIC_DATASETS.get(dataset_name)
        if dataset_url is None:
            raise ValueError(
                f"Unsupported dataset '{dataset_name}'. "
                f"Choose one of: {', '.join(cls.PUBLIC_DATASETS)}"
            )

        with urlopen(dataset_url, timeout=20) as response:
            return response.read().decode('utf-8', errors='ignore')

    def train_from_public_dataset(
        self,
        dataset_name: str = 'NSL-KDD',
        *,
        feature_columns=None,
        local_path: str | None = None,
    ):
        """Train from a public dataset by selecting numeric feature columns."""
        if pd is None:
            raise ImportError(
                'pandas is required to read public IDS datasets. '
                'Install pandas to enable dataset-backed training.'
            )

        data = self.load_public_dataset(dataset_name, local_path=local_path)
        if data.startswith('http'):
            return None

        df = pd.read_csv(data if not local_path else local_path)
        if feature_columns is not None:
            features = df[list(feature_columns)]
        else:
            features = df.select_dtypes(include=['number'])
        return self.train_from_dataframe(features)

    def predict(self, feature_vector: np.ndarray) -> dict:
        """Return a dict with anomaly decision and anomaly score for the
        provided feature vector.

        Raises:
            RuntimeError: if the detector has not been trained yet.
        """
        if not self._is_trained:
            raise RuntimeError("Model is not trained.")

        arr = self._coerce_features(feature_vector)

        # Isolation Forest returns -1 for anomaly, 1 for normal
        pred = self.model.predict(arr)[0]
        score = self.model.score_samples(arr)[0]

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
