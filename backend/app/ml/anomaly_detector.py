"""
Isolation Forest Anomaly Detection Engine

Theoretical Basis:
  - Builds a forest of iTrees (Isolation Trees)
  - Anomalies are "few and different" — require fewer random splits
  - Path Length h(x): edges from root to leaf node
  - Average path length: c(n) = 2H(n-1) - (2(n-1)/n)
    where H(i) = ln(i) + 0.5772156649 (Euler's constant)
  - Anomaly score: s(x, n) = 2^(-E(h(x))/c(n))
  
Interpretation:
  - s → 1: Definite anomaly (very short path)
  - s < 0.5: Normal instance
  - s ≈ 0.5: No distinct anomalies in sample
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
from typing import Optional
from ..config import settings


class VotingAnomalyDetector:
    """
    Real-time anomaly detection for the e-voting system.
    Detects: bot voting, rapid submissions, duplicate IP patterns.
    """

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=settings.isolation_forest_contamination,
            random_state=42,
            max_samples="auto"
        )
        self.is_trained = False
        self.training_data = []
        self.threshold = settings.anomaly_score_threshold

    def extract_features(
        self,
        ip_address: str,
        user_agent: str,
        time_since_login: float,       # seconds
        login_hour: int,               # hour of day (0–23)
        votes_from_ip: int,            # total votes from this IP
        session_duration: float,       # seconds from login to vote
        page_interactions: int = 1,    # number of clicks before voting
    ) -> list[float]:
        """
        Extract numerical feature vector for anomaly detection.
        Features are designed to capture both human and bot patterns.
        """
        # Encode time_since_login (bots are typically very fast)
        speed_score = 1.0 / (time_since_login + 1)  # higher = faster = more suspicious

        # Encode login_hour (normalize to 0-1)
        hour_normalized = login_hour / 23.0

        # IP voting frequency
        ip_freq = min(votes_from_ip, 10) / 10.0

        # Session duration (bots have very short or very long sessions)
        session_score = 1.0 / (session_duration + 1)

        # User agent complexity (simple/missing UA = suspicious)
        ua_length = min(len(user_agent), 200) / 200.0

        return [
            speed_score,
            hour_normalized,
            ip_freq,
            session_score,
            ua_length,
            float(page_interactions),
        ]

    def add_training_sample(self, features: list[float]):
        """Add a sample to the training buffer."""
        self.training_data.append(features)
        # Retrain once we have enough samples
        if len(self.training_data) >= 10:
            self._train()

    def _train(self):
        """Train the Isolation Forest on collected samples."""
        if len(self.training_data) < 5:
            return
        X = np.array(self.training_data)
        self.model.fit(X)
        self.is_trained = True

    def score(self, features: list[float]) -> float:
        """
        Compute anomaly score for a feature vector.
        Returns a score between 0 and 1.
        
        Score → 1: Definite anomaly
        Score < 0.5: Normal
        """
        if not self.is_trained:
            # Not enough data — use heuristic scoring
            return self._heuristic_score(features)

        X = np.array([features])
        # sklearn's decision_function returns negative values for anomalies
        raw_score = self.model.decision_function(X)[0]
        # Normalize to 0–1 range (invert so high = anomalous)
        normalized = 1 - (raw_score + 0.5)
        return float(np.clip(normalized, 0.0, 1.0))

    def _heuristic_score(self, features: list[float]) -> float:
        """
        Heuristic scoring when model isn't trained yet.
        Based on known bot indicators.
        """
        speed_score, hour_norm, ip_freq, session_score, ua_length, interactions = features

        suspicion = 0.0
        # Very fast voting
        if speed_score > 0.8:
            suspicion += 0.4
        # Many votes from same IP
        if ip_freq > 0.3:
            suspicion += 0.3
        # Very short session
        if session_score > 0.9:
            suspicion += 0.2
        # Missing/simple user agent
        if ua_length < 0.1:
            suspicion += 0.1

        return min(suspicion, 1.0)

    def is_anomalous(self, features: list[float]) -> tuple[bool, float]:
        """
        Determine if a voting session is anomalous.
        Returns (is_flagged, anomaly_score).
        """
        score = self.score(features)
        return score >= self.threshold, score


# Global detector instance
detector = VotingAnomalyDetector()
