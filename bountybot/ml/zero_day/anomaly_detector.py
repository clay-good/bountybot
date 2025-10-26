"""Anomaly detector for zero-day prediction."""

import logging
from typing import Dict
import numpy as np

from bountybot.ml.zero_day.models import AnomalyScore, ZeroDayConfig

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detect anomalies in code patterns."""
    
    def __init__(self, config: ZeroDayConfig):
        self.config = config
    
    def detect(self, code: str, metadata: Dict) -> AnomalyScore:
        """
        Detect anomalies in code.
        
        Returns:
            Anomaly score
        """
        # Calculate features
        features = self._extract_features(code)
        
        # Calculate anomaly score (simplified - in production use Isolation Forest)
        score = self._calculate_anomaly_score(features)
        
        is_anomalous = score > self.config.anomaly_threshold
        
        return AnomalyScore(
            score=score,
            is_anomalous=is_anomalous,
            anomaly_type="statistical" if is_anomalous else "normal",
            confidence=0.8,
            contributing_features=features
        )
    
    def _extract_features(self, code: str) -> Dict[str, float]:
        """Extract features for anomaly detection."""
        return {
            'length': float(len(code)),
            'lines': float(code.count('\n')),
            'complexity': float(code.count('if') + code.count('for')),
        }
    
    def _calculate_anomaly_score(self, features: Dict[str, float]) -> float:
        """Calculate anomaly score."""
        # Simplified scoring
        values = list(features.values())
        if not values:
            return 0.0
        
        # Normalize and calculate score
        normalized = [min(1.0, v / 1000) for v in values]
        score = np.mean(normalized)
        
        return float(score)

