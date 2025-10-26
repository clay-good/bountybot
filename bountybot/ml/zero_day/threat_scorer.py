"""Threat scorer for zero-day prediction."""

import logging
from typing import Dict

from bountybot.ml.zero_day.models import ZeroDayConfig, ThreatLevel

logger = logging.getLogger(__name__)


class ThreatScorer:
    """Score threat level of potential vulnerabilities."""
    
    def __init__(self, config: ZeroDayConfig):
        self.config = config
    
    def score(self, factors: Dict[str, float]) -> ThreatLevel:
        """
        Score threat level based on factors.
        
        Args:
            factors: Dictionary of threat factors
        
        Returns:
            Threat level
        """
        # Calculate weighted score
        total_score = sum(factors.values()) / len(factors) if factors else 0.0
        
        # Map to threat level
        if total_score >= 0.8:
            return ThreatLevel.CRITICAL
        elif total_score >= 0.6:
            return ThreatLevel.HIGH
        elif total_score >= 0.4:
            return ThreatLevel.MEDIUM
        elif total_score >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.MINIMAL

