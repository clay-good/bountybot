"""Pattern analyzer for zero-day prediction."""

import logging
from typing import Dict
import re

from bountybot.ml.zero_day.models import ZeroDayConfig

logger = logging.getLogger(__name__)


class PatternAnalyzer:
    """Analyze code patterns for novelty."""
    
    KNOWN_PATTERNS = [
        r'eval\s*\(',
        r'exec\s*\(',
        r'system\s*\(',
        r'innerHTML\s*=',
    ]
    
    def __init__(self, config: ZeroDayConfig):
        self.config = config
    
    def analyze(self, code: str, metadata: Dict) -> float:
        """
        Analyze code patterns for novelty.
        
        Returns:
            Pattern novelty score (0-1)
        """
        # Count known patterns
        known_count = sum(
            len(re.findall(pattern, code, re.IGNORECASE))
            for pattern in self.KNOWN_PATTERNS
        )
        
        # Calculate novelty (inverse of known patterns)
        total_patterns = max(1, known_count + 10)
        novelty = 1.0 - (known_count / total_patterns)
        
        return novelty

