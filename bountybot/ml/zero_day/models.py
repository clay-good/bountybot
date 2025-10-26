"""Data models for zero-day prediction."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional
from datetime import datetime


class ThreatLevel(Enum):
    """Threat level classifications."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class VulnerabilityNovelty(Enum):
    """Novelty level of vulnerability."""
    COMPLETELY_NEW = "completely_new"
    VARIANT_OF_KNOWN = "variant_of_known"
    KNOWN_PATTERN = "known_pattern"


@dataclass
class PredictionFactors:
    """Factors contributing to zero-day prediction."""
    code_complexity: float = 0.0
    attack_surface: float = 0.0
    historical_vulnerability_density: float = 0.0
    code_change_frequency: float = 0.0
    dependency_risk: float = 0.0
    security_practices_score: float = 0.0
    anomaly_score: float = 0.0
    pattern_novelty: float = 0.0
    
    def get_weighted_score(self) -> float:
        """Calculate weighted prediction score."""
        weights = {
            'code_complexity': 0.15,
            'attack_surface': 0.20,
            'historical_vulnerability_density': 0.15,
            'code_change_frequency': 0.10,
            'dependency_risk': 0.15,
            'security_practices_score': 0.10,
            'anomaly_score': 0.10,
            'pattern_novelty': 0.05,
        }
        
        score = (
            self.code_complexity * weights['code_complexity'] +
            self.attack_surface * weights['attack_surface'] +
            self.historical_vulnerability_density * weights['historical_vulnerability_density'] +
            self.code_change_frequency * weights['code_change_frequency'] +
            self.dependency_risk * weights['dependency_risk'] +
            self.security_practices_score * weights['security_practices_score'] +
            self.anomaly_score * weights['anomaly_score'] +
            self.pattern_novelty * weights['pattern_novelty']
        )
        
        return score


@dataclass
class AnomalyScore:
    """Anomaly detection score."""
    score: float
    is_anomalous: bool
    anomaly_type: str
    confidence: float
    contributing_features: Dict[str, float] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ZeroDayPrediction:
    """Zero-day vulnerability prediction."""
    likelihood: float  # 0-1 probability
    threat_level: ThreatLevel
    novelty: VulnerabilityNovelty
    factors: PredictionFactors
    time_to_exploit_days: Optional[int] = None
    potential_impact: str = ""
    recommended_actions: List[str] = field(default_factory=list)
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def is_high_risk(self) -> bool:
        """Check if prediction indicates high risk."""
        return self.likelihood > 0.7 and self.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]
    
    def get_priority_score(self) -> float:
        """Calculate priority score for remediation."""
        threat_weights = {
            ThreatLevel.CRITICAL: 1.0,
            ThreatLevel.HIGH: 0.8,
            ThreatLevel.MEDIUM: 0.5,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.MINIMAL: 0.1,
        }
        
        return self.likelihood * threat_weights[self.threat_level] * self.confidence


@dataclass
class ZeroDayConfig:
    """Configuration for zero-day prediction."""
    anomaly_threshold: float = 0.7
    min_confidence: float = 0.6
    enable_pattern_analysis: bool = True
    enable_anomaly_detection: bool = True
    enable_threat_scoring: bool = True
    historical_window_days: int = 90

