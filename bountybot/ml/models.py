"""
Data models for ML module.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum


class ModelType(Enum):
    """Types of ML models."""
    PATTERN_LEARNER = "pattern_learner"
    SEVERITY_PREDICTOR = "severity_predictor"
    ANOMALY_DETECTOR = "anomaly_detector"
    FALSE_POSITIVE_PREDICTOR = "false_positive_predictor"
    TREND_FORECASTER = "trend_forecaster"


class AnomalyType(Enum):
    """Types of anomalies."""
    NOVEL_ATTACK = "novel_attack"
    UNUSUAL_PATTERN = "unusual_pattern"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    OUTLIER_SEVERITY = "outlier_severity"
    ABNORMAL_TIMING = "abnormal_timing"


@dataclass
class VulnerabilityPattern:
    """Learned vulnerability pattern."""
    
    pattern_id: str
    vulnerability_type: str
    features: Dict[str, Any]
    frequency: int
    confidence: float
    examples: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    
    # Pattern characteristics
    common_keywords: List[str] = field(default_factory=list)
    common_endpoints: List[str] = field(default_factory=list)
    common_parameters: List[str] = field(default_factory=list)
    typical_severity_range: tuple = (0.0, 10.0)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'pattern_id': self.pattern_id,
            'vulnerability_type': self.vulnerability_type,
            'features': self.features,
            'frequency': self.frequency,
            'confidence': self.confidence,
            'examples': self.examples[:5],  # Limit examples
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'common_keywords': self.common_keywords,
            'common_endpoints': self.common_endpoints,
            'common_parameters': self.common_parameters,
            'typical_severity_range': self.typical_severity_range
        }


@dataclass
class PredictionResult:
    """Result of ML prediction."""
    
    prediction_type: str
    predicted_value: Any
    confidence: float
    probability_distribution: Dict[str, float] = field(default_factory=dict)
    
    # Supporting information
    features_used: List[str] = field(default_factory=list)
    model_version: str = "1.0.0"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Explanation
    feature_importance: Dict[str, float] = field(default_factory=dict)
    reasoning: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'prediction_type': self.prediction_type,
            'predicted_value': self.predicted_value,
            'confidence': round(self.confidence, 3),
            'probability_distribution': {
                k: round(v, 3) for k, v in self.probability_distribution.items()
            },
            'features_used': self.features_used,
            'model_version': self.model_version,
            'timestamp': self.timestamp.isoformat(),
            'feature_importance': {
                k: round(v, 3) for k, v in self.feature_importance.items()
            },
            'reasoning': self.reasoning
        }


@dataclass
class AnomalyScore:
    """Anomaly detection result."""
    
    is_anomaly: bool
    anomaly_score: float  # 0.0 = normal, 1.0 = highly anomalous
    anomaly_type: Optional[AnomalyType]
    
    # Details
    expected_range: tuple = (0.0, 1.0)
    actual_value: float = 0.0
    deviation_sigma: float = 0.0  # Standard deviations from mean
    
    # Context
    similar_cases: List[str] = field(default_factory=list)
    explanation: str = ""
    recommendations: List[str] = field(default_factory=list)
    
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'is_anomaly': self.is_anomaly,
            'anomaly_score': round(self.anomaly_score, 3),
            'anomaly_type': self.anomaly_type.value if self.anomaly_type else None,
            'expected_range': self.expected_range,
            'actual_value': round(self.actual_value, 3),
            'deviation_sigma': round(self.deviation_sigma, 2),
            'similar_cases': self.similar_cases[:5],
            'explanation': self.explanation,
            'recommendations': self.recommendations,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ResearcherProfile:
    """ML-based researcher profile."""
    
    researcher_id: str
    total_submissions: int
    valid_submissions: int
    
    # Quality metrics
    average_severity: float
    average_confidence: float
    false_positive_rate: float
    duplicate_rate: float
    
    # Specialization
    specializations: List[str] = field(default_factory=list)
    preferred_targets: List[str] = field(default_factory=list)
    
    # Behavioral patterns
    submission_frequency: float = 0.0  # Reports per day
    peak_hours: List[int] = field(default_factory=list)
    typical_report_length: int = 0
    
    # Reputation
    reputation_score: float = 0.0  # 0-100
    trust_level: str = "unknown"  # unknown, low, medium, high, expert
    
    # Predictions
    predicted_next_submission: Optional[datetime] = None
    predicted_quality: float = 0.0
    
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'researcher_id': self.researcher_id,
            'total_submissions': self.total_submissions,
            'valid_submissions': self.valid_submissions,
            'quality_metrics': {
                'average_severity': round(self.average_severity, 2),
                'average_confidence': round(self.average_confidence, 2),
                'false_positive_rate': round(self.false_positive_rate, 3),
                'duplicate_rate': round(self.duplicate_rate, 3)
            },
            'specializations': self.specializations,
            'preferred_targets': self.preferred_targets,
            'behavioral_patterns': {
                'submission_frequency': round(self.submission_frequency, 2),
                'peak_hours': self.peak_hours,
                'typical_report_length': self.typical_report_length
            },
            'reputation': {
                'reputation_score': round(self.reputation_score, 1),
                'trust_level': self.trust_level
            },
            'predictions': {
                'predicted_next_submission': self.predicted_next_submission.isoformat() if self.predicted_next_submission else None,
                'predicted_quality': round(self.predicted_quality, 2)
            },
            'last_updated': self.last_updated.isoformat()
        }


@dataclass
class MLModelMetadata:
    """Metadata for ML models."""
    
    model_id: str
    model_type: ModelType
    version: str
    
    # Training info
    trained_on: datetime
    training_samples: int
    validation_accuracy: float
    
    # Performance metrics
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    
    # Model details
    features: List[str] = field(default_factory=list)
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    
    # Usage stats
    predictions_made: int = 0
    last_used: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'model_id': self.model_id,
            'model_type': self.model_type.value,
            'version': self.version,
            'training_info': {
                'trained_on': self.trained_on.isoformat(),
                'training_samples': self.training_samples,
                'validation_accuracy': round(self.validation_accuracy, 3)
            },
            'performance_metrics': {
                'precision': round(self.precision, 3),
                'recall': round(self.recall, 3),
                'f1_score': round(self.f1_score, 3)
            },
            'features': self.features,
            'hyperparameters': self.hyperparameters,
            'usage_stats': {
                'predictions_made': self.predictions_made,
                'last_used': self.last_used.isoformat() if self.last_used else None
            }
        }

