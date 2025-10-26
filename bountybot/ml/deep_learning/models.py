"""
Data models for deep learning vulnerability classification.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime


class VulnerabilityType(Enum):
    """Types of vulnerabilities that can be classified."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    XXE = "xxe"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFO_DISCLOSURE = "info_disclosure"
    DESERIALIZATION = "deserialization"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"
    CRYPTOGRAPHIC_WEAKNESS = "cryptographic_weakness"
    BUSINESS_LOGIC = "business_logic"
    OTHER = "other"


@dataclass
class FeatureVector:
    """Feature vector for vulnerability classification."""
    # Text features
    title_tokens: List[str] = field(default_factory=list)
    description_tokens: List[str] = field(default_factory=list)
    
    # Numerical features
    title_length: int = 0
    description_length: int = 0
    num_urls: int = 0
    num_code_blocks: int = 0
    num_special_chars: int = 0
    
    # Categorical features
    has_poc: bool = False
    has_exploit: bool = False
    has_cve: bool = False
    
    # Keyword features
    keyword_counts: Dict[str, int] = field(default_factory=dict)
    
    # Embedding features (for neural networks)
    text_embedding: Optional[List[float]] = None
    
    def to_array(self) -> List[float]:
        """Convert feature vector to numerical array."""
        features = [
            float(self.title_length),
            float(self.description_length),
            float(self.num_urls),
            float(self.num_code_blocks),
            float(self.num_special_chars),
            float(self.has_poc),
            float(self.has_exploit),
            float(self.has_cve),
        ]
        
        # Add keyword counts
        for count in self.keyword_counts.values():
            features.append(float(count))
        
        # Add embedding if available
        if self.text_embedding:
            features.extend(self.text_embedding)
        
        return features


@dataclass
class ClassificationResult:
    """Result of vulnerability classification."""
    predicted_type: VulnerabilityType
    confidence: float
    probabilities: Dict[VulnerabilityType, float] = field(default_factory=dict)
    feature_importance: Dict[str, float] = field(default_factory=dict)
    model_version: str = "1.0.0"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def get_top_predictions(self, n: int = 3) -> List[tuple]:
        """Get top N predictions with probabilities."""
        sorted_probs = sorted(
            self.probabilities.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_probs[:n]
    
    def is_confident(self, threshold: float = 0.8) -> bool:
        """Check if prediction is confident."""
        return self.confidence >= threshold


@dataclass
class TrainingConfig:
    """Configuration for model training."""
    # Model architecture
    input_size: int = 128
    hidden_sizes: List[int] = field(default_factory=lambda: [256, 128, 64])
    output_size: int = 20  # Number of vulnerability types
    dropout_rate: float = 0.3
    
    # Training parameters
    learning_rate: float = 0.001
    batch_size: int = 32
    num_epochs: int = 100
    early_stopping_patience: int = 10
    
    # Data parameters
    train_split: float = 0.7
    val_split: float = 0.15
    test_split: float = 0.15
    
    # Regularization
    l2_regularization: float = 0.0001
    use_batch_normalization: bool = True
    
    # Optimization
    optimizer: str = "adam"
    loss_function: str = "cross_entropy"
    
    # Data augmentation
    use_augmentation: bool = True
    augmentation_factor: float = 0.2


@dataclass
class ModelMetrics:
    """Metrics for model evaluation."""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    
    # Per-class metrics
    per_class_precision: Dict[VulnerabilityType, float] = field(default_factory=dict)
    per_class_recall: Dict[VulnerabilityType, float] = field(default_factory=dict)
    per_class_f1: Dict[VulnerabilityType, float] = field(default_factory=dict)
    
    # Confusion matrix
    confusion_matrix: List[List[int]] = field(default_factory=list)
    
    # Training metrics
    training_loss: List[float] = field(default_factory=list)
    validation_loss: List[float] = field(default_factory=list)
    training_accuracy: List[float] = field(default_factory=list)
    validation_accuracy: List[float] = field(default_factory=list)
    
    # Model info
    num_parameters: int = 0
    training_time_seconds: float = 0.0
    model_size_mb: float = 0.0
    
    def get_macro_f1(self) -> float:
        """Calculate macro-averaged F1 score."""
        if not self.per_class_f1:
            return 0.0
        return sum(self.per_class_f1.values()) / len(self.per_class_f1)
    
    def get_weighted_f1(self, class_weights: Dict[VulnerabilityType, float]) -> float:
        """Calculate weighted F1 score."""
        if not self.per_class_f1:
            return 0.0
        
        weighted_sum = sum(
            self.per_class_f1[vuln_type] * class_weights.get(vuln_type, 1.0)
            for vuln_type in self.per_class_f1
        )
        total_weight = sum(class_weights.values())
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0


@dataclass
class TrainingExample:
    """Training example for vulnerability classification."""
    vulnerability_id: str
    title: str
    description: str
    true_type: VulnerabilityType
    features: Optional[FeatureVector] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class ModelCheckpoint:
    """Model checkpoint for saving/loading."""
    model_state: Dict
    optimizer_state: Dict
    epoch: int
    metrics: ModelMetrics
    config: TrainingConfig
    timestamp: datetime = field(default_factory=datetime.utcnow)
    version: str = "1.0.0"

