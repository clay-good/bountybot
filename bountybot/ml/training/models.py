"""
Data models for AI model training and fine-tuning system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4


class TrainingStatus(Enum):
    """Training status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ModelType(Enum):
    """Model type."""
    VULNERABILITY_CLASSIFIER = "vulnerability_classifier"
    CODE_ANALYZER = "code_analyzer"
    EXPLOIT_GENERATOR = "exploit_generator"
    ZERO_DAY_PREDICTOR = "zero_day_predictor"
    CUSTOM = "custom"


class ExperimentStatus(Enum):
    """Experiment status."""
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class DatasetSplit(Enum):
    """Dataset split type."""
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


@dataclass
class TrainingExample:
    """Single training example."""
    example_id: str = field(default_factory=lambda: str(uuid4()))
    input_data: Dict[str, Any] = field(default_factory=dict)
    label: str = ""
    confidence: float = 1.0  # Confidence in label (for active learning)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    labeled_by: Optional[str] = None  # User who labeled this
    split: DatasetSplit = DatasetSplit.TRAIN


@dataclass
class TrainingDataset:
    """Training dataset."""
    dataset_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    model_type: ModelType = ModelType.VULNERABILITY_CLASSIFIER
    examples: List[TrainingExample] = field(default_factory=list)
    num_classes: int = 0
    class_names: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    tenant_id: Optional[str] = None  # For multi-tenant scenarios
    
    def get_split(self, split: DatasetSplit) -> List[TrainingExample]:
        """Get examples for a specific split."""
        return [ex for ex in self.examples if ex.split == split]
    
    def get_class_distribution(self) -> Dict[str, int]:
        """Get distribution of classes in dataset."""
        distribution = {}
        for example in self.examples:
            label = example.label
            distribution[label] = distribution.get(label, 0) + 1
        return distribution


@dataclass
class ExperimentMetrics:
    """Training experiment metrics."""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    loss: float = 0.0
    val_accuracy: float = 0.0
    val_loss: float = 0.0
    training_time_seconds: float = 0.0
    num_epochs: int = 0
    best_epoch: int = 0
    confusion_matrix: Optional[List[List[int]]] = None
    per_class_metrics: Dict[str, Dict[str, float]] = field(default_factory=dict)
    learning_curve: List[Dict[str, float]] = field(default_factory=list)


@dataclass
class TrainingExperiment:
    """Training experiment."""
    experiment_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    model_type: ModelType = ModelType.VULNERABILITY_CLASSIFIER
    dataset_id: str = ""
    base_model_id: Optional[str] = None  # For transfer learning
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    status: ExperimentStatus = ExperimentStatus.CREATED
    metrics: Optional[ExperimentMetrics] = None
    model_path: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: Optional[str] = None
    error_message: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class ModelVersion:
    """Model version."""
    version_id: str = field(default_factory=lambda: str(uuid4()))
    model_name: str = ""
    version: str = "1.0.0"
    model_type: ModelType = ModelType.VULNERABILITY_CLASSIFIER
    experiment_id: str = ""
    model_path: str = ""
    metrics: Optional[ExperimentMetrics] = None
    is_production: bool = False
    is_champion: bool = False  # Best performing model
    created_at: datetime = field(default_factory=datetime.utcnow)
    deployed_at: Optional[datetime] = None
    deprecated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelRegistry:
    """Model registry for versioning."""
    registry_id: str = field(default_factory=lambda: str(uuid4()))
    model_name: str = ""
    model_type: ModelType = ModelType.VULNERABILITY_CLASSIFIER
    versions: List[ModelVersion] = field(default_factory=list)
    champion_version_id: Optional[str] = None
    production_version_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def get_champion(self) -> Optional[ModelVersion]:
        """Get champion model version."""
        if not self.champion_version_id:
            return None
        for version in self.versions:
            if version.version_id == self.champion_version_id:
                return version
        return None
    
    def get_production(self) -> Optional[ModelVersion]:
        """Get production model version."""
        if not self.production_version_id:
            return None
        for version in self.versions:
            if version.version_id == self.production_version_id:
                return version
        return None


@dataclass
class ABTestConfig:
    """A/B test configuration."""
    test_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    model_a_version_id: str = ""  # Control
    model_b_version_id: str = ""  # Treatment
    traffic_split: float = 0.5  # % traffic to model B
    start_date: datetime = field(default_factory=datetime.utcnow)
    end_date: Optional[datetime] = None
    min_samples: int = 100  # Minimum samples before declaring winner
    confidence_level: float = 0.95
    is_active: bool = True
    created_by: Optional[str] = None


@dataclass
class ABTestResult:
    """A/B test result."""
    test_id: str = ""
    model_a_samples: int = 0
    model_b_samples: int = 0
    model_a_accuracy: float = 0.0
    model_b_accuracy: float = 0.0
    model_a_latency_ms: float = 0.0
    model_b_latency_ms: float = 0.0
    statistical_significance: bool = False
    p_value: float = 1.0
    winner: Optional[str] = None  # "A", "B", or None
    confidence: float = 0.0
    recommendation: str = ""
    detailed_metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FederatedRound:
    """Federated learning round."""
    round_id: str = field(default_factory=lambda: str(uuid4()))
    round_number: int = 0
    global_model_version: str = ""
    participating_tenants: List[str] = field(default_factory=list)
    tenant_updates: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    aggregated_metrics: Optional[ExperimentMetrics] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: TrainingStatus = TrainingStatus.PENDING


@dataclass
class ExplainabilityResult:
    """Model explainability result."""
    prediction_id: str = field(default_factory=lambda: str(uuid4()))
    model_version_id: str = ""
    input_data: Dict[str, Any] = field(default_factory=dict)
    prediction: str = ""
    confidence: float = 0.0
    feature_importance: Dict[str, float] = field(default_factory=dict)
    shap_values: Optional[Dict[str, float]] = None
    lime_explanation: Optional[Dict[str, Any]] = None
    top_features: List[tuple] = field(default_factory=list)  # [(feature, importance)]
    explanation_text: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)

