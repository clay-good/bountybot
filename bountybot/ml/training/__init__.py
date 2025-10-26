"""
AI Model Training & Fine-Tuning System

Provides comprehensive model training capabilities including:
- Custom model training on organization-specific data
- Transfer learning from pre-trained models
- Active learning with human-in-the-loop
- Model versioning and A/B testing
- Federated learning for multi-tenant scenarios
- Model explainability with SHAP/LIME
"""

from .models import (
    TrainingDataset,
    TrainingExample,
    ModelVersion,
    TrainingExperiment,
    ExperimentMetrics,
    ModelRegistry,
    ABTestConfig,
    ABTestResult,
    FederatedRound,
    ExplainabilityResult,
    DatasetSplit,
    TrainingStatus,
    ModelType,
    ExperimentStatus
)

from .training_pipeline import TrainingPipeline
from .transfer_learning import TransferLearningEngine
from .active_learning import ActiveLearningPipeline, SamplingStrategy
from .model_registry import ModelRegistryManager
from .ab_testing import ABTestingFramework
from .federated_learning import FederatedLearningCoordinator
from .explainability import ModelExplainer

__all__ = [
    # Models
    'TrainingDataset',
    'TrainingExample',
    'ModelVersion',
    'TrainingExperiment',
    'ExperimentMetrics',
    'ModelRegistry',
    'ABTestConfig',
    'ABTestResult',
    'FederatedRound',
    'ExplainabilityResult',
    'DatasetSplit',
    'TrainingStatus',
    'ModelType',
    'ExperimentStatus',
    
    # Components
    'TrainingPipeline',
    'TransferLearningEngine',
    'ActiveLearningPipeline',
    'SamplingStrategy',
    'ModelRegistryManager',
    'ABTestingFramework',
    'FederatedLearningCoordinator',
    'ModelExplainer',
]

