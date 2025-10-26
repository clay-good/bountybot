"""
Deep Learning Module for Vulnerability Classification

This module provides deep learning models for advanced vulnerability classification
using neural networks with multi-class classification capabilities.
"""

from bountybot.ml.deep_learning.models import (
    VulnerabilityType,
    ClassificationResult,
    TrainingConfig,
    ModelMetrics,
    FeatureVector
)

from bountybot.ml.deep_learning.vulnerability_classifier import VulnerabilityClassifier
from bountybot.ml.deep_learning.neural_network import NeuralNetwork
from bountybot.ml.deep_learning.training_pipeline import TrainingPipeline
from bountybot.ml.deep_learning.feature_engineering import FeatureEngineering

__all__ = [
    "VulnerabilityType",
    "ClassificationResult",
    "TrainingConfig",
    "ModelMetrics",
    "FeatureVector",
    "VulnerabilityClassifier",
    "NeuralNetwork",
    "TrainingPipeline",
    "FeatureEngineering",
]

