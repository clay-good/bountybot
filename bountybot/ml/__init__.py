"""
Machine Learning & Predictive Analytics Module for BountyBot.

This module provides ML-powered capabilities for:
- Vulnerability pattern learning
- Predictive severity scoring
- Anomaly detection
- Researcher profiling
- False positive prediction
- Trend forecasting
"""

try:
    from .models import (
        VulnerabilityPattern,
        PredictionResult,
        AnomalyScore,
        ResearcherProfile,
        MLModelMetadata
    )
    
    from .pattern_learner import PatternLearner
    from .severity_predictor import SeverityPredictor
    from .anomaly_detector import AnomalyDetector
    from .researcher_profiler import ResearcherProfiler
    from .false_positive_predictor import FalsePositivePredictor
    from .trend_forecaster import TrendForecaster
    from .model_trainer import ModelTrainer
    from .feature_extractor import FeatureExtractor
    
    __all__ = [
        # Models
        'VulnerabilityPattern',
        'PredictionResult',
        'AnomalyScore',
        'ResearcherProfile',
        'MLModelMetadata',
        
        # Core ML Components
        'PatternLearner',
        'SeverityPredictor',
        'AnomalyDetector',
        'ResearcherProfiler',
        'FalsePositivePredictor',
        'TrendForecaster',
        'ModelTrainer',
        'FeatureExtractor',
    ]
    
except ImportError as e:
    # Graceful degradation if ML dependencies are missing
    import logging
    logging.warning(f"ML module not fully available: {e}")
    __all__ = []

