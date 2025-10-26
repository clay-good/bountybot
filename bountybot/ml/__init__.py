"""
Machine Learning & Predictive Analytics Module for BountyBot.

This module provides ML-powered capabilities for:
- Vulnerability pattern learning
- Predictive severity scoring
- Anomaly detection
- Researcher profiling
- False positive prediction
- Trend forecasting
- Deep learning vulnerability classification (v2.17.0)
- Transformer-based code analysis (v2.17.0)
- Automated exploit generation (v2.17.0)
- Zero-day prediction (v2.17.0)
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

    # Advanced ML features (v2.17.0)
    try:
        from .deep_learning import (
            VulnerabilityClassifier,
            NeuralNetwork,
            TrainingPipeline,
            FeatureEngineering,
            VulnerabilityType,
            ClassificationResult,
            TrainingConfig,
            ModelMetrics
        )

        from .transformers import (
            CodeAnalyzer,
            CodeTokenizer,
            VulnerabilityDetector,
            CodeEmbeddings,
            TransformerConfig,
            CodeAnalysisResult,
            VulnerabilityPattern as TransformerVulnPattern
        )

        from .exploit_generation import (
            ExploitGenerator,
            PayloadGenerator,
            ExploitValidator,
            TemplateEngine,
            ExploitType,
            ExploitResult,
            PayloadTemplate,
            SafetyConstraints
        )

        from .zero_day import (
            ZeroDayPredictor,
            PatternAnalyzer,
            AnomalyDetector as ZeroDayAnomalyDetector,
            ThreatScorer,
            ZeroDayPrediction,
            AnomalyScore as ZeroDayAnomalyScore,
            ThreatLevel,
            PredictionFactors
        )

        ADVANCED_ML_AVAILABLE = True
    except ImportError as e:
        import logging
        logging.warning(f"Advanced ML features not available: {e}")
        ADVANCED_ML_AVAILABLE = False

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

    if ADVANCED_ML_AVAILABLE:
        __all__.extend([
            # Deep Learning
            'VulnerabilityClassifier',
            'NeuralNetwork',
            'TrainingPipeline',
            'FeatureEngineering',
            'VulnerabilityType',
            'ClassificationResult',
            'TrainingConfig',
            'ModelMetrics',

            # Transformers
            'CodeAnalyzer',
            'CodeTokenizer',
            'VulnerabilityDetector',
            'CodeEmbeddings',
            'TransformerConfig',
            'CodeAnalysisResult',

            # Exploit Generation
            'ExploitGenerator',
            'PayloadGenerator',
            'ExploitValidator',
            'TemplateEngine',
            'ExploitType',
            'ExploitResult',
            'PayloadTemplate',
            'SafetyConstraints',

            # Zero-Day Prediction
            'ZeroDayPredictor',
            'PatternAnalyzer',
            'ZeroDayAnomalyDetector',
            'ThreatScorer',
            'ZeroDayPrediction',
            'ZeroDayAnomalyScore',
            'ThreatLevel',
            'PredictionFactors',
        ])

except ImportError as e:
    # Graceful degradation if ML dependencies are missing
    import logging
    logging.warning(f"ML module not fully available: {e}")
    __all__ = []
    ADVANCED_ML_AVAILABLE = False

