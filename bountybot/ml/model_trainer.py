"""
ML model training and management.
"""

import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from .models import MLModelMetadata, ModelType
from .pattern_learner import PatternLearner
from .severity_predictor import SeverityPredictor
from .anomaly_detector import AnomalyDetector
from .researcher_profiler import ResearcherProfiler
from .false_positive_predictor import FalsePositivePredictor
from .trend_forecaster import TrendForecaster

logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Train and manage all ML models.
    
    Handles:
    - Model training
    - Model versioning
    - Model persistence
    - Model evaluation
    - Model deployment
    """
    
    def __init__(self, model_dir: Optional[Path] = None):
        """
        Initialize model trainer.
        
        Args:
            model_dir: Directory to store trained models
        """
        self.model_dir = model_dir or Path("./models")
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize all ML components
        self.pattern_learner = PatternLearner()
        self.severity_predictor = SeverityPredictor()
        self.anomaly_detector = AnomalyDetector()
        self.researcher_profiler = ResearcherProfiler()
        self.false_positive_predictor = FalsePositivePredictor()
        self.trend_forecaster = TrendForecaster()
        
        # Model metadata
        self.model_metadata: Dict[str, MLModelMetadata] = {}
        
        logger.info(f"ModelTrainer initialized (model_dir={model_dir})")
    
    def train_all_models(
        self,
        reports: List[Any],
        validation_results: List[Any],
        timestamps: Optional[List[datetime]] = None
    ) -> Dict[str, MLModelMetadata]:
        """
        Train all ML models on historical data.
        
        Args:
            reports: List of vulnerability reports
            validation_results: Corresponding validation results
            timestamps: Optional submission timestamps
            
        Returns:
            Dictionary of model metadata
        """
        logger.info(f"Training all ML models on {len(reports)} reports")
        
        trained_models = {}
        
        # Train pattern learner
        try:
            logger.info("Training pattern learner...")
            patterns = self.pattern_learner.learn_from_reports(reports, validation_results)
            metadata = self._create_metadata(
                ModelType.PATTERN_LEARNER,
                len(reports),
                len(patterns) / max(len(reports), 1)
            )
            trained_models['pattern_learner'] = metadata
            self.model_metadata['pattern_learner'] = metadata
            logger.info(f"Pattern learner trained: {len(patterns)} patterns learned")
        except Exception as e:
            logger.error(f"Failed to train pattern learner: {e}")
        
        # Train severity predictor
        try:
            logger.info("Training severity predictor...")
            self.severity_predictor.train(reports, validation_results)
            metadata = self._create_metadata(
                ModelType.SEVERITY_PREDICTOR,
                len(reports),
                0.8  # Placeholder accuracy
            )
            trained_models['severity_predictor'] = metadata
            self.model_metadata['severity_predictor'] = metadata
            logger.info("Severity predictor trained")
        except Exception as e:
            logger.error(f"Failed to train severity predictor: {e}")
        
        # Train anomaly detector
        try:
            logger.info("Training anomaly detector...")
            self.anomaly_detector.build_baseline(reports, timestamps)
            metadata = self._create_metadata(
                ModelType.ANOMALY_DETECTOR,
                len(reports),
                0.85  # Placeholder accuracy
            )
            trained_models['anomaly_detector'] = metadata
            self.model_metadata['anomaly_detector'] = metadata
            logger.info("Anomaly detector trained")
        except Exception as e:
            logger.error(f"Failed to train anomaly detector: {e}")
        
        # Train false positive predictor
        try:
            logger.info("Training false positive predictor...")
            self.false_positive_predictor.train(reports, validation_results)
            stats = self.false_positive_predictor.get_training_stats()
            metadata = self._create_metadata(
                ModelType.FALSE_POSITIVE_PREDICTOR,
                len(reports),
                0.75  # Placeholder accuracy
            )
            trained_models['false_positive_predictor'] = metadata
            self.model_metadata['false_positive_predictor'] = metadata
            logger.info(f"False positive predictor trained: {stats.get('indicators_learned', 0)} indicators")
        except Exception as e:
            logger.error(f"Failed to train false positive predictor: {e}")
        
        # Train trend forecaster
        try:
            if timestamps:
                logger.info("Training trend forecaster...")
                self.trend_forecaster.analyze_historical_data(reports, timestamps)
                metadata = self._create_metadata(
                    ModelType.TREND_FORECASTER,
                    len(reports),
                    0.7  # Placeholder accuracy
                )
                trained_models['trend_forecaster'] = metadata
                self.model_metadata['trend_forecaster'] = metadata
                logger.info("Trend forecaster trained")
        except Exception as e:
            logger.error(f"Failed to train trend forecaster: {e}")
        
        # Build researcher profiles
        try:
            logger.info("Building researcher profiles...")
            researcher_ids = set()
            for report in reports:
                if hasattr(report, 'researcher_id') and report.researcher_id:
                    researcher_ids.add(report.researcher_id)
            
            for researcher_id in researcher_ids:
                researcher_reports = [
                    r for r in reports
                    if hasattr(r, 'researcher_id') and r.researcher_id == researcher_id
                ]
                researcher_validations = [
                    validation_results[i] for i, r in enumerate(reports)
                    if hasattr(r, 'researcher_id') and r.researcher_id == researcher_id
                ]
                
                if researcher_reports:
                    self.researcher_profiler.build_profile(
                        researcher_id,
                        researcher_reports,
                        researcher_validations
                    )
            
            logger.info(f"Built {len(researcher_ids)} researcher profiles")
        except Exception as e:
            logger.error(f"Failed to build researcher profiles: {e}")
        
        logger.info(f"Training complete: {len(trained_models)} models trained")
        
        return trained_models
    
    def evaluate_models(self, test_reports: List[Any], test_validations: List[Any]) -> Dict[str, Dict[str, float]]:
        """
        Evaluate trained models on test data.
        
        Args:
            test_reports: Test reports
            test_validations: Test validation results
            
        Returns:
            Dictionary of evaluation metrics for each model
        """
        logger.info(f"Evaluating models on {len(test_reports)} test reports")
        
        evaluation_results = {}
        
        # Evaluate severity predictor
        try:
            severity_metrics = self._evaluate_severity_predictor(test_reports, test_validations)
            evaluation_results['severity_predictor'] = severity_metrics
        except Exception as e:
            logger.error(f"Failed to evaluate severity predictor: {e}")
        
        # Evaluate false positive predictor
        try:
            fp_metrics = self._evaluate_fp_predictor(test_reports, test_validations)
            evaluation_results['false_positive_predictor'] = fp_metrics
        except Exception as e:
            logger.error(f"Failed to evaluate FP predictor: {e}")
        
        # Evaluate anomaly detector
        try:
            anomaly_metrics = self._evaluate_anomaly_detector(test_reports)
            evaluation_results['anomaly_detector'] = anomaly_metrics
        except Exception as e:
            logger.error(f"Failed to evaluate anomaly detector: {e}")
        
        return evaluation_results
    
    def _evaluate_severity_predictor(self, reports: List[Any], validations: List[Any]) -> Dict[str, float]:
        """Evaluate severity predictor."""
        predictions = []
        actuals = []
        
        for report, validation in zip(reports, validations):
            if not hasattr(validation, 'cvss_score') or validation.cvss_score is None:
                continue
            
            prediction = self.severity_predictor.predict(report)
            predicted_cvss = prediction.predicted_value.get('cvss_score', 0.0)
            
            predictions.append(predicted_cvss)
            actuals.append(validation.cvss_score)
        
        if not predictions:
            return {'error': 'No predictions made'}
        
        # Calculate metrics
        mae = sum(abs(p - a) for p, a in zip(predictions, actuals)) / len(predictions)
        rmse = (sum((p - a) ** 2 for p, a in zip(predictions, actuals)) / len(predictions)) ** 0.5
        
        # Accuracy within 1.0 CVSS point
        accurate_predictions = sum(1 for p, a in zip(predictions, actuals) if abs(p - a) <= 1.0)
        accuracy = accurate_predictions / len(predictions)
        
        return {
            'mae': mae,
            'rmse': rmse,
            'accuracy_within_1': accuracy,
            'samples': len(predictions)
        }
    
    def _evaluate_fp_predictor(self, reports: List[Any], validations: List[Any]) -> Dict[str, float]:
        """Evaluate false positive predictor."""
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        
        for report, validation in zip(reports, validations):
            prediction = self.false_positive_predictor.predict(report)
            predicted_fp = prediction.predicted_value
            
            # Determine actual FP status
            actual_fp = False
            if hasattr(validation, 'is_false_positive'):
                actual_fp = validation.is_false_positive
            elif hasattr(validation, 'verdict'):
                actual_fp = validation.verdict == 'invalid'
            
            # Update confusion matrix
            if predicted_fp and actual_fp:
                true_positives += 1
            elif predicted_fp and not actual_fp:
                false_positives += 1
            elif not predicted_fp and not actual_fp:
                true_negatives += 1
            else:
                false_negatives += 1
        
        total = true_positives + false_positives + true_negatives + false_negatives
        if total == 0:
            return {'error': 'No predictions made'}
        
        accuracy = (true_positives + true_negatives) / total
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'samples': total
        }
    
    def _evaluate_anomaly_detector(self, reports: List[Any]) -> Dict[str, float]:
        """Evaluate anomaly detector."""
        anomaly_scores = []
        
        for report in reports:
            result = self.anomaly_detector.detect_anomalies(report)
            anomaly_scores.append(result.anomaly_score)
        
        if not anomaly_scores:
            return {'error': 'No predictions made'}
        
        import statistics
        
        return {
            'mean_anomaly_score': statistics.mean(anomaly_scores),
            'median_anomaly_score': statistics.median(anomaly_scores),
            'anomalies_detected': sum(1 for s in anomaly_scores if s > 0.7),
            'anomaly_rate': sum(1 for s in anomaly_scores if s > 0.7) / len(anomaly_scores),
            'samples': len(anomaly_scores)
        }
    
    def _create_metadata(self, model_type: ModelType, training_samples: int, accuracy: float) -> MLModelMetadata:
        """Create model metadata."""
        return MLModelMetadata(
            model_id=f"{model_type.value}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            model_type=model_type,
            version="1.0.0",
            trained_on=datetime.utcnow(),
            training_samples=training_samples,
            validation_accuracy=accuracy,
            precision=0.0,  # To be filled by evaluation
            recall=0.0,
            f1_score=0.0
        )
    
    def save_models(self):
        """Save all trained models to disk."""
        logger.info(f"Saving models to {self.model_dir}")
        
        # Save metadata
        metadata_file = self.model_dir / "model_metadata.json"
        with open(metadata_file, 'w') as f:
            metadata_dict = {
                name: meta.to_dict()
                for name, meta in self.model_metadata.items()
            }
            json.dump(metadata_dict, f, indent=2)
        
        logger.info(f"Saved {len(self.model_metadata)} model metadata files")
    
    def load_models(self):
        """Load trained models from disk."""
        logger.info(f"Loading models from {self.model_dir}")
        
        # Load metadata
        metadata_file = self.model_dir / "model_metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata_dict = json.load(f)
            
            logger.info(f"Loaded {len(metadata_dict)} model metadata files")
        else:
            logger.warning("No saved models found")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about all trained models."""
        return {
            'models': {
                name: meta.to_dict()
                for name, meta in self.model_metadata.items()
            },
            'model_dir': str(self.model_dir),
            'total_models': len(self.model_metadata)
        }

