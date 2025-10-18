"""
ML-based severity prediction for vulnerability reports.
"""

import logging
import statistics
from typing import Dict, List, Any, Optional
from collections import defaultdict

from .models import PredictionResult
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


class SeverityPredictor:
    """
    Predict vulnerability severity using ML.
    
    Uses historical data to predict:
    - CVSS score
    - Severity rating (Critical/High/Medium/Low)
    - Confidence in prediction
    """
    
    def __init__(self):
        """Initialize severity predictor."""
        self.feature_extractor = FeatureExtractor()
        
        # Training data storage
        self.training_data: List[tuple] = []  # (features, cvss_score, severity)
        
        # Simple statistical model (can be replaced with sklearn/tensorflow)
        self.severity_models: Dict[str, Dict[str, Any]] = {}
        
        logger.info("SeverityPredictor initialized")
    
    def train(self, reports: List[Any], validation_results: List[Any]):
        """
        Train the severity predictor.
        
        Args:
            reports: List of vulnerability reports
            validation_results: Corresponding validation results with CVSS scores
        """
        logger.info(f"Training severity predictor on {len(reports)} reports")
        
        # Clear existing training data
        self.training_data = []
        
        # Extract features and labels
        for report, validation in zip(reports, validation_results):
            if not hasattr(validation, 'cvss_score') or validation.cvss_score is None:
                continue
            
            features = self.feature_extractor.extract_from_report(report)
            cvss_score = validation.cvss_score
            severity = self._cvss_to_severity(cvss_score)
            
            self.training_data.append((features, cvss_score, severity))
        
        # Build statistical models by vulnerability type
        self._build_models()
        
        logger.info(f"Training complete: {len(self.training_data)} samples, {len(self.severity_models)} models")
    
    def predict(self, report: Any) -> PredictionResult:
        """
        Predict severity for a report.
        
        Args:
            report: Vulnerability report
            
        Returns:
            PredictionResult with predicted severity and confidence
        """
        features = self.feature_extractor.extract_from_report(report)
        vuln_type = features.get('vulnerability_type', 'unknown')
        
        # Get model for this vulnerability type
        model = self.severity_models.get(vuln_type)
        
        if not model:
            # Fall back to general model
            model = self.severity_models.get('_general_')
        
        if not model:
            # No training data available
            return PredictionResult(
                prediction_type='severity',
                predicted_value='medium',
                confidence=0.3,
                reasoning="Insufficient training data for prediction"
            )
        
        # Predict CVSS score
        predicted_cvss = self._predict_cvss(features, model)
        predicted_severity = self._cvss_to_severity(predicted_cvss)
        
        # Calculate confidence
        confidence = self._calculate_confidence(features, model)
        
        # Calculate probability distribution
        prob_dist = self._calculate_probability_distribution(predicted_cvss, confidence)
        
        # Feature importance
        feature_importance = self._calculate_feature_importance(features, model)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(features, predicted_cvss, predicted_severity, feature_importance)
        
        return PredictionResult(
            prediction_type='severity',
            predicted_value={
                'cvss_score': round(predicted_cvss, 1),
                'severity': predicted_severity
            },
            confidence=confidence,
            probability_distribution=prob_dist,
            features_used=list(features.keys()),
            feature_importance=feature_importance,
            reasoning=reasoning
        )
    
    def _build_models(self):
        """Build statistical models from training data."""
        # Group by vulnerability type
        grouped_data = defaultdict(list)
        
        for features, cvss_score, severity in self.training_data:
            vuln_type = features.get('vulnerability_type', 'unknown')
            grouped_data[vuln_type].append((features, cvss_score, severity))
        
        # Build model for each type
        for vuln_type, data in grouped_data.items():
            if len(data) < 3:
                continue
            
            cvss_scores = [cvss for _, cvss, _ in data]
            
            model = {
                'sample_count': len(data),
                'mean_cvss': statistics.mean(cvss_scores),
                'median_cvss': statistics.median(cvss_scores),
                'stdev_cvss': statistics.stdev(cvss_scores) if len(cvss_scores) > 1 else 0.0,
                'min_cvss': min(cvss_scores),
                'max_cvss': max(cvss_scores),
                
                # Feature statistics
                'feature_stats': self._calculate_feature_stats(data),
            }
            
            self.severity_models[vuln_type] = model
        
        # Build general model from all data
        if self.training_data:
            all_cvss = [cvss for _, cvss, _ in self.training_data]
            self.severity_models['_general_'] = {
                'sample_count': len(self.training_data),
                'mean_cvss': statistics.mean(all_cvss),
                'median_cvss': statistics.median(all_cvss),
                'stdev_cvss': statistics.stdev(all_cvss) if len(all_cvss) > 1 else 0.0,
                'min_cvss': min(all_cvss),
                'max_cvss': max(all_cvss),
                'feature_stats': self._calculate_feature_stats(self.training_data),
            }
    
    def _calculate_feature_stats(self, data: List[tuple]) -> Dict[str, Dict[str, float]]:
        """Calculate statistics for each feature."""
        feature_stats = defaultdict(lambda: {'values': [], 'cvss_correlation': 0.0})
        
        for features, cvss_score, _ in data:
            for key, value in features.items():
                if isinstance(value, (int, float, bool)):
                    numeric_value = float(value) if isinstance(value, bool) else value
                    feature_stats[key]['values'].append((numeric_value, cvss_score))
        
        # Calculate correlations
        stats = {}
        for key, data_dict in feature_stats.items():
            values = data_dict['values']
            if len(values) < 2:
                continue
            
            # Simple correlation calculation
            feature_values = [v[0] for v in values]
            cvss_values = [v[1] for v in values]
            
            correlation = self._calculate_correlation(feature_values, cvss_values)
            
            stats[key] = {
                'mean': statistics.mean(feature_values),
                'correlation': correlation
            }
        
        return stats
    
    def _calculate_correlation(self, x: List[float], y: List[float]) -> float:
        """Calculate Pearson correlation coefficient."""
        if len(x) != len(y) or len(x) < 2:
            return 0.0
        
        mean_x = statistics.mean(x)
        mean_y = statistics.mean(y)
        
        numerator = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
        denominator_x = sum((xi - mean_x) ** 2 for xi in x)
        denominator_y = sum((yi - mean_y) ** 2 for yi in y)
        
        if denominator_x == 0 or denominator_y == 0:
            return 0.0
        
        return numerator / (denominator_x * denominator_y) ** 0.5
    
    def _predict_cvss(self, features: Dict[str, Any], model: Dict[str, Any]) -> float:
        """Predict CVSS score using the model."""
        # Start with median as baseline
        predicted_cvss = model['median_cvss']
        
        # Adjust based on features
        feature_stats = model.get('feature_stats', {})
        
        adjustments = []
        for key, value in features.items():
            if key not in feature_stats:
                continue
            
            if not isinstance(value, (int, float, bool)):
                continue
            
            numeric_value = float(value) if isinstance(value, bool) else value
            stats = feature_stats[key]
            
            # Adjust based on correlation
            correlation = stats.get('correlation', 0.0)
            mean = stats.get('mean', 0.0)
            
            if mean != 0:
                deviation = (numeric_value - mean) / abs(mean)
                adjustment = correlation * deviation * model['stdev_cvss']
                adjustments.append(adjustment)
        
        # Apply adjustments (weighted average)
        if adjustments:
            avg_adjustment = sum(adjustments) / len(adjustments)
            predicted_cvss += avg_adjustment
        
        # Clamp to valid range
        predicted_cvss = max(0.0, min(10.0, predicted_cvss))
        
        return predicted_cvss
    
    def _calculate_confidence(self, features: Dict[str, Any], model: Dict[str, Any]) -> float:
        """Calculate confidence in prediction."""
        # Base confidence on sample size
        sample_count = model['sample_count']
        base_confidence = min(0.9, 0.5 + (sample_count / 100) * 0.4)
        
        # Reduce confidence if features are unusual
        feature_stats = model.get('feature_stats', {})
        unusual_features = 0
        total_features = 0
        
        for key, value in features.items():
            if key not in feature_stats or not isinstance(value, (int, float, bool)):
                continue
            
            total_features += 1
            numeric_value = float(value) if isinstance(value, bool) else value
            mean = feature_stats[key].get('mean', 0.0)
            
            # Check if value is unusual (more than 2 standard deviations from mean)
            if abs(numeric_value - mean) > 2 * model['stdev_cvss']:
                unusual_features += 1
        
        if total_features > 0:
            unusual_ratio = unusual_features / total_features
            confidence_penalty = unusual_ratio * 0.3
            base_confidence -= confidence_penalty
        
        return max(0.1, min(0.95, base_confidence))
    
    def _calculate_probability_distribution(self, predicted_cvss: float, confidence: float) -> Dict[str, float]:
        """Calculate probability distribution over severity levels."""
        predicted_severity = self._cvss_to_severity(predicted_cvss)
        
        # Base probabilities
        probs = {
            'critical': 0.0,
            'high': 0.0,
            'medium': 0.0,
            'low': 0.0
        }
        
        # Assign probability to predicted severity
        probs[predicted_severity] = confidence
        
        # Distribute remaining probability to adjacent severities
        remaining = 1.0 - confidence
        
        severity_order = ['low', 'medium', 'high', 'critical']
        predicted_idx = severity_order.index(predicted_severity)
        
        # Adjacent severities get more probability
        if predicted_idx > 0:
            probs[severity_order[predicted_idx - 1]] = remaining * 0.6
        if predicted_idx < len(severity_order) - 1:
            probs[severity_order[predicted_idx + 1]] = remaining * 0.4
        
        return probs
    
    def _calculate_feature_importance(self, features: Dict[str, Any], model: Dict[str, Any]) -> Dict[str, float]:
        """Calculate feature importance for the prediction."""
        feature_stats = model.get('feature_stats', {})
        importance = {}
        
        for key in features.keys():
            if key in feature_stats:
                # Importance based on correlation strength
                correlation = abs(feature_stats[key].get('correlation', 0.0))
                importance[key] = correlation
        
        # Normalize
        total = sum(importance.values())
        if total > 0:
            importance = {k: v / total for k, v in importance.items()}
        
        # Return top 5
        sorted_importance = sorted(importance.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_importance[:5])
    
    def _generate_reasoning(self, features: Dict[str, Any], cvss: float, severity: str, importance: Dict[str, float]) -> str:
        """Generate human-readable reasoning."""
        reasoning_parts = [
            f"Predicted CVSS score: {cvss:.1f} ({severity.upper()})"
        ]
        
        if importance:
            top_feature = list(importance.keys())[0]
            reasoning_parts.append(f"Most influential factor: {top_feature}")
        
        vuln_type = features.get('vulnerability_type', 'unknown')
        if vuln_type != 'unknown':
            reasoning_parts.append(f"Based on {vuln_type} vulnerability patterns")
        
        return ". ".join(reasoning_parts)
    
    def _cvss_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity rating."""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'

