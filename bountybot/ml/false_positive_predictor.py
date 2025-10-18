"""
ML-based false positive prediction.
"""

import logging
import statistics
from typing import Dict, List, Any, Optional
from collections import defaultdict

from .models import PredictionResult
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


class FalsePositivePredictor:
    """
    Predict likelihood of false positives using ML.
    
    Analyzes:
    - Report quality indicators
    - Historical false positive patterns
    - Researcher track record
    - Technical indicators
    """
    
    def __init__(self, threshold: float = 0.7):
        """
        Initialize false positive predictor.
        
        Args:
            threshold: Probability threshold for FP classification
        """
        self.threshold = threshold
        self.feature_extractor = FeatureExtractor()
        
        # Training data
        self.training_data: List[tuple] = []  # (features, is_fp)
        
        # False positive indicators
        self.fp_indicators: Dict[str, float] = {}
        
        logger.info(f"FalsePositivePredictor initialized (threshold={threshold})")
    
    def train(self, reports: List[Any], validation_results: List[Any]):
        """
        Train the false positive predictor.
        
        Args:
            reports: List of vulnerability reports
            validation_results: Corresponding validation results
        """
        logger.info(f"Training false positive predictor on {len(reports)} reports")
        
        # Clear existing training data
        self.training_data = []
        
        # Extract features and labels
        for report, validation in zip(reports, validation_results):
            features = self.feature_extractor.extract_from_report(report)
            
            # Determine if it's a false positive
            is_fp = False
            if hasattr(validation, 'is_false_positive'):
                is_fp = validation.is_false_positive
            elif hasattr(validation, 'verdict'):
                is_fp = validation.verdict == 'invalid'
            
            self.training_data.append((features, is_fp))
        
        # Build false positive indicators
        self._build_fp_indicators()
        
        logger.info(f"Training complete: {len(self.training_data)} samples")
    
    def predict(self, report: Any, researcher_profile: Optional[Any] = None) -> PredictionResult:
        """
        Predict if a report is likely a false positive.
        
        Args:
            report: Vulnerability report
            researcher_profile: Optional researcher profile
            
        Returns:
            PredictionResult with FP probability
        """
        features = self.feature_extractor.extract_from_report(report)
        
        # Calculate FP probability
        fp_probability = self._calculate_fp_probability(features, researcher_profile)
        
        # Determine prediction
        is_false_positive = fp_probability >= self.threshold
        
        # Calculate feature importance
        feature_importance = self._calculate_feature_importance(features)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(features, fp_probability, feature_importance)
        
        return PredictionResult(
            prediction_type='false_positive',
            predicted_value=is_false_positive,
            confidence=abs(fp_probability - 0.5) * 2,  # Distance from uncertain (0.5)
            probability_distribution={
                'false_positive': fp_probability,
                'legitimate': 1.0 - fp_probability
            },
            features_used=list(features.keys()),
            feature_importance=feature_importance,
            reasoning=reasoning
        )
    
    def _build_fp_indicators(self):
        """Build indicators of false positives from training data."""
        if not self.training_data:
            return
        
        # Separate FP and legitimate reports
        fp_features = []
        legit_features = []
        
        for features, is_fp in self.training_data:
            if is_fp:
                fp_features.append(features)
            else:
                legit_features.append(features)
        
        if not fp_features or not legit_features:
            return
        
        # Calculate indicators for each feature
        all_keys = set()
        for features in fp_features + legit_features:
            all_keys.update(features.keys())
        
        for key in all_keys:
            # Get values for FP and legitimate reports
            fp_values = [
                f[key] for f in fp_features
                if key in f and isinstance(f[key], (int, float, bool))
            ]
            legit_values = [
                f[key] for f in legit_features
                if key in f and isinstance(f[key], (int, float, bool))
            ]
            
            if not fp_values or not legit_values:
                continue
            
            # Convert booleans to floats
            fp_values = [float(v) if isinstance(v, bool) else v for v in fp_values]
            legit_values = [float(v) if isinstance(v, bool) else v for v in legit_values]
            
            # Calculate means
            fp_mean = statistics.mean(fp_values)
            legit_mean = statistics.mean(legit_values)
            
            # Indicator strength (difference between FP and legitimate)
            if legit_mean != 0:
                indicator_strength = (fp_mean - legit_mean) / abs(legit_mean)
            else:
                indicator_strength = fp_mean - legit_mean
            
            self.fp_indicators[key] = indicator_strength
    
    def _calculate_fp_probability(self, features: Dict[str, Any], researcher_profile: Optional[Any]) -> float:
        """Calculate probability of false positive."""
        if not self.fp_indicators:
            # No training data - use heuristics
            return self._heuristic_fp_probability(features)
        
        # Start with base probability
        fp_count = sum(1 for _, is_fp in self.training_data if is_fp)
        base_probability = fp_count / len(self.training_data) if self.training_data else 0.5
        
        # Adjust based on features
        adjustments = []
        
        for key, value in features.items():
            if key not in self.fp_indicators:
                continue
            
            if not isinstance(value, (int, float, bool)):
                continue
            
            numeric_value = float(value) if isinstance(value, bool) else value
            indicator_strength = self.fp_indicators[key]
            
            # Positive indicator strength means higher values correlate with FP
            adjustment = indicator_strength * numeric_value * 0.1
            adjustments.append(adjustment)
        
        # Apply adjustments
        if adjustments:
            avg_adjustment = sum(adjustments) / len(adjustments)
            probability = base_probability + avg_adjustment
        else:
            probability = base_probability
        
        # Adjust based on researcher profile
        if researcher_profile:
            if hasattr(researcher_profile, 'false_positive_rate'):
                # Weight researcher's historical FP rate
                researcher_weight = 0.3
                probability = (
                    probability * (1 - researcher_weight) +
                    researcher_profile.false_positive_rate * researcher_weight
                )
        
        # Clamp to valid range
        return max(0.0, min(1.0, probability))
    
    def _heuristic_fp_probability(self, features: Dict[str, Any]) -> float:
        """Calculate FP probability using heuristics when no training data."""
        fp_score = 0.0
        indicators = 0
        
        # Low quality indicators
        if features.get('description_length', 0) < 100:
            fp_score += 0.2
            indicators += 1
        
        if not features.get('has_steps', False):
            fp_score += 0.15
            indicators += 1
        
        if not features.get('has_poc', False):
            fp_score += 0.15
            indicators += 1
        
        if features.get('word_count', 0) < 50:
            fp_score += 0.2
            indicators += 1
        
        # Technical indicators
        if not features.get('has_urls', False):
            fp_score += 0.1
            indicators += 1
        
        if features.get('url_count', 0) == 0:
            fp_score += 0.1
            indicators += 1
        
        if not features.get('has_code_blocks', False):
            fp_score += 0.1
            indicators += 1
        
        if indicators == 0:
            return 0.5
        
        return min(1.0, fp_score)
    
    def _calculate_feature_importance(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Calculate feature importance for the prediction."""
        if not self.fp_indicators:
            return {}
        
        importance = {}
        
        for key, value in features.items():
            if key in self.fp_indicators:
                # Importance based on indicator strength
                importance[key] = abs(self.fp_indicators[key])
        
        # Normalize
        total = sum(importance.values())
        if total > 0:
            importance = {k: v / total for k, v in importance.items()}
        
        # Return top 5
        sorted_importance = sorted(importance.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_importance[:5])
    
    def _generate_reasoning(self, features: Dict[str, Any], probability: float, importance: Dict[str, float]) -> str:
        """Generate human-readable reasoning."""
        if probability >= 0.7:
            risk_level = "HIGH"
            verdict = "likely a false positive"
        elif probability >= 0.5:
            risk_level = "MEDIUM"
            verdict = "possibly a false positive"
        else:
            risk_level = "LOW"
            verdict = "likely legitimate"
        
        reasoning_parts = [
            f"False positive probability: {probability:.1%} ({risk_level} risk)",
            f"Report is {verdict}"
        ]
        
        # Add key indicators
        if importance:
            top_indicator = list(importance.keys())[0]
            reasoning_parts.append(f"Key indicator: {top_indicator}")
        
        # Add specific concerns
        concerns = []
        if features.get('description_length', 0) < 100:
            concerns.append("very short description")
        if not features.get('has_steps', False):
            concerns.append("missing reproduction steps")
        if not features.get('has_poc', False):
            concerns.append("no proof of concept")
        
        if concerns:
            reasoning_parts.append(f"Concerns: {', '.join(concerns)}")
        
        return ". ".join(reasoning_parts)
    
    def get_fp_indicators(self) -> Dict[str, float]:
        """Get the learned false positive indicators."""
        return self.fp_indicators.copy()
    
    def get_training_stats(self) -> Dict[str, Any]:
        """Get statistics about training data."""
        if not self.training_data:
            return {'error': 'No training data available'}
        
        fp_count = sum(1 for _, is_fp in self.training_data if is_fp)
        legit_count = len(self.training_data) - fp_count
        
        return {
            'total_samples': len(self.training_data),
            'false_positives': fp_count,
            'legitimate': legit_count,
            'fp_rate': fp_count / len(self.training_data),
            'indicators_learned': len(self.fp_indicators)
        }

