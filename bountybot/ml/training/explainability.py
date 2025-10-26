"""
Model Explainability

Provides interpretability for ML model predictions using SHAP and LIME.
"""

import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging

from .models import (
    ExplainabilityResult,
    ModelVersion
)
from ..deep_learning import NeuralNetwork, FeatureVector

logger = logging.getLogger(__name__)


class ModelExplainer:
    """
    Model explainability engine.
    
    Features:
    - SHAP (SHapley Additive exPlanations) values
    - LIME (Local Interpretable Model-agnostic Explanations)
    - Feature importance ranking
    - Natural language explanations
    - Counterfactual explanations
    """
    
    def __init__(self, model: NeuralNetwork):
        """
        Initialize model explainer.
        
        Args:
            model: Model to explain
        """
        self.model = model
        self.logger = logging.getLogger(__name__)
    
    def explain_prediction(
        self,
        input_data: Dict[str, any],
        features: FeatureVector,
        prediction: str,
        confidence: float,
        model_version_id: str,
        use_shap: bool = True,
        use_lime: bool = True
    ) -> ExplainabilityResult:
        """
        Explain model prediction.
        
        Args:
            input_data: Original input data
            features: Feature vector
            prediction: Model prediction
            confidence: Prediction confidence
            model_version_id: Model version ID
            use_shap: Whether to compute SHAP values
            use_lime: Whether to compute LIME explanation
            
        Returns:
            Explainability result
        """
        self.logger.info(f"Explaining prediction: {prediction}")
        
        # Calculate feature importance
        feature_importance = self._calculate_feature_importance(features)
        
        # Calculate SHAP values if requested
        shap_values = None
        if use_shap:
            shap_values = self._calculate_shap_values(features)
        
        # Calculate LIME explanation if requested
        lime_explanation = None
        if use_lime:
            lime_explanation = self._calculate_lime_explanation(features, prediction)
        
        # Get top features
        top_features = sorted(
            feature_importance.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:10]
        
        # Generate natural language explanation
        explanation_text = self._generate_explanation(
            input_data,
            prediction,
            confidence,
            top_features
        )
        
        result = ExplainabilityResult(
            model_version_id=model_version_id,
            input_data=input_data,
            prediction=prediction,
            confidence=confidence,
            feature_importance=feature_importance,
            shap_values=shap_values,
            lime_explanation=lime_explanation,
            top_features=top_features,
            explanation_text=explanation_text
        )
        
        return result
    
    def _calculate_feature_importance(
        self,
        features: FeatureVector
    ) -> Dict[str, float]:
        """
        Calculate feature importance using gradient-based method.

        Args:
            features: Feature vector

        Returns:
            Feature importance scores
        """
        # Simplified implementation: use feature magnitudes
        # In real implementation, use gradients or integrated gradients

        importance = {}

        # Numerical features
        importance['title_length'] = float(features.title_length)
        importance['description_length'] = float(features.description_length)
        importance['num_urls'] = float(features.num_urls)
        importance['num_code_blocks'] = float(features.num_code_blocks)
        importance['num_special_chars'] = float(features.num_special_chars)

        # Boolean features
        importance['has_poc'] = float(features.has_poc)
        importance['has_exploit'] = float(features.has_exploit)
        importance['has_cve'] = float(features.has_cve)

        # Keyword counts
        for key, val in features.keyword_counts.items():
            importance[f'keyword_{key}'] = float(val)

        # Normalize
        total = sum(importance.values())
        if total > 0:
            importance = {k: v/total for k, v in importance.items()}

        return importance
    
    def _calculate_shap_values(
        self,
        features: FeatureVector
    ) -> Dict[str, float]:
        """
        Calculate SHAP values for features.

        Args:
            features: Feature vector

        Returns:
            SHAP values
        """
        # Simplified SHAP implementation
        # In real implementation, use shap library

        # Convert features to array
        feature_array = np.array(features.to_array())

        # Use permutation-based approximation
        baseline_output = self._get_model_output(np.zeros_like(feature_array))
        full_output = self._get_model_output(feature_array)

        shap_values = {}

        # Calculate contribution of each feature
        for i in range(len(feature_array)):
            # Create feature vector with this feature masked
            masked = feature_array.copy()
            masked[i] = 0

            masked_output = self._get_model_output(masked)

            # SHAP value = difference in output
            shap_value = full_output - masked_output
            shap_values[f'feature_{i}'] = float(shap_value)

        return shap_values
    
    def _calculate_lime_explanation(
        self,
        features: FeatureVector,
        prediction: str
    ) -> Dict[str, any]:
        """
        Calculate LIME explanation.

        Args:
            features: Feature vector
            prediction: Model prediction

        Returns:
            LIME explanation
        """
        # Simplified LIME implementation
        # In real implementation, use lime library

        # Convert features to array
        feature_array = np.array(features.to_array())

        # Generate perturbed samples
        n_samples = 100
        perturbed = []
        predictions = []

        for _ in range(n_samples):
            # Perturb features
            noise = np.random.normal(0, 0.1, feature_array.shape)
            perturbed_features = feature_array + noise

            # Get prediction
            output = self._get_model_output(perturbed_features)

            perturbed.append(perturbed_features)
            predictions.append(output)

        # Fit linear model to approximate local behavior
        # Simplified: just return feature weights

        return {
            'local_model': 'linear',
            'n_samples': n_samples,
            'prediction': prediction,
            'intercept': 0.0,
            'coefficients': {}  # Would contain feature coefficients
        }
    
    def _get_model_output(self, features: np.ndarray) -> float:
        """Get model output for features."""
        # Reshape if needed
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        # Forward pass
        output, _ = self.model.forward(features, training=False)
        
        # Return max probability
        return float(np.max(output))
    
    def _generate_explanation(
        self,
        input_data: Dict[str, any],
        prediction: str,
        confidence: float,
        top_features: List[Tuple[str, float]]
    ) -> str:
        """
        Generate natural language explanation.
        
        Args:
            input_data: Original input
            prediction: Prediction
            confidence: Confidence
            top_features: Top contributing features
            
        Returns:
            Natural language explanation
        """
        explanation = f"The model predicted '{prediction}' with {confidence:.1%} confidence.\n\n"
        
        explanation += "Key factors influencing this prediction:\n"
        
        for i, (feature, importance) in enumerate(top_features[:5], 1):
            explanation += f"{i}. {feature}: {importance:.3f} importance\n"
        
        # Add context from input
        if 'title' in input_data:
            explanation += f"\nThe vulnerability title mentions: '{input_data['title'][:100]}...'\n"
        
        if 'description' in input_data:
            explanation += f"The description contains: '{input_data['description'][:100]}...'\n"
        
        return explanation
    
    def generate_counterfactual(
        self,
        features: FeatureVector,
        target_prediction: str,
        max_changes: int = 3
    ) -> Dict[str, any]:
        """
        Generate counterfactual explanation.

        Args:
            features: Original features
            target_prediction: Desired prediction
            max_changes: Maximum number of features to change

        Returns:
            Counterfactual explanation
        """
        self.logger.info(f"Generating counterfactual for target: {target_prediction}")

        # Simplified counterfactual generation
        # In real implementation, use optimization or search

        # Convert features to array
        feature_array = np.array(features.to_array())

        original_output = self._get_model_output(feature_array)

        # Try changing top features
        changes = []
        modified_features = feature_array.copy()

        for i in range(min(max_changes, len(feature_array))):
            # Try increasing/decreasing feature
            for delta in [0.1, -0.1, 0.5, -0.5]:
                test_features = modified_features.copy()
                test_features[i] += delta

                output = self._get_model_output(test_features)

                # Check if closer to target
                if output > original_output:
                    changes.append({
                        'feature_index': i,
                        'original_value': float(modified_features[i]),
                        'new_value': float(test_features[i]),
                        'delta': delta
                    })
                    modified_features[i] = test_features[i]
                    break

        return {
            'target_prediction': target_prediction,
            'changes_needed': changes,
            'num_changes': len(changes),
            'explanation': f"To achieve '{target_prediction}', modify {len(changes)} features"
        }
    
    def explain_model_globally(
        self,
        sample_features: List[FeatureVector],
        sample_labels: List[str]
    ) -> Dict[str, any]:
        """
        Generate global model explanation.
        
        Args:
            sample_features: Sample feature vectors
            sample_labels: Sample labels
            
        Returns:
            Global explanation
        """
        self.logger.info(f"Generating global explanation from {len(sample_features)} samples")
        
        # Calculate average feature importance across samples
        all_importances = []
        
        for features in sample_features:
            importance = self._calculate_feature_importance(features)
            all_importances.append(importance)
        
        # Aggregate importances
        global_importance = {}
        for imp_dict in all_importances:
            for feature, value in imp_dict.items():
                if feature not in global_importance:
                    global_importance[feature] = []
                global_importance[feature].append(value)
        
        # Calculate mean importance
        mean_importance = {
            feature: np.mean(values)
            for feature, values in global_importance.items()
        }
        
        # Get top features
        top_global_features = sorted(
            mean_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )[:20]
        
        return {
            'num_samples': len(sample_features),
            'top_features': top_global_features,
            'feature_importance': mean_importance,
            'explanation': f"Across {len(sample_features)} samples, the most important features are: " +
                          ", ".join([f[0] for f in top_global_features[:5]])
        }
    
    def compare_predictions(
        self,
        features_a: FeatureVector,
        features_b: FeatureVector,
        prediction_a: str,
        prediction_b: str
    ) -> Dict[str, any]:
        """
        Compare two predictions and explain differences.

        Args:
            features_a: First feature vector
            features_b: Second feature vector
            prediction_a: First prediction
            prediction_b: Second prediction

        Returns:
            Comparison explanation
        """
        # Convert features to arrays
        array_a = np.array(features_a.to_array())
        array_b = np.array(features_b.to_array())

        # Calculate feature differences
        diff = array_a - array_b

        # Find features with largest differences
        diff_indices = np.argsort(np.abs(diff))[-10:]

        key_differences = [
            {
                'feature_index': int(i),
                'value_a': float(array_a[i]),
                'value_b': float(array_b[i]),
                'difference': float(diff[i])
            }
            for i in diff_indices
        ]

        return {
            'prediction_a': prediction_a,
            'prediction_b': prediction_b,
            'key_differences': key_differences,
            'explanation': f"The predictions differ because of {len(key_differences)} key feature differences"
        }

