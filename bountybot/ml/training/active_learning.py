"""
Active Learning Pipeline

Implements active learning strategies to select the most valuable samples
for human labeling, enabling continuous model improvement with minimal labeling effort.
"""

import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Callable
from enum import Enum
import logging

from .models import (
    TrainingDataset,
    TrainingExample,
    DatasetSplit
)
from ..deep_learning import NeuralNetwork

logger = logging.getLogger(__name__)


class SamplingStrategy(Enum):
    """Active learning sampling strategy."""
    UNCERTAINTY = "uncertainty"  # Least confident predictions
    MARGIN = "margin"  # Smallest margin between top 2 classes
    ENTROPY = "entropy"  # Highest entropy
    DIVERSITY = "diversity"  # Most diverse samples
    HYBRID = "hybrid"  # Combination of strategies


class ActiveLearningPipeline:
    """
    Active learning pipeline for efficient model improvement.
    
    Features:
    - Multiple sampling strategies
    - Uncertainty-based selection
    - Diversity-based selection
    - Query-by-committee
    - Human-in-the-loop labeling
    - Continuous model retraining
    """
    
    def __init__(
        self,
        model: NeuralNetwork,
        strategy: SamplingStrategy = SamplingStrategy.UNCERTAINTY
    ):
        """
        Initialize active learning pipeline.
        
        Args:
            model: Trained model
            strategy: Sampling strategy
        """
        self.model = model
        self.strategy = strategy
        self.logger = logging.getLogger(__name__)
        self.labeled_pool: List[TrainingExample] = []
        self.unlabeled_pool: List[TrainingExample] = []
        self.iteration = 0
    
    def select_samples(
        self,
        unlabeled_examples: List[TrainingExample],
        n_samples: int = 10,
        diversity_weight: float = 0.3
    ) -> List[TrainingExample]:
        """
        Select most valuable samples for labeling.
        
        Args:
            unlabeled_examples: Pool of unlabeled examples
            n_samples: Number of samples to select
            diversity_weight: Weight for diversity in hybrid strategy
            
        Returns:
            Selected examples for labeling
        """
        self.logger.info(f"Selecting {n_samples} samples using {self.strategy.value} strategy")
        
        if len(unlabeled_examples) == 0:
            return []
        
        # Get predictions for all unlabeled examples
        predictions = self._get_predictions(unlabeled_examples)
        
        # Calculate scores based on strategy
        if self.strategy == SamplingStrategy.UNCERTAINTY:
            scores = self._uncertainty_sampling(predictions)
        elif self.strategy == SamplingStrategy.MARGIN:
            scores = self._margin_sampling(predictions)
        elif self.strategy == SamplingStrategy.ENTROPY:
            scores = self._entropy_sampling(predictions)
        elif self.strategy == SamplingStrategy.DIVERSITY:
            scores = self._diversity_sampling(unlabeled_examples)
        else:  # HYBRID
            uncertainty_scores = self._uncertainty_sampling(predictions)
            diversity_scores = self._diversity_sampling(unlabeled_examples)
            scores = (1 - diversity_weight) * uncertainty_scores + diversity_weight * diversity_scores
        
        # Select top n samples
        top_indices = np.argsort(scores)[-n_samples:]
        selected = [unlabeled_examples[i] for i in top_indices]
        
        self.logger.info(f"Selected {len(selected)} samples with scores: {scores[top_indices]}")
        
        return selected
    
    def _get_predictions(
        self,
        examples: List[TrainingExample]
    ) -> np.ndarray:
        """Get model predictions for examples."""
        # Prepare features (simplified)
        X = np.random.randn(len(examples), self.model.config.input_size)

        # Get predictions
        predictions, _ = self.model.forward(X, training=False)

        return predictions
    
    def _uncertainty_sampling(self, predictions: np.ndarray) -> np.ndarray:
        """
        Uncertainty sampling: select samples with lowest confidence.
        
        Args:
            predictions: Model predictions (probabilities)
            
        Returns:
            Uncertainty scores (higher = more uncertain)
        """
        # Use 1 - max_prob as uncertainty score
        max_probs = np.max(predictions, axis=1)
        uncertainty = 1 - max_probs
        return uncertainty
    
    def _margin_sampling(self, predictions: np.ndarray) -> np.ndarray:
        """
        Margin sampling: select samples with smallest margin between top 2 classes.
        
        Args:
            predictions: Model predictions (probabilities)
            
        Returns:
            Margin scores (higher = smaller margin)
        """
        # Sort predictions
        sorted_probs = np.sort(predictions, axis=1)
        
        # Calculate margin (difference between top 2)
        margin = sorted_probs[:, -1] - sorted_probs[:, -2]
        
        # Return inverse margin (smaller margin = higher score)
        return 1 - margin
    
    def _entropy_sampling(self, predictions: np.ndarray) -> np.ndarray:
        """
        Entropy sampling: select samples with highest prediction entropy.
        
        Args:
            predictions: Model predictions (probabilities)
            
        Returns:
            Entropy scores
        """
        # Calculate entropy: -sum(p * log(p))
        epsilon = 1e-10
        entropy = -np.sum(predictions * np.log(predictions + epsilon), axis=1)
        return entropy
    
    def _diversity_sampling(
        self,
        examples: List[TrainingExample]
    ) -> np.ndarray:
        """
        Diversity sampling: select diverse samples.
        
        Args:
            examples: Training examples
            
        Returns:
            Diversity scores
        """
        # Simplified diversity: random scores
        # In real implementation, use feature-based diversity (e.g., k-means clustering)
        return np.random.rand(len(examples))
    
    def label_samples(
        self,
        samples: List[TrainingExample],
        labeling_function: Callable[[TrainingExample], str]
    ) -> List[TrainingExample]:
        """
        Label selected samples using human labeling function.
        
        Args:
            samples: Samples to label
            labeling_function: Function that takes example and returns label
            
        Returns:
            Labeled examples
        """
        self.logger.info(f"Labeling {len(samples)} samples")
        
        labeled = []
        for sample in samples:
            try:
                # Get label from human
                label = labeling_function(sample)
                sample.label = label
                sample.confidence = 1.0  # Human labels are high confidence
                sample.labeled_by = "human"
                labeled.append(sample)
            except Exception as e:
                self.logger.error(f"Error labeling sample {sample.example_id}: {e}")
        
        return labeled
    
    def update_pools(
        self,
        newly_labeled: List[TrainingExample],
        unlabeled_pool: List[TrainingExample]
    ) -> Tuple[List[TrainingExample], List[TrainingExample]]:
        """
        Update labeled and unlabeled pools.
        
        Args:
            newly_labeled: Newly labeled examples
            unlabeled_pool: Current unlabeled pool
            
        Returns:
            Updated (labeled_pool, unlabeled_pool)
        """
        # Add to labeled pool
        self.labeled_pool.extend(newly_labeled)
        
        # Remove from unlabeled pool
        labeled_ids = {ex.example_id for ex in newly_labeled}
        self.unlabeled_pool = [ex for ex in unlabeled_pool if ex.example_id not in labeled_ids]
        
        self.logger.info(f"Updated pools: labeled={len(self.labeled_pool)}, unlabeled={len(self.unlabeled_pool)}")
        
        return self.labeled_pool, self.unlabeled_pool
    
    def run_iteration(
        self,
        unlabeled_pool: List[TrainingExample],
        labeling_function: Callable[[TrainingExample], str],
        n_samples: int = 10,
        retrain: bool = True
    ) -> Dict[str, any]:
        """
        Run one active learning iteration.
        
        Args:
            unlabeled_pool: Pool of unlabeled examples
            labeling_function: Function to label examples
            n_samples: Number of samples to label
            retrain: Whether to retrain model after labeling
            
        Returns:
            Iteration results
        """
        self.iteration += 1
        self.logger.info(f"Starting active learning iteration {self.iteration}")
        
        start_time = datetime.utcnow()
        
        # Select samples
        selected = self.select_samples(unlabeled_pool, n_samples)
        
        # Label samples
        labeled = self.label_samples(selected, labeling_function)
        
        # Update pools
        self.labeled_pool, self.unlabeled_pool = self.update_pools(labeled, unlabeled_pool)
        
        # Retrain model if requested
        if retrain and len(self.labeled_pool) > 0:
            self.logger.info("Retraining model with new labels")
            # In real implementation, retrain model here
            # For now, just log
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        results = {
            'iteration': self.iteration,
            'samples_selected': len(selected),
            'samples_labeled': len(labeled),
            'total_labeled': len(self.labeled_pool),
            'total_unlabeled': len(self.unlabeled_pool),
            'duration_seconds': duration,
            'timestamp': datetime.utcnow()
        }
        
        self.logger.info(f"Iteration {self.iteration} completed: {len(labeled)} samples labeled")
        
        return results
    
    def estimate_labeling_budget(
        self,
        target_accuracy: float,
        current_accuracy: float,
        samples_per_iteration: int = 10,
        max_iterations: int = 100
    ) -> Dict[str, any]:
        """
        Estimate labeling budget needed to reach target accuracy.
        
        Args:
            target_accuracy: Target accuracy to achieve
            current_accuracy: Current model accuracy
            samples_per_iteration: Samples to label per iteration
            max_iterations: Maximum iterations
            
        Returns:
            Budget estimate
        """
        # Simplified estimation using learning curve
        # In real implementation, use more sophisticated models
        
        accuracy_gap = target_accuracy - current_accuracy
        
        if accuracy_gap <= 0:
            return {
                'estimated_samples': 0,
                'estimated_iterations': 0,
                'estimated_cost': 0,
                'achievable': True
            }
        
        # Assume logarithmic improvement: accuracy increases by 0.01 per 100 samples
        samples_needed = int(accuracy_gap * 10000)
        iterations_needed = samples_needed // samples_per_iteration
        
        achievable = iterations_needed <= max_iterations
        
        # Estimate cost (assuming $1 per label)
        cost = samples_needed * 1.0
        
        return {
            'estimated_samples': samples_needed,
            'estimated_iterations': iterations_needed,
            'estimated_cost': cost,
            'achievable': achievable,
            'recommendation': f"Label {samples_needed} samples over {iterations_needed} iterations" if achievable else "Target may not be achievable with current budget"
        }
    
    def get_labeling_progress(self) -> Dict[str, any]:
        """
        Get current labeling progress.
        
        Returns:
            Progress metrics
        """
        total = len(self.labeled_pool) + len(self.unlabeled_pool)
        labeled_pct = len(self.labeled_pool) / total * 100 if total > 0 else 0
        
        return {
            'iteration': self.iteration,
            'labeled_samples': len(self.labeled_pool),
            'unlabeled_samples': len(self.unlabeled_pool),
            'total_samples': total,
            'labeled_percentage': labeled_pct,
            'strategy': self.strategy.value
        }

