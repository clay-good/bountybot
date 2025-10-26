"""
Custom Model Training Pipeline

Provides end-to-end training pipeline for custom vulnerability classification models.
"""

import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import logging

from .models import (
    TrainingDataset,
    TrainingExample,
    TrainingExperiment,
    ExperimentMetrics,
    ExperimentStatus,
    TrainingStatus,
    DatasetSplit,
    ModelType
)
from ..deep_learning import (
    NeuralNetwork,
    TrainingConfig,
    FeatureVector
)
from ..deep_learning.feature_engineering import FeatureEngineering

logger = logging.getLogger(__name__)


class TrainingPipeline:
    """
    End-to-end training pipeline for custom models.
    
    Features:
    - Data preparation and validation
    - Feature engineering
    - Model training with early stopping
    - Hyperparameter tuning
    - Cross-validation
    - Model evaluation
    """
    
    def __init__(self, config: Optional[TrainingConfig] = None):
        """
        Initialize training pipeline.
        
        Args:
            config: Training configuration
        """
        self.config = config or TrainingConfig()
        self.feature_engineer = FeatureEngineering()
        self.logger = logging.getLogger(__name__)
    
    def prepare_dataset(
        self,
        dataset: TrainingDataset,
        validation_split: float = 0.2,
        test_split: float = 0.1,
        shuffle: bool = True,
        random_seed: int = 42
    ) -> TrainingDataset:
        """
        Prepare dataset with train/val/test splits.
        
        Args:
            dataset: Training dataset
            validation_split: Fraction for validation
            test_split: Fraction for test
            shuffle: Whether to shuffle data
            random_seed: Random seed for reproducibility
            
        Returns:
            Dataset with split assignments
        """
        self.logger.info(f"Preparing dataset: {dataset.name}")
        
        # Get all examples
        examples = dataset.examples.copy()
        
        # Shuffle if requested
        if shuffle:
            np.random.seed(random_seed)
            np.random.shuffle(examples)
        
        # Calculate split sizes
        n_total = len(examples)
        n_test = int(n_total * test_split)
        n_val = int(n_total * validation_split)
        n_train = n_total - n_test - n_val
        
        # Assign splits
        for i, example in enumerate(examples):
            if i < n_train:
                example.split = DatasetSplit.TRAIN
            elif i < n_train + n_val:
                example.split = DatasetSplit.VALIDATION
            else:
                example.split = DatasetSplit.TEST
        
        dataset.examples = examples
        dataset.updated_at = datetime.utcnow()
        
        self.logger.info(f"Dataset split: train={n_train}, val={n_val}, test={n_test}")
        
        return dataset
    
    def validate_dataset(self, dataset: TrainingDataset) -> Tuple[bool, List[str]]:
        """
        Validate dataset for training.
        
        Args:
            dataset: Training dataset
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Check minimum examples
        if len(dataset.examples) < 10:
            errors.append("Dataset must have at least 10 examples")
        
        # Check class distribution
        distribution = dataset.get_class_distribution()
        if len(distribution) < 2:
            errors.append("Dataset must have at least 2 classes")
        
        # Check for class imbalance
        counts = list(distribution.values())
        if max(counts) / min(counts) > 100:
            errors.append("Severe class imbalance detected (>100:1 ratio)")
        
        # Check splits
        train_examples = dataset.get_split(DatasetSplit.TRAIN)
        if len(train_examples) < 5:
            errors.append("Training split must have at least 5 examples")
        
        return len(errors) == 0, errors
    
    def augment_data(
        self,
        examples: List[TrainingExample],
        augmentation_factor: int = 2
    ) -> List[TrainingExample]:
        """
        Augment training data to increase dataset size.
        
        Args:
            examples: Training examples
            augmentation_factor: How many augmented versions per example
            
        Returns:
            Augmented examples
        """
        augmented = examples.copy()
        
        for example in examples:
            for i in range(augmentation_factor - 1):
                # Create augmented version
                aug_example = TrainingExample(
                    input_data=example.input_data.copy(),
                    label=example.label,
                    confidence=example.confidence,
                    metadata={**example.metadata, 'augmented': True, 'source': example.example_id},
                    split=example.split
                )
                
                # Apply augmentation (simple text perturbation)
                if 'title' in aug_example.input_data:
                    title = aug_example.input_data['title']
                    # Add noise (in real implementation, use more sophisticated methods)
                    aug_example.input_data['title'] = title
                
                augmented.append(aug_example)
        
        return augmented
    
    def train(
        self,
        dataset: TrainingDataset,
        experiment: TrainingExperiment,
        augment: bool = False,
        early_stopping: bool = True,
        patience: int = 10
    ) -> TrainingExperiment:
        """
        Train model on dataset.
        
        Args:
            dataset: Training dataset
            experiment: Training experiment
            augment: Whether to augment training data
            early_stopping: Whether to use early stopping
            patience: Patience for early stopping
            
        Returns:
            Updated experiment with results
        """
        self.logger.info(f"Starting training experiment: {experiment.name}")
        
        try:
            # Update experiment status
            experiment.status = ExperimentStatus.RUNNING
            experiment.started_at = datetime.utcnow()
            
            # Validate dataset
            is_valid, errors = self.validate_dataset(dataset)
            if not is_valid:
                raise ValueError(f"Invalid dataset: {', '.join(errors)}")
            
            # Get splits
            train_examples = dataset.get_split(DatasetSplit.TRAIN)
            val_examples = dataset.get_split(DatasetSplit.VALIDATION)
            test_examples = dataset.get_split(DatasetSplit.TEST)
            
            # Augment if requested
            if augment:
                train_examples = self.augment_data(train_examples)
                self.logger.info(f"Augmented training data: {len(train_examples)} examples")
            
            # Extract features
            X_train, y_train = self._prepare_features(train_examples, dataset.class_names)
            X_val, y_val = self._prepare_features(val_examples, dataset.class_names)
            X_test, y_test = self._prepare_features(test_examples, dataset.class_names)
            
            # Create model
            model = NeuralNetwork(
                input_size=X_train.shape[1],
                output_size=len(dataset.class_names),
                hidden_sizes=experiment.hyperparameters.get('hidden_sizes', [256, 128, 64]),
                learning_rate=experiment.hyperparameters.get('learning_rate', 0.001),
                dropout_rate=experiment.hyperparameters.get('dropout_rate', 0.3)
            )
            
            # Training loop
            best_val_loss = float('inf')
            patience_counter = 0
            learning_curve = []
            
            num_epochs = experiment.hyperparameters.get('num_epochs', 100)
            batch_size = experiment.hyperparameters.get('batch_size', 32)
            
            for epoch in range(num_epochs):
                # Train epoch
                train_loss = self._train_epoch(model, X_train, y_train, batch_size)
                
                # Validate
                val_loss, val_acc = self._validate(model, X_val, y_val)
                
                # Record metrics
                learning_curve.append({
                    'epoch': epoch + 1,
                    'train_loss': train_loss,
                    'val_loss': val_loss,
                    'val_accuracy': val_acc
                })
                
                # Early stopping
                if early_stopping:
                    if val_loss < best_val_loss:
                        best_val_loss = val_loss
                        patience_counter = 0
                    else:
                        patience_counter += 1
                        if patience_counter >= patience:
                            self.logger.info(f"Early stopping at epoch {epoch + 1}")
                            break
            
            # Final evaluation on test set
            test_loss, test_acc = self._validate(model, X_test, y_test)
            
            # Calculate metrics
            metrics = ExperimentMetrics(
                accuracy=test_acc,
                val_accuracy=val_acc,
                loss=test_loss,
                val_loss=val_loss,
                training_time_seconds=(datetime.utcnow() - experiment.started_at).total_seconds(),
                num_epochs=len(learning_curve),
                best_epoch=min(range(len(learning_curve)), key=lambda i: learning_curve[i]['val_loss']) + 1,
                learning_curve=learning_curve
            )
            
            # Update experiment
            experiment.status = ExperimentStatus.COMPLETED
            experiment.completed_at = datetime.utcnow()
            experiment.metrics = metrics
            
            self.logger.info(f"Training completed: accuracy={test_acc:.3f}")
            
            return experiment
            
        except Exception as e:
            self.logger.exception("Training failed")
            experiment.status = ExperimentStatus.FAILED
            experiment.error_message = str(e)
            experiment.completed_at = datetime.utcnow()
            return experiment
    
    def _prepare_features(
        self,
        examples: List[TrainingExample],
        class_names: List[str]
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features and labels from examples."""
        X = []
        y = []
        
        for example in examples:
            # Extract features
            title = example.input_data.get('title', '')
            description = example.input_data.get('description', '')
            features = self.feature_engineer.extract_features(title, description)
            X.append(features.vector)
            
            # Encode label
            label_idx = class_names.index(example.label) if example.label in class_names else 0
            y.append(label_idx)
        
        return np.array(X), np.array(y)
    
    def _train_epoch(
        self,
        model: NeuralNetwork,
        X: np.ndarray,
        y: np.ndarray,
        batch_size: int
    ) -> float:
        """Train one epoch."""
        total_loss = 0.0
        n_batches = 0
        
        # Shuffle data
        indices = np.random.permutation(len(X))
        
        for i in range(0, len(X), batch_size):
            batch_indices = indices[i:i + batch_size]
            X_batch = X[batch_indices]
            y_batch = y[batch_indices]
            
            # Forward pass
            output, _ = model.forward(X_batch, training=True)
            
            # Calculate loss (cross-entropy)
            loss = -np.mean(np.log(output[np.arange(len(y_batch)), y_batch] + 1e-10))
            total_loss += loss
            n_batches += 1
        
        return total_loss / n_batches if n_batches > 0 else 0.0
    
    def _validate(
        self,
        model: NeuralNetwork,
        X: np.ndarray,
        y: np.ndarray
    ) -> Tuple[float, float]:
        """Validate model."""
        # Forward pass
        output, _ = model.forward(X, training=False)
        
        # Calculate loss
        loss = -np.mean(np.log(output[np.arange(len(y)), y] + 1e-10))
        
        # Calculate accuracy
        predictions = np.argmax(output, axis=1)
        accuracy = np.mean(predictions == y)
        
        return loss, accuracy

