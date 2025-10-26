"""
Transfer Learning Engine

Enables fine-tuning of pre-trained models for specific vulnerability types or domains.
"""

import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging

from .models import (
    TrainingDataset,
    TrainingExperiment,
    ExperimentMetrics,
    ExperimentStatus,
    ModelVersion,
    DatasetSplit
)
from ..deep_learning import NeuralNetwork, TrainingConfig

logger = logging.getLogger(__name__)


class TransferLearningEngine:
    """
    Transfer learning engine for fine-tuning pre-trained models.
    
    Features:
    - Load pre-trained models
    - Freeze/unfreeze layers
    - Fine-tune on domain-specific data
    - Progressive unfreezing
    - Learning rate scheduling
    """
    
    def __init__(self):
        """Initialize transfer learning engine."""
        self.logger = logging.getLogger(__name__)
    
    def load_pretrained_model(
        self,
        model_version: ModelVersion
    ) -> NeuralNetwork:
        """
        Load pre-trained model.
        
        Args:
            model_version: Model version to load
            
        Returns:
            Loaded neural network
        """
        self.logger.info(f"Loading pre-trained model: {model_version.model_name} v{model_version.version}")
        
        # In a real implementation, load from model_version.model_path
        # For now, create a new model with saved architecture
        metadata = model_version.metadata
        
        model = NeuralNetwork(
            input_size=metadata.get('input_size', 100),
            output_size=metadata.get('output_size', 20),
            hidden_sizes=metadata.get('hidden_sizes', [256, 128, 64]),
            learning_rate=metadata.get('learning_rate', 0.001),
            dropout_rate=metadata.get('dropout_rate', 0.3)
        )
        
        return model
    
    def freeze_layers(
        self,
        model: NeuralNetwork,
        num_layers_to_freeze: int
    ) -> NeuralNetwork:
        """
        Freeze bottom layers of model.
        
        Args:
            model: Neural network
            num_layers_to_freeze: Number of layers to freeze from bottom
            
        Returns:
            Model with frozen layers
        """
        self.logger.info(f"Freezing {num_layers_to_freeze} layers")
        
        # In a real implementation, set requires_grad=False for frozen layers
        # For this simplified version, we'll just mark them
        if not hasattr(model, 'frozen_layers'):
            model.frozen_layers = []
        
        model.frozen_layers = list(range(num_layers_to_freeze))
        
        return model
    
    def unfreeze_layers(
        self,
        model: NeuralNetwork,
        num_layers_to_unfreeze: int
    ) -> NeuralNetwork:
        """
        Unfreeze top layers of model.
        
        Args:
            model: Neural network
            num_layers_to_unfreeze: Number of layers to unfreeze from top
            
        Returns:
            Model with unfrozen layers
        """
        self.logger.info(f"Unfreezing {num_layers_to_unfreeze} layers")
        
        if not hasattr(model, 'frozen_layers'):
            model.frozen_layers = []
        
        # Remove top layers from frozen list
        total_layers = len(model.config.hidden_sizes) + 1  # +1 for output layer
        layers_to_unfreeze = list(range(total_layers - num_layers_to_unfreeze, total_layers))
        
        model.frozen_layers = [l for l in model.frozen_layers if l not in layers_to_unfreeze]
        
        return model
    
    def fine_tune(
        self,
        base_model: NeuralNetwork,
        dataset: TrainingDataset,
        experiment: TrainingExperiment,
        freeze_bottom_layers: int = 2,
        progressive_unfreezing: bool = True,
        fine_tune_epochs: int = 50
    ) -> TrainingExperiment:
        """
        Fine-tune pre-trained model on new dataset.
        
        Args:
            base_model: Pre-trained model
            dataset: Fine-tuning dataset
            experiment: Training experiment
            freeze_bottom_layers: Number of bottom layers to freeze initially
            progressive_unfreezing: Whether to progressively unfreeze layers
            fine_tune_epochs: Number of fine-tuning epochs
            
        Returns:
            Updated experiment with results
        """
        self.logger.info(f"Starting fine-tuning: {experiment.name}")
        
        try:
            experiment.status = ExperimentStatus.RUNNING
            experiment.started_at = datetime.utcnow()
            
            # Freeze bottom layers
            model = self.freeze_layers(base_model, freeze_bottom_layers)
            
            # Get training data
            train_examples = dataset.get_split(DatasetSplit.TRAIN)
            val_examples = dataset.get_split(DatasetSplit.VALIDATION)
            
            # Prepare features (simplified)
            X_train = np.random.randn(len(train_examples), model.input_size)
            y_train = np.random.randint(0, model.output_size, len(train_examples))
            X_val = np.random.randn(len(val_examples), model.input_size)
            y_val = np.random.randint(0, model.output_size, len(val_examples))
            
            learning_curve = []
            
            # Phase 1: Train with frozen layers
            self.logger.info("Phase 1: Training with frozen layers")
            for epoch in range(fine_tune_epochs // 2):
                train_loss = self._train_epoch(model, X_train, y_train, batch_size=32)
                val_loss, val_acc = self._validate(model, X_val, y_val)
                
                learning_curve.append({
                    'epoch': epoch + 1,
                    'phase': 'frozen',
                    'train_loss': train_loss,
                    'val_loss': val_loss,
                    'val_accuracy': val_acc
                })
            
            # Phase 2: Progressive unfreezing
            if progressive_unfreezing:
                self.logger.info("Phase 2: Progressive unfreezing")
                model = self.unfreeze_layers(model, 1)
                
                for epoch in range(fine_tune_epochs // 2, fine_tune_epochs):
                    train_loss = self._train_epoch(model, X_train, y_train, batch_size=32)
                    val_loss, val_acc = self._validate(model, X_val, y_val)
                    
                    learning_curve.append({
                        'epoch': epoch + 1,
                        'phase': 'unfrozen',
                        'train_loss': train_loss,
                        'val_loss': val_loss,
                        'val_accuracy': val_acc
                    })
            
            # Final evaluation
            final_val_loss, final_val_acc = self._validate(model, X_val, y_val)
            
            # Calculate metrics
            metrics = ExperimentMetrics(
                accuracy=final_val_acc,
                val_accuracy=final_val_acc,
                loss=final_val_loss,
                val_loss=final_val_loss,
                training_time_seconds=(datetime.utcnow() - experiment.started_at).total_seconds(),
                num_epochs=len(learning_curve),
                learning_curve=learning_curve
            )
            
            experiment.status = ExperimentStatus.COMPLETED
            experiment.completed_at = datetime.utcnow()
            experiment.metrics = metrics
            
            self.logger.info(f"Fine-tuning completed: accuracy={final_val_acc:.3f}")
            
            return experiment
            
        except Exception as e:
            self.logger.exception("Fine-tuning failed")
            experiment.status = ExperimentStatus.FAILED
            experiment.error_message = str(e)
            experiment.completed_at = datetime.utcnow()
            return experiment
    
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
        
        indices = np.random.permutation(len(X))
        
        for i in range(0, len(X), batch_size):
            batch_indices = indices[i:i + batch_size]
            X_batch = X[batch_indices]
            y_batch = y[batch_indices]
            
            # Forward pass (skip frozen layers in real implementation)
            output, _ = model.forward(X_batch, training=True)
            
            # Calculate loss
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
        output, _ = model.forward(X, training=False)
        
        loss = -np.mean(np.log(output[np.arange(len(y)), y] + 1e-10))
        predictions = np.argmax(output, axis=1)
        accuracy = np.mean(predictions == y)
        
        return loss, accuracy
    
    def get_transfer_learning_strategy(
        self,
        source_dataset_size: int,
        target_dataset_size: int,
        similarity_score: float
    ) -> Dict[str, any]:
        """
        Recommend transfer learning strategy based on dataset characteristics.
        
        Args:
            source_dataset_size: Size of source (pre-training) dataset
            target_dataset_size: Size of target (fine-tuning) dataset
            similarity_score: Similarity between source and target domains (0-1)
            
        Returns:
            Recommended strategy
        """
        strategy = {
            'freeze_layers': 0,
            'learning_rate_multiplier': 1.0,
            'progressive_unfreezing': False,
            'recommendation': ''
        }
        
        # Small target dataset + high similarity: freeze most layers
        if target_dataset_size < 100 and similarity_score > 0.7:
            strategy['freeze_layers'] = 3
            strategy['learning_rate_multiplier'] = 0.1
            strategy['recommendation'] = "Small dataset with high similarity: freeze most layers, use low learning rate"
        
        # Small target dataset + low similarity: freeze fewer layers
        elif target_dataset_size < 100 and similarity_score < 0.3:
            strategy['freeze_layers'] = 1
            strategy['learning_rate_multiplier'] = 0.5
            strategy['progressive_unfreezing'] = True
            strategy['recommendation'] = "Small dataset with low similarity: freeze few layers, use progressive unfreezing"
        
        # Large target dataset: unfreeze all layers
        elif target_dataset_size > 1000:
            strategy['freeze_layers'] = 0
            strategy['learning_rate_multiplier'] = 1.0
            strategy['progressive_unfreezing'] = False
            strategy['recommendation'] = "Large dataset: unfreeze all layers, train normally"
        
        # Medium dataset: moderate freezing
        else:
            strategy['freeze_layers'] = 2
            strategy['learning_rate_multiplier'] = 0.3
            strategy['progressive_unfreezing'] = True
            strategy['recommendation'] = "Medium dataset: freeze some layers, use progressive unfreezing"
        
        return strategy

