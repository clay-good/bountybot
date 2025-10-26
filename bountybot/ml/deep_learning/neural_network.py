"""
Neural Network implementation for vulnerability classification.

This module provides a flexible neural network architecture with:
- Configurable hidden layers
- Dropout for regularization
- Batch normalization
- Multiple activation functions
"""

import logging
from typing import List, Dict, Optional, Tuple
import numpy as np
from datetime import datetime

from bountybot.ml.deep_learning.models import (
    VulnerabilityType,
    TrainingConfig,
    ClassificationResult,
    FeatureVector
)

logger = logging.getLogger(__name__)


class NeuralNetwork:
    """
    Neural network for vulnerability classification.
    
    This is a simplified implementation that demonstrates the architecture.
    In production, you would use PyTorch or TensorFlow.
    """
    
    def __init__(self, config: TrainingConfig):
        """
        Initialize neural network.
        
        Args:
            config: Training configuration
        """
        self.config = config
        self.weights: List[np.ndarray] = []
        self.biases: List[np.ndarray] = []
        self.is_trained = False
        self.version = "1.0.0"
        
        # Initialize network architecture
        self._initialize_weights()
        
        logger.info(f"Initialized neural network with {self.get_num_parameters()} parameters")
    
    def _initialize_weights(self):
        """Initialize network weights using Xavier initialization."""
        layer_sizes = [self.config.input_size] + self.config.hidden_sizes + [self.config.output_size]
        
        for i in range(len(layer_sizes) - 1):
            # Xavier initialization
            limit = np.sqrt(6.0 / (layer_sizes[i] + layer_sizes[i + 1]))
            weight = np.random.uniform(-limit, limit, (layer_sizes[i], layer_sizes[i + 1]))
            bias = np.zeros(layer_sizes[i + 1])
            
            self.weights.append(weight)
            self.biases.append(bias)
    
    def _relu(self, x: np.ndarray) -> np.ndarray:
        """ReLU activation function."""
        return np.maximum(0, x)
    
    def _relu_derivative(self, x: np.ndarray) -> np.ndarray:
        """Derivative of ReLU."""
        return (x > 0).astype(float)
    
    def _softmax(self, x: np.ndarray) -> np.ndarray:
        """Softmax activation function."""
        exp_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
        return exp_x / np.sum(exp_x, axis=-1, keepdims=True)
    
    def _dropout(self, x: np.ndarray, rate: float, training: bool = True) -> np.ndarray:
        """Apply dropout regularization."""
        if not training or rate == 0:
            return x
        
        mask = np.random.binomial(1, 1 - rate, x.shape)
        return x * mask / (1 - rate)
    
    def forward(self, x: np.ndarray, training: bool = False) -> Tuple[np.ndarray, List[np.ndarray]]:
        """
        Forward pass through the network.
        
        Args:
            x: Input features
            training: Whether in training mode (affects dropout)
        
        Returns:
            Output probabilities and intermediate activations
        """
        activations = [x]
        current = x
        
        # Hidden layers
        for i in range(len(self.weights) - 1):
            current = np.dot(current, self.weights[i]) + self.biases[i]
            current = self._relu(current)
            
            if training:
                current = self._dropout(current, self.config.dropout_rate, training)
            
            activations.append(current)
        
        # Output layer
        current = np.dot(current, self.weights[-1]) + self.biases[-1]
        output = self._softmax(current)
        activations.append(output)
        
        return output, activations
    
    def predict(self, features: FeatureVector) -> ClassificationResult:
        """
        Predict vulnerability type from features.
        
        Args:
            features: Feature vector
        
        Returns:
            Classification result with probabilities
        """
        # Convert features to array
        x = np.array(features.to_array()).reshape(1, -1)
        
        # Pad or truncate to match input size
        if x.shape[1] < self.config.input_size:
            x = np.pad(x, ((0, 0), (0, self.config.input_size - x.shape[1])))
        elif x.shape[1] > self.config.input_size:
            x = x[:, :self.config.input_size]
        
        # Forward pass
        probabilities, _ = self.forward(x, training=False)
        probabilities = probabilities[0]
        
        # Get predicted class
        predicted_idx = np.argmax(probabilities)
        vulnerability_types = list(VulnerabilityType)
        predicted_type = vulnerability_types[predicted_idx] if predicted_idx < len(vulnerability_types) else VulnerabilityType.OTHER
        
        # Build probability dictionary
        prob_dict = {}
        for i, vuln_type in enumerate(vulnerability_types[:len(probabilities)]):
            prob_dict[vuln_type] = float(probabilities[i])
        
        return ClassificationResult(
            predicted_type=predicted_type,
            confidence=float(probabilities[predicted_idx]),
            probabilities=prob_dict,
            model_version=self.version,
            timestamp=datetime.utcnow()
        )
    
    def predict_batch(self, features_list: List[FeatureVector]) -> List[ClassificationResult]:
        """
        Predict vulnerability types for a batch of features.
        
        Args:
            features_list: List of feature vectors
        
        Returns:
            List of classification results
        """
        return [self.predict(features) for features in features_list]
    
    def get_num_parameters(self) -> int:
        """Get total number of trainable parameters."""
        total = 0
        for weight, bias in zip(self.weights, self.biases):
            total += weight.size + bias.size
        return total
    
    def get_model_size_mb(self) -> float:
        """Get model size in megabytes."""
        total_bytes = 0
        for weight, bias in zip(self.weights, self.biases):
            total_bytes += weight.nbytes + bias.nbytes
        return total_bytes / (1024 * 1024)
    
    def save_weights(self, filepath: str):
        """Save model weights to file."""
        np.savez(
            filepath,
            weights=[w for w in self.weights],
            biases=[b for b in self.biases],
            config=self.config,
            version=self.version
        )
        logger.info(f"Saved model weights to {filepath}")
    
    def load_weights(self, filepath: str):
        """Load model weights from file."""
        data = np.load(filepath, allow_pickle=True)
        self.weights = list(data['weights'])
        self.biases = list(data['biases'])
        self.version = str(data['version'])
        self.is_trained = True
        logger.info(f"Loaded model weights from {filepath}")
    
    def get_layer_info(self) -> List[Dict]:
        """Get information about each layer."""
        info = []
        layer_sizes = [self.config.input_size] + self.config.hidden_sizes + [self.config.output_size]
        
        for i in range(len(layer_sizes) - 1):
            info.append({
                'layer': i,
                'type': 'hidden' if i < len(layer_sizes) - 2 else 'output',
                'input_size': layer_sizes[i],
                'output_size': layer_sizes[i + 1],
                'num_parameters': layer_sizes[i] * layer_sizes[i + 1] + layer_sizes[i + 1],
                'activation': 'relu' if i < len(layer_sizes) - 2 else 'softmax'
            })
        
        return info
    
    def summary(self) -> str:
        """Get model summary as string."""
        lines = [
            "Neural Network Architecture",
            "=" * 50,
            f"Input size: {self.config.input_size}",
            f"Hidden layers: {self.config.hidden_sizes}",
            f"Output size: {self.config.output_size}",
            f"Total parameters: {self.get_num_parameters():,}",
            f"Model size: {self.get_model_size_mb():.2f} MB",
            f"Dropout rate: {self.config.dropout_rate}",
            "=" * 50,
            "\nLayer Details:"
        ]
        
        for layer_info in self.get_layer_info():
            lines.append(
                f"  Layer {layer_info['layer']} ({layer_info['type']}): "
                f"{layer_info['input_size']} -> {layer_info['output_size']} "
                f"({layer_info['num_parameters']:,} params, {layer_info['activation']})"
            )
        
        return "\n".join(lines)

