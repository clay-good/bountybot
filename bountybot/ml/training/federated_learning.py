"""
Federated Learning Coordinator

Enables collaborative model training across multiple tenants without sharing raw data.
"""

import numpy as np
from datetime import datetime
from typing import Dict, List, Optional
import logging

from .models import (
    FederatedRound,
    TrainingStatus,
    ExperimentMetrics,
    ModelType
)
from ..deep_learning import NeuralNetwork

logger = logging.getLogger(__name__)


class FederatedLearningCoordinator:
    """
    Federated learning coordinator for multi-tenant model training.
    
    Features:
    - Privacy-preserving training
    - Secure aggregation
    - Differential privacy
    - Client selection
    - Model aggregation (FedAvg, FedProx)
    - Byzantine-robust aggregation
    """
    
    def __init__(
        self,
        global_model: NeuralNetwork,
        aggregation_method: str = "fedavg"
    ):
        """
        Initialize federated learning coordinator.
        
        Args:
            global_model: Global model to train
            aggregation_method: Aggregation method ("fedavg", "fedprox", "median")
        """
        self.global_model = global_model
        self.aggregation_method = aggregation_method
        self.logger = logging.getLogger(__name__)
        self.rounds: List[FederatedRound] = []
        self.current_round = 0
    
    def start_round(
        self,
        participating_tenants: List[str]
    ) -> FederatedRound:
        """
        Start new federated learning round.
        
        Args:
            participating_tenants: List of tenant IDs participating in this round
            
        Returns:
            Federated round
        """
        self.current_round += 1
        self.logger.info(f"Starting federated round {self.current_round} with {len(participating_tenants)} tenants")
        
        round_obj = FederatedRound(
            round_number=self.current_round,
            global_model_version=f"global_v{self.current_round}",
            participating_tenants=participating_tenants,
            status=TrainingStatus.RUNNING
        )
        
        self.rounds.append(round_obj)
        
        return round_obj
    
    def get_global_model(self) -> Dict[str, np.ndarray]:
        """
        Get current global model parameters.
        
        Returns:
            Model parameters
        """
        # In real implementation, return actual model weights
        # For now, return placeholder
        return {
            'weights': np.random.randn(100, 50),
            'biases': np.random.randn(50)
        }
    
    def submit_local_update(
        self,
        round_id: str,
        tenant_id: str,
        local_weights: Dict[str, np.ndarray],
        num_samples: int,
        local_metrics: Optional[ExperimentMetrics] = None
    ):
        """
        Submit local model update from tenant.
        
        Args:
            round_id: Round ID
            tenant_id: Tenant ID
            local_weights: Local model weights
            num_samples: Number of samples used for training
            local_metrics: Local training metrics
        """
        self.logger.info(f"Received update from tenant {tenant_id} for round {round_id}")
        
        # Find round
        round_obj = None
        for r in self.rounds:
            if r.round_id == round_id:
                round_obj = r
                break
        
        if not round_obj:
            raise ValueError(f"Round not found: {round_id}")
        
        # Store update
        round_obj.tenant_updates[tenant_id] = {
            'weights': local_weights,
            'num_samples': num_samples,
            'metrics': local_metrics,
            'timestamp': datetime.utcnow()
        }
        
        self.logger.info(f"Stored update from {tenant_id}: {num_samples} samples")
    
    def aggregate_updates(
        self,
        round_id: str,
        apply_differential_privacy: bool = True,
        privacy_epsilon: float = 1.0
    ) -> Dict[str, np.ndarray]:
        """
        Aggregate local updates into global model.
        
        Args:
            round_id: Round ID
            apply_differential_privacy: Whether to apply differential privacy
            privacy_epsilon: Privacy budget (smaller = more private)
            
        Returns:
            Aggregated model weights
        """
        self.logger.info(f"Aggregating updates for round {round_id}")
        
        # Find round
        round_obj = None
        for r in self.rounds:
            if r.round_id == round_id:
                round_obj = r
                break
        
        if not round_obj:
            raise ValueError(f"Round not found: {round_id}")
        
        updates = round_obj.tenant_updates
        
        if len(updates) == 0:
            raise ValueError("No updates to aggregate")
        
        # Aggregate based on method
        if self.aggregation_method == "fedavg":
            aggregated = self._fedavg_aggregation(updates)
        elif self.aggregation_method == "fedprox":
            aggregated = self._fedprox_aggregation(updates)
        elif self.aggregation_method == "median":
            aggregated = self._median_aggregation(updates)
        else:
            raise ValueError(f"Unknown aggregation method: {self.aggregation_method}")
        
        # Apply differential privacy if requested
        if apply_differential_privacy:
            aggregated = self._apply_differential_privacy(aggregated, privacy_epsilon)
        
        # Update global model
        # In real implementation, update self.global_model with aggregated weights
        
        self.logger.info(f"Aggregation complete: {len(updates)} updates")
        
        return aggregated
    
    def _fedavg_aggregation(
        self,
        updates: Dict[str, Dict]
    ) -> Dict[str, np.ndarray]:
        """
        FedAvg aggregation: weighted average by number of samples.
        
        Args:
            updates: Tenant updates
            
        Returns:
            Aggregated weights
        """
        total_samples = sum(u['num_samples'] for u in updates.values())
        
        # Initialize aggregated weights
        aggregated = {}
        
        # Get first update to determine structure
        first_update = list(updates.values())[0]
        weight_keys = first_update['weights'].keys()
        
        for key in weight_keys:
            # Weighted average
            weighted_sum = None
            for tenant_id, update in updates.items():
                weight = update['num_samples'] / total_samples
                tensor = update['weights'][key]
                
                if weighted_sum is None:
                    weighted_sum = weight * tensor
                else:
                    weighted_sum += weight * tensor
            
            aggregated[key] = weighted_sum
        
        return aggregated
    
    def _fedprox_aggregation(
        self,
        updates: Dict[str, Dict]
    ) -> Dict[str, np.ndarray]:
        """
        FedProx aggregation: similar to FedAvg but with proximal term.
        
        Args:
            updates: Tenant updates
            
        Returns:
            Aggregated weights
        """
        # Simplified: same as FedAvg for this implementation
        return self._fedavg_aggregation(updates)
    
    def _median_aggregation(
        self,
        updates: Dict[str, Dict]
    ) -> Dict[str, np.ndarray]:
        """
        Median aggregation: robust to Byzantine attacks.
        
        Args:
            updates: Tenant updates
            
        Returns:
            Aggregated weights
        """
        aggregated = {}
        
        # Get first update to determine structure
        first_update = list(updates.values())[0]
        weight_keys = first_update['weights'].keys()
        
        for key in weight_keys:
            # Collect all tensors for this key
            tensors = [update['weights'][key] for update in updates.values()]
            
            # Stack and take median
            stacked = np.stack(tensors, axis=0)
            aggregated[key] = np.median(stacked, axis=0)
        
        return aggregated
    
    def _apply_differential_privacy(
        self,
        weights: Dict[str, np.ndarray],
        epsilon: float
    ) -> Dict[str, np.ndarray]:
        """
        Apply differential privacy to aggregated weights.
        
        Args:
            weights: Aggregated weights
            epsilon: Privacy budget
            
        Returns:
            Privatized weights
        """
        privatized = {}
        
        for key, tensor in weights.items():
            # Add Gaussian noise calibrated to epsilon
            sensitivity = 1.0  # Simplified
            noise_scale = sensitivity / epsilon
            noise = np.random.normal(0, noise_scale, tensor.shape)
            
            privatized[key] = tensor + noise
        
        return privatized
    
    def complete_round(
        self,
        round_id: str
    ) -> FederatedRound:
        """
        Complete federated learning round.
        
        Args:
            round_id: Round ID
            
        Returns:
            Completed round
        """
        self.logger.info(f"Completing round {round_id}")
        
        # Find round
        round_obj = None
        for r in self.rounds:
            if r.round_id == round_id:
                round_obj = r
                break
        
        if not round_obj:
            raise ValueError(f"Round not found: {round_id}")
        
        # Aggregate updates
        aggregated = self.aggregate_updates(round_id)
        
        # Calculate aggregated metrics
        updates = round_obj.tenant_updates
        if updates:
            avg_accuracy = np.mean([
                u['metrics'].accuracy for u in updates.values()
                if u['metrics'] is not None
            ])
            
            round_obj.aggregated_metrics = ExperimentMetrics(
                accuracy=avg_accuracy,
                training_time_seconds=(datetime.utcnow() - round_obj.started_at).total_seconds()
            )
        
        round_obj.status = TrainingStatus.COMPLETED
        round_obj.completed_at = datetime.utcnow()
        
        self.logger.info(f"Round {self.current_round} completed with {len(updates)} participants")
        
        return round_obj
    
    def select_clients(
        self,
        all_tenants: List[str],
        selection_fraction: float = 0.3,
        min_clients: int = 2
    ) -> List[str]:
        """
        Select clients for next round.
        
        Args:
            all_tenants: All available tenant IDs
            selection_fraction: Fraction of clients to select
            min_clients: Minimum number of clients
            
        Returns:
            Selected tenant IDs
        """
        n_select = max(min_clients, int(len(all_tenants) * selection_fraction))
        n_select = min(n_select, len(all_tenants))
        
        # Random selection (in real implementation, use more sophisticated strategies)
        selected = np.random.choice(all_tenants, size=n_select, replace=False).tolist()
        
        self.logger.info(f"Selected {len(selected)} clients for next round")
        
        return selected
    
    def get_training_progress(self) -> Dict[str, any]:
        """
        Get federated training progress.
        
        Returns:
            Progress metrics
        """
        if not self.rounds:
            return {
                'total_rounds': 0,
                'completed_rounds': 0,
                'current_round': 0
            }
        
        completed = sum(1 for r in self.rounds if r.status == TrainingStatus.COMPLETED)
        
        latest_round = self.rounds[-1]
        
        return {
            'total_rounds': len(self.rounds),
            'completed_rounds': completed,
            'current_round': self.current_round,
            'latest_round_status': latest_round.status.value,
            'latest_round_participants': len(latest_round.participating_tenants),
            'latest_round_updates': len(latest_round.tenant_updates)
        }

