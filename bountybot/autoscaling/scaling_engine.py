"""
Scaling Decision Engine

Makes intelligent scaling decisions based on multiple metrics:
- Queue depth and pending validations
- AI provider latency
- Cost optimization
- Predictive workload patterns
"""

import logging
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from .workload_predictor import WorkloadPredictor, WorkloadSample, WorkloadPrediction
from .cost_optimizer import CostOptimizer

logger = logging.getLogger(__name__)


class ScalingAction(str, Enum):
    """Scaling actions."""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    NO_CHANGE = "no_change"


@dataclass
class ScalingMetrics:
    """Current system metrics for scaling decisions."""
    queue_depth: int
    validations_per_minute: float
    avg_latency_seconds: float
    active_workers: int
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    ai_provider_latency: float = 0.0
    current_cost_per_hour: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScalingDecision:
    """Scaling decision with reasoning."""
    action: ScalingAction
    target_workers: int
    current_workers: int
    confidence: float
    reasoning: List[str] = field(default_factory=list)
    metrics: Optional[ScalingMetrics] = None
    prediction: Optional[WorkloadPrediction] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


class ScalingEngine:
    """
    Intelligent scaling decision engine.
    
    Features:
    - Multi-metric decision making
    - ML-based workload prediction
    - Cost-aware scaling
    - Cooldown periods to prevent flapping
    - Confidence-based decisions
    """
    
    def __init__(self, config: Dict):
        """
        Initialize scaling engine.
        
        Args:
            config: Scaling configuration
        """
        self.config = config
        
        # Scaling parameters
        self.min_workers = config.get('min_workers', 1)
        self.max_workers = config.get('max_workers', 10)
        self.target_queue_depth = config.get('target_queue_depth', 10)
        self.target_latency_seconds = config.get('target_latency_seconds', 30.0)
        self.scale_up_threshold = config.get('scale_up_threshold', 0.7)
        self.scale_down_threshold = config.get('scale_down_threshold', 0.3)
        self.cooldown_minutes = config.get('cooldown_minutes', 5)
        
        # Components
        self.workload_predictor = WorkloadPredictor(
            history_size=config.get('history_size', 1000)
        )
        self.cost_optimizer = CostOptimizer(config.get('cost_config', {}))
        
        # State
        self.last_scaling_action: Optional[datetime] = None
        self.last_decision: Optional[ScalingDecision] = None
        
        logger.info(f"Initialized ScalingEngine: min={self.min_workers}, max={self.max_workers}")
    
    def add_metrics(self, metrics: ScalingMetrics):
        """
        Add current metrics to history.
        
        Args:
            metrics: Current system metrics
        """
        # Convert to workload sample
        sample = WorkloadSample(
            timestamp=metrics.timestamp,
            validations_per_minute=metrics.validations_per_minute,
            queue_depth=metrics.queue_depth,
            avg_latency_seconds=metrics.avg_latency_seconds,
            active_workers=metrics.active_workers,
            cpu_usage=metrics.cpu_usage,
            memory_usage=metrics.memory_usage
        )
        
        self.workload_predictor.add_sample(sample)
    
    def make_decision(self, metrics: ScalingMetrics) -> ScalingDecision:
        """
        Make scaling decision based on current metrics.
        
        Args:
            metrics: Current system metrics
            
        Returns:
            ScalingDecision with action and reasoning
        """
        reasoning = []
        
        # Check cooldown period
        if self._in_cooldown():
            time_remaining = self._cooldown_remaining()
            reasoning.append(f"In cooldown period ({time_remaining:.1f} minutes remaining)")
            return ScalingDecision(
                action=ScalingAction.NO_CHANGE,
                target_workers=metrics.active_workers,
                current_workers=metrics.active_workers,
                confidence=1.0,
                reasoning=reasoning,
                metrics=metrics
            )
        
        # Get workload prediction
        prediction = self.workload_predictor.predict(time_horizon_minutes=5)
        
        # Calculate scaling scores
        queue_score = self._calculate_queue_score(metrics, prediction)
        latency_score = self._calculate_latency_score(metrics)
        prediction_score = self._calculate_prediction_score(prediction)
        cost_score = self.cost_optimizer.calculate_cost_score(
            metrics.current_cost_per_hour,
            metrics.active_workers
        )
        
        # Combine scores with weights
        # 40% queue, 25% latency, 20% prediction, 15% cost
        combined_score = (
            0.40 * queue_score +
            0.25 * latency_score +
            0.20 * prediction_score +
            0.15 * cost_score
        )
        
        reasoning.append(f"Queue score: {queue_score:.2f}")
        reasoning.append(f"Latency score: {latency_score:.2f}")
        reasoning.append(f"Prediction score: {prediction_score:.2f}")
        reasoning.append(f"Cost score: {cost_score:.2f}")
        reasoning.append(f"Combined score: {combined_score:.2f}")
        
        # Make decision based on combined score
        action = ScalingAction.NO_CHANGE
        target_workers = metrics.active_workers
        
        if combined_score > self.scale_up_threshold:
            # Scale up
            action = ScalingAction.SCALE_UP
            target_workers = self._calculate_target_workers_up(metrics, prediction)
            reasoning.append(f"Score {combined_score:.2f} > threshold {self.scale_up_threshold}")
            reasoning.append(f"Scaling up from {metrics.active_workers} to {target_workers} workers")
        elif combined_score < self.scale_down_threshold:
            # Scale down
            action = ScalingAction.SCALE_DOWN
            target_workers = self._calculate_target_workers_down(metrics, prediction)
            reasoning.append(f"Score {combined_score:.2f} < threshold {self.scale_down_threshold}")
            reasoning.append(f"Scaling down from {metrics.active_workers} to {target_workers} workers")
        else:
            reasoning.append(f"Score {combined_score:.2f} within stable range")
        
        # Enforce limits
        target_workers = max(self.min_workers, min(self.max_workers, target_workers))
        
        # Calculate confidence
        confidence = self._calculate_decision_confidence(
            metrics, prediction, combined_score
        )
        
        decision = ScalingDecision(
            action=action,
            target_workers=target_workers,
            current_workers=metrics.active_workers,
            confidence=confidence,
            reasoning=reasoning,
            metrics=metrics,
            prediction=prediction
        )
        
        # Update state
        if action != ScalingAction.NO_CHANGE:
            self.last_scaling_action = datetime.utcnow()
        self.last_decision = decision
        
        return decision
    
    def _calculate_queue_score(self, metrics: ScalingMetrics, 
                               prediction: WorkloadPrediction) -> float:
        """Calculate score based on queue depth (0.0 = scale down, 1.0 = scale up)."""
        current_queue = metrics.queue_depth
        predicted_queue = prediction.predicted_queue_depth
        
        # Use max of current and predicted
        effective_queue = max(current_queue, predicted_queue)
        
        # Normalize to 0-1 range
        if effective_queue <= self.target_queue_depth * 0.5:
            return 0.0  # Very low queue, can scale down
        elif effective_queue >= self.target_queue_depth * 2.0:
            return 1.0  # Very high queue, must scale up
        else:
            # Linear interpolation
            return (effective_queue - self.target_queue_depth * 0.5) / (self.target_queue_depth * 1.5)
    
    def _calculate_latency_score(self, metrics: ScalingMetrics) -> float:
        """Calculate score based on latency (0.0 = scale down, 1.0 = scale up)."""
        latency = metrics.avg_latency_seconds
        
        if latency <= self.target_latency_seconds * 0.5:
            return 0.0  # Very low latency, can scale down
        elif latency >= self.target_latency_seconds * 2.0:
            return 1.0  # Very high latency, must scale up
        else:
            # Linear interpolation
            return (latency - self.target_latency_seconds * 0.5) / (self.target_latency_seconds * 1.5)
    
    def _calculate_prediction_score(self, prediction: WorkloadPrediction) -> float:
        """Calculate score based on workload prediction (0.0 = scale down, 1.0 = scale up)."""
        predicted_rate = prediction.predicted_validations_per_minute
        
        # Assume target rate is 1 validation per minute per worker
        target_rate = 1.0
        
        if predicted_rate <= target_rate * 0.5:
            return 0.0  # Low predicted workload
        elif predicted_rate >= target_rate * 2.0:
            return 1.0  # High predicted workload
        else:
            return (predicted_rate - target_rate * 0.5) / (target_rate * 1.5)
    
    def _calculate_target_workers_up(self, metrics: ScalingMetrics,
                                    prediction: WorkloadPrediction) -> int:
        """Calculate target worker count for scale up."""
        # Calculate based on queue and predicted workload
        queue_workers = int(metrics.queue_depth / 10) + 1
        prediction_workers = int(prediction.predicted_validations_per_minute) + 1
        
        # Take max and add buffer
        target = max(queue_workers, prediction_workers, metrics.active_workers + 1)
        
        return min(self.max_workers, target)
    
    def _calculate_target_workers_down(self, metrics: ScalingMetrics,
                                      prediction: WorkloadPrediction) -> int:
        """Calculate target worker count for scale down."""
        # Calculate based on predicted workload
        prediction_workers = max(1, int(prediction.predicted_validations_per_minute))
        
        # Scale down gradually (reduce by 1)
        target = max(prediction_workers, metrics.active_workers - 1)
        
        return max(self.min_workers, target)
    
    def _calculate_decision_confidence(self, metrics: ScalingMetrics,
                                       prediction: WorkloadPrediction,
                                       combined_score: float) -> float:
        """Calculate confidence in scaling decision."""
        # Factors: prediction confidence, score extremity, data quality
        
        # Prediction confidence (0.0 to 0.4)
        pred_confidence = prediction.confidence * 0.4
        
        # Score extremity (0.0 to 0.4) - more extreme = more confident
        score_extremity = abs(combined_score - 0.5) * 0.8
        
        # Data quality (0.0 to 0.2)
        stats = self.workload_predictor.get_statistics()
        data_quality = min(0.2, stats['sample_count'] / 100.0)
        
        confidence = pred_confidence + score_extremity + data_quality
        return min(1.0, max(0.0, confidence))
    
    def _in_cooldown(self) -> bool:
        """Check if in cooldown period."""
        if not self.last_scaling_action:
            return False
        
        elapsed = (datetime.utcnow() - self.last_scaling_action).total_seconds() / 60.0
        return elapsed < self.cooldown_minutes
    
    def _cooldown_remaining(self) -> float:
        """Get remaining cooldown time in minutes."""
        if not self.last_scaling_action:
            return 0.0
        
        elapsed = (datetime.utcnow() - self.last_scaling_action).total_seconds() / 60.0
        return max(0.0, self.cooldown_minutes - elapsed)
    
    def get_statistics(self) -> Dict:
        """Get scaling engine statistics."""
        return {
            'workload_stats': self.workload_predictor.get_statistics(),
            'last_decision': {
                'action': self.last_decision.action.value if self.last_decision else None,
                'target_workers': self.last_decision.target_workers if self.last_decision else None,
                'confidence': self.last_decision.confidence if self.last_decision else None,
                'timestamp': self.last_decision.timestamp.isoformat() if self.last_decision else None
            } if self.last_decision else None,
            'in_cooldown': self._in_cooldown(),
            'cooldown_remaining_minutes': self._cooldown_remaining()
        }

