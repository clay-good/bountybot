"""
Auto-scaling module for intelligent resource management.

Provides ML-powered auto-scaling based on:
- Queue depth and pending validations
- AI provider latency and response times
- Cost optimization and budget constraints
- Predictive workload patterns
"""

from .workload_predictor import WorkloadPredictor
from .scaling_engine import ScalingEngine, ScalingDecision, ScalingAction
from .cost_optimizer import CostOptimizer
from .metrics_collector import AutoScalingMetricsCollector

__all__ = [
    'WorkloadPredictor',
    'ScalingEngine',
    'ScalingDecision',
    'ScalingAction',
    'CostOptimizer',
    'AutoScalingMetricsCollector'
]

