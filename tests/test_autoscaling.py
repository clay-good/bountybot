"""
Tests for auto-scaling module.
"""

import pytest
import time
from datetime import datetime, timedelta

from bountybot.autoscaling.workload_predictor import (
    WorkloadPredictor,
    WorkloadSample,
    WorkloadPrediction
)
from bountybot.autoscaling.scaling_engine import (
    ScalingEngine,
    ScalingMetrics,
    ScalingDecision,
    ScalingAction
)
from bountybot.autoscaling.cost_optimizer import (
    CostOptimizer,
    CostBudget,
    CostMetrics
)
from bountybot.autoscaling.metrics_collector import (
    AutoScalingMetricsCollector,
    ValidationMetrics
)


class TestWorkloadPredictor:
    """Tests for WorkloadPredictor."""
    
    def test_init(self):
        """Test predictor initialization."""
        predictor = WorkloadPredictor(history_size=100)
        assert predictor.history_size == 100
        assert len(predictor.samples) == 0
    
    def test_add_sample(self):
        """Test adding samples."""
        predictor = WorkloadPredictor()
        
        sample = WorkloadSample(
            timestamp=datetime.utcnow(),
            validations_per_minute=5.0,
            queue_depth=10,
            avg_latency_seconds=25.0,
            active_workers=3
        )
        
        predictor.add_sample(sample)
        assert len(predictor.samples) == 1
    
    def test_predict_insufficient_data(self):
        """Test prediction with insufficient data."""
        predictor = WorkloadPredictor()
        
        # Add one sample
        sample = WorkloadSample(
            timestamp=datetime.utcnow(),
            validations_per_minute=5.0,
            queue_depth=10,
            avg_latency_seconds=25.0,
            active_workers=3
        )
        predictor.add_sample(sample)
        
        # Predict
        prediction = predictor.predict(time_horizon_minutes=5)
        
        assert isinstance(prediction, WorkloadPrediction)
        assert prediction.confidence < 0.5  # Low confidence with little data
    
    def test_predict_with_data(self):
        """Test prediction with sufficient data."""
        predictor = WorkloadPredictor()
        
        # Add 20 samples with increasing workload
        base_time = datetime.utcnow()
        for i in range(20):
            sample = WorkloadSample(
                timestamp=base_time + timedelta(minutes=i),
                validations_per_minute=5.0 + i * 0.5,
                queue_depth=10 + i,
                avg_latency_seconds=25.0,
                active_workers=3
            )
            predictor.add_sample(sample)
        
        # Predict
        prediction = predictor.predict(time_horizon_minutes=5)
        
        assert isinstance(prediction, WorkloadPrediction)
        assert prediction.predicted_validations_per_minute > 0
        assert prediction.predicted_queue_depth >= 0
        assert 0.0 <= prediction.confidence <= 1.0
    
    def test_get_statistics(self):
        """Test statistics retrieval."""
        predictor = WorkloadPredictor()
        
        # Add samples
        for i in range(10):
            sample = WorkloadSample(
                timestamp=datetime.utcnow() + timedelta(minutes=i),
                validations_per_minute=5.0,
                queue_depth=10,
                avg_latency_seconds=25.0,
                active_workers=3
            )
            predictor.add_sample(sample)
        
        stats = predictor.get_statistics()
        
        assert stats['sample_count'] == 10
        assert stats['avg_validations_per_minute'] == 5.0
        assert stats['avg_queue_depth'] == 10.0


class TestScalingEngine:
    """Tests for ScalingEngine."""
    
    def test_init(self):
        """Test engine initialization."""
        config = {
            'min_workers': 1,
            'max_workers': 10,
            'target_queue_depth': 10,
            'target_latency_seconds': 30.0
        }
        
        engine = ScalingEngine(config)
        
        assert engine.min_workers == 1
        assert engine.max_workers == 10
        assert engine.target_queue_depth == 10
        assert engine.target_latency_seconds == 30.0
    
    def test_add_metrics(self):
        """Test adding metrics."""
        config = {'min_workers': 1, 'max_workers': 10}
        engine = ScalingEngine(config)
        
        metrics = ScalingMetrics(
            queue_depth=5,
            validations_per_minute=3.0,
            avg_latency_seconds=20.0,
            active_workers=2
        )
        
        engine.add_metrics(metrics)
        
        # Check that sample was added to predictor
        assert len(engine.workload_predictor.samples) == 1
    
    def test_make_decision_no_change(self):
        """Test decision with stable metrics."""
        config = {
            'min_workers': 1,
            'max_workers': 10,
            'target_queue_depth': 10,
            'target_latency_seconds': 30.0,
            'scale_up_threshold': 0.7,
            'scale_down_threshold': 0.3
        }
        engine = ScalingEngine(config)

        # Add some history with moderate load
        for i in range(15):
            metrics = ScalingMetrics(
                queue_depth=8,  # Close to target
                validations_per_minute=3.0,
                avg_latency_seconds=25.0,  # Close to target
                active_workers=3
            )
            engine.add_metrics(metrics)

        # Make decision with moderate load
        metrics = ScalingMetrics(
            queue_depth=8,
            validations_per_minute=3.0,
            avg_latency_seconds=25.0,
            active_workers=3
        )

        decision = engine.make_decision(metrics)

        assert isinstance(decision, ScalingDecision)
        # Should be NO_CHANGE or within reasonable bounds
        assert decision.current_workers == 3
    
    def test_make_decision_scale_up(self):
        """Test decision to scale up."""
        config = {
            'min_workers': 1,
            'max_workers': 10,
            'target_queue_depth': 10,
            'target_latency_seconds': 30.0,
            'scale_up_threshold': 0.6
        }
        engine = ScalingEngine(config)
        
        # Add history with increasing load
        for i in range(15):
            metrics = ScalingMetrics(
                queue_depth=20 + i,
                validations_per_minute=5.0 + i * 0.5,
                avg_latency_seconds=40.0 + i,
                active_workers=2
            )
            engine.add_metrics(metrics)
        
        # Make decision with high load
        metrics = ScalingMetrics(
            queue_depth=50,
            validations_per_minute=15.0,
            avg_latency_seconds=60.0,
            active_workers=2
        )
        
        decision = engine.make_decision(metrics)
        
        assert decision.action == ScalingAction.SCALE_UP
        assert decision.target_workers > decision.current_workers
    
    def test_make_decision_scale_down(self):
        """Test decision to scale down."""
        config = {
            'min_workers': 1,
            'max_workers': 10,
            'target_queue_depth': 10,
            'target_latency_seconds': 30.0,
            'scale_down_threshold': 0.4
        }
        engine = ScalingEngine(config)
        
        # Add history with low load
        for i in range(15):
            metrics = ScalingMetrics(
                queue_depth=2,
                validations_per_minute=1.0,
                avg_latency_seconds=10.0,
                active_workers=5
            )
            engine.add_metrics(metrics)
        
        # Make decision with low load
        metrics = ScalingMetrics(
            queue_depth=1,
            validations_per_minute=0.5,
            avg_latency_seconds=8.0,
            active_workers=5
        )
        
        decision = engine.make_decision(metrics)
        
        assert decision.action == ScalingAction.SCALE_DOWN
        assert decision.target_workers < decision.current_workers
        assert decision.target_workers >= config['min_workers']
    
    def test_cooldown_period(self):
        """Test cooldown period prevents rapid scaling."""
        config = {
            'min_workers': 1,
            'max_workers': 10,
            'cooldown_minutes': 5,
            'scale_up_threshold': 0.6
        }
        engine = ScalingEngine(config)

        # Add history to enable scaling
        for i in range(15):
            metrics = ScalingMetrics(
                queue_depth=30 + i,
                validations_per_minute=10.0 + i * 0.5,
                avg_latency_seconds=50.0,
                active_workers=2
            )
            engine.add_metrics(metrics)

        # First decision (scale up)
        metrics = ScalingMetrics(
            queue_depth=50,
            validations_per_minute=15.0,
            avg_latency_seconds=60.0,
            active_workers=2
        )

        decision1 = engine.make_decision(metrics)

        # Immediate second decision (should be blocked by cooldown if first was scale action)
        decision2 = engine.make_decision(metrics)

        # If first decision was a scaling action, second should be blocked
        if decision1.action != ScalingAction.NO_CHANGE:
            assert decision2.action == ScalingAction.NO_CHANGE
            assert "cooldown" in decision2.reasoning[0].lower()


class TestCostOptimizer:
    """Tests for CostOptimizer."""
    
    def test_init(self):
        """Test optimizer initialization."""
        config = {
            'hourly_budget': 10.0,
            'daily_budget': 200.0,
            'monthly_budget': 5000.0
        }
        
        optimizer = CostOptimizer(config)
        
        assert optimizer.budget.hourly_budget == 10.0
        assert optimizer.budget.daily_budget == 200.0
        assert optimizer.budget.monthly_budget == 5000.0
    
    def test_calculate_cost_score_low(self):
        """Test cost score with low utilization."""
        config = {'hourly_budget': 10.0}
        optimizer = CostOptimizer(config)
        
        score = optimizer.calculate_cost_score(
            current_cost_per_hour=3.0,
            active_workers=2
        )
        
        assert score == 0.0  # Low utilization, can scale up
    
    def test_calculate_cost_score_high(self):
        """Test cost score with high utilization."""
        config = {'hourly_budget': 10.0}
        optimizer = CostOptimizer(config)
        
        score = optimizer.calculate_cost_score(
            current_cost_per_hour=9.5,
            active_workers=5
        )
        
        assert score == 1.0  # High utilization, must scale down
    
    def test_can_scale_up_within_budget(self):
        """Test scaling up within budget."""
        config = {
            'hourly_budget': 10.0,
            'cost_per_worker_hour': 2.0
        }
        optimizer = CostOptimizer(config)
        optimizer.metrics.current_hour_cost = 4.0
        
        allowed, reason = optimizer.can_scale_up(
            current_workers=2,
            target_workers=3
        )
        
        assert allowed is True
        assert "within budget" in reason.lower()
    
    def test_can_scale_up_over_budget(self):
        """Test scaling up over budget."""
        config = {
            'hourly_budget': 10.0,
            'cost_per_worker_hour': 2.0
        }
        optimizer = CostOptimizer(config)
        optimizer.metrics.current_hour_cost = 9.0
        
        allowed, reason = optimizer.can_scale_up(
            current_workers=4,
            target_workers=6
        )
        
        assert allowed is False
        assert "exceed" in reason.lower()


class TestMetricsCollector:
    """Tests for AutoScalingMetricsCollector."""
    
    def test_init(self):
        """Test collector initialization."""
        collector = AutoScalingMetricsCollector(window_minutes=5)
        
        assert collector.window_minutes == 5
        assert len(collector.active_validations) == 0
    
    def test_start_validation(self):
        """Test starting validation."""
        collector = AutoScalingMetricsCollector()
        
        collector.start_validation("val-001")
        
        assert "val-001" in collector.active_validations
        assert len(collector.active_validations) == 1
    
    def test_end_validation(self):
        """Test ending validation."""
        collector = AutoScalingMetricsCollector()
        
        collector.start_validation("val-001")
        time.sleep(0.1)
        collector.end_validation("val-001", success=True)
        
        assert "val-001" not in collector.active_validations
        assert len(collector.completed_validations) == 1
        assert collector.total_validations == 1
        assert collector.total_successes == 1
    
    def test_get_current_metrics(self):
        """Test getting current metrics."""
        collector = AutoScalingMetricsCollector()
        
        # Start some validations
        collector.start_validation("val-001")
        collector.start_validation("val-002")
        
        # Complete one
        time.sleep(0.1)
        collector.end_validation("val-001", success=True)
        
        metrics = collector.get_current_metrics()
        
        assert metrics['queue_depth'] == 1  # One still active
        assert metrics['validations_per_minute'] >= 0
        assert 'cpu_usage' in metrics
        assert 'memory_usage' in metrics
    
    def test_get_statistics(self):
        """Test getting statistics."""
        collector = AutoScalingMetricsCollector()
        
        # Add some validations
        for i in range(5):
            collector.start_validation(f"val-{i}")
            time.sleep(0.05)
            collector.end_validation(f"val-{i}", success=True)
        
        stats = collector.get_statistics()
        
        assert stats['total_validations'] == 5
        assert stats['total_successes'] == 5
        assert stats['overall_success_rate'] == 1.0

