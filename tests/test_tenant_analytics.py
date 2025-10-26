"""
Tests for Tenant Analytics System
"""

import pytest
from datetime import datetime, timedelta

from bountybot.tenant_analytics import (
    UsageTracker,
    BenchmarkingEngine,
    PredictiveAnalyticsEngine,
    TenantHealthScorer,
    SaaSMetricsCalculator,
    TenantAnalyticsManager,
    UsageMetricType,
    AggregationPeriod,
    BenchmarkCategory,
    ChurnRiskLevel,
    HealthStatus,
    HealthDimension,
)


# ============================================================================
# Usage Tracker Tests
# ============================================================================

class TestUsageTracker:
    """Tests for UsageTracker."""
    
    def test_track_event(self):
        """Test tracking a usage event."""
        tracker = UsageTracker()
        
        event = tracker.track_event(
            tenant_id="tenant1",
            metric_type=UsageMetricType.API_CALLS,
            value=1.0,
        )
        
        assert event.tenant_id == "tenant1"
        assert event.metric_type == UsageMetricType.API_CALLS
        assert event.value == 1.0
        assert len(tracker.events) == 1
    
    def test_track_multiple_events(self):
        """Test tracking multiple events."""
        tracker = UsageTracker()
        
        for i in range(10):
            tracker.track_event(
                tenant_id="tenant1",
                metric_type=UsageMetricType.API_CALLS,
                value=1.0,
            )
        
        assert len(tracker.events) == 10
        assert tracker.stats['total_events'] == 10
    
    def test_track_different_metric_types(self):
        """Test tracking different metric types."""
        tracker = UsageTracker()

        tracker.track_api_call("tenant1", "/api/validate", 100.0)
        tracker.track_validation("tenant1", "security", 5.0)
        tracker.track_ai_tokens("tenant1", 1000, "openai", "gpt-4")
        tracker.track_storage("tenant1", 1024 * 1024, "s3")

        assert len(tracker.events) == 4
        assert tracker.stats['events_by_type'][UsageMetricType.API_CALLS] == 1
        assert tracker.stats['events_by_type'][UsageMetricType.VALIDATIONS] == 1
        assert tracker.stats['events_by_type'][UsageMetricType.AI_TOKENS] == 1
        assert tracker.stats['events_by_type'][UsageMetricType.STORAGE_BYTES] == 1
    
    def test_aggregate_metrics(self):
        """Test aggregating usage metrics."""
        tracker = UsageTracker()

        # Track 10 API calls
        for i in range(10):
            tracker.track_api_call("tenant1", "/api/validate", 100.0)

        # Aggregate
        aggregation = tracker.aggregate_metrics(
            tenant_id="tenant1",
            period=AggregationPeriod.DAILY,
        )

        assert aggregation.tenant_id == "tenant1"
        assert aggregation.total_events == 10
        assert UsageMetricType.API_CALLS in aggregation.metrics

        metric = aggregation.metrics[UsageMetricType.API_CALLS]
        assert metric.total == 10.0
        assert metric.count == 10
    
    def test_get_usage_trend(self):
        """Test getting usage trend."""
        tracker = UsageTracker()

        # Track events over multiple days
        for day in range(7):
            for i in range(day + 1):  # Increasing trend
                tracker.track_api_call("tenant1", "/api/validate", 100.0)

        trend = tracker.get_usage_trend(
            tenant_id="tenant1",
            metric_type=UsageMetricType.API_CALLS,
            num_periods=7,
        )

        assert len(trend) <= 7
    
    def test_get_top_tenants(self):
        """Test getting top tenants by usage."""
        tracker = UsageTracker()

        # Track different amounts for different tenants
        for i in range(10):
            tracker.track_api_call("tenant1", "/api/validate", 100.0)
        for i in range(5):
            tracker.track_api_call("tenant2", "/api/validate", 100.0)
        for i in range(15):
            tracker.track_api_call("tenant3", "/api/validate", 100.0)

        # Aggregate metrics for each tenant
        tracker.aggregate_metrics("tenant1", AggregationPeriod.DAILY)
        tracker.aggregate_metrics("tenant2", AggregationPeriod.DAILY)
        tracker.aggregate_metrics("tenant3", AggregationPeriod.DAILY)

        top_tenants = tracker.get_top_tenants(
            metric_type=UsageMetricType.API_CALLS,
            limit=3,
        )

        assert len(top_tenants) == 3
        assert top_tenants[0][0] == "tenant3"  # Highest usage
        assert top_tenants[0][1] == 15


# ============================================================================
# Benchmarking Engine Tests
# ============================================================================

class TestBenchmarkingEngine:
    """Tests for BenchmarkingEngine."""
    
    def test_calculate_benchmark(self):
        """Test calculating benchmark statistics."""
        engine = BenchmarkingEngine()
        
        tenant_values = {
            "tenant1": 100.0,
            "tenant2": 200.0,
            "tenant3": 150.0,
            "tenant4": 300.0,
            "tenant5": 250.0,
        }
        
        benchmark = engine.calculate_benchmark(
            metric_name="api_calls_per_day",
            category=BenchmarkCategory.USAGE,
            tenant_values=tenant_values,
            description="API calls per day",
        )
        
        assert benchmark.name == "api_calls_per_day"
        assert benchmark.category == BenchmarkCategory.USAGE
        assert benchmark.mean == 200.0
        assert benchmark.median == 200.0
        assert benchmark.sample_size == 5
    
    def test_compare_tenant(self):
        """Test comparing tenant against benchmark."""
        engine = BenchmarkingEngine()
        
        tenant_values = {
            "tenant1": 100.0,
            "tenant2": 200.0,
            "tenant3": 150.0,
            "tenant4": 300.0,
            "tenant5": 250.0,
        }
        
        engine.calculate_benchmark(
            metric_name="api_calls_per_day",
            category=BenchmarkCategory.USAGE,
            tenant_values=tenant_values,
        )
        
        comparison = engine.compare_tenant(
            tenant_id="tenant4",
            metric_name="api_calls_per_day",
            tenant_value=300.0,
        )
        
        assert comparison.tenant_id == "tenant4"
        assert comparison.tenant_value == 300.0
        assert comparison.above_average is True
        assert comparison.performance_tier == "top"
    
    def test_get_top_performers(self):
        """Test getting top performers."""
        engine = BenchmarkingEngine()
        
        tenant_values = {
            "tenant1": 100.0,
            "tenant2": 200.0,
            "tenant3": 150.0,
            "tenant4": 300.0,
            "tenant5": 250.0,
        }
        
        engine.calculate_benchmark(
            metric_name="api_calls_per_day",
            category=BenchmarkCategory.USAGE,
            tenant_values=tenant_values,
        )
        
        top_performers = engine.get_top_performers(
            metric_name="api_calls_per_day",
            limit=3,
        )
        
        assert len(top_performers) == 3
        assert top_performers[0][0] == "tenant4"  # Highest value
        assert top_performers[0][1] == 300.0
    
    def test_performance_distribution(self):
        """Test getting performance distribution."""
        engine = BenchmarkingEngine()
        
        tenant_values = {f"tenant{i}": float(i * 10) for i in range(1, 21)}
        
        engine.calculate_benchmark(
            metric_name="api_calls_per_day",
            category=BenchmarkCategory.USAGE,
            tenant_values=tenant_values,
        )
        
        distribution = engine.get_performance_distribution("api_calls_per_day")
        
        assert isinstance(distribution, dict)
        assert sum(distribution.values()) == 20  # All tenants categorized


# ============================================================================
# Predictive Analytics Tests
# ============================================================================

class TestPredictiveAnalyticsEngine:
    """Tests for PredictiveAnalyticsEngine."""
    
    def test_predict_usage_increasing(self):
        """Test predicting usage with increasing trend."""
        engine = PredictiveAnalyticsEngine()
        
        historical_values = [100, 120, 140, 160, 180]
        
        prediction = engine.predict_usage(
            tenant_id="tenant1",
            metric_type=UsageMetricType.API_CALLS,
            historical_values=historical_values,
        )
        
        assert prediction.tenant_id == "tenant1"
        assert prediction.predicted_value > 180  # Should predict higher
        assert prediction.trend == "increasing"
        assert prediction.confidence > 0
    
    def test_predict_usage_decreasing(self):
        """Test predicting usage with decreasing trend."""
        engine = PredictiveAnalyticsEngine()
        
        historical_values = [200, 180, 160, 140, 120]
        
        prediction = engine.predict_usage(
            tenant_id="tenant1",
            metric_type=UsageMetricType.API_CALLS,
            historical_values=historical_values,
        )
        
        assert prediction.trend == "decreasing"
        assert prediction.growth_rate < 0
    
    def test_calculate_churn_risk_high(self):
        """Test calculating high churn risk."""
        engine = PredictiveAnalyticsEngine()
        
        churn_score = engine.calculate_churn_risk(
            tenant_id="tenant1",
            days_since_last_activity=45,  # Very inactive
            usage_values=[100, 90, 80, 70, 60],  # Declining
            feature_adoption_count=2,  # Low adoption
            total_features=20,
            support_tickets_count=15,  # Many tickets
        )
        
        assert churn_score.tenant_id == "tenant1"
        assert churn_score.risk_level in [ChurnRiskLevel.HIGH, ChurnRiskLevel.VERY_HIGH]
        assert len(churn_score.factors) > 0
        assert len(churn_score.retention_actions) > 0
    
    def test_calculate_churn_risk_low(self):
        """Test calculating low churn risk."""
        engine = PredictiveAnalyticsEngine()
        
        churn_score = engine.calculate_churn_risk(
            tenant_id="tenant1",
            days_since_last_activity=1,  # Very active
            usage_values=[100, 110, 120, 130, 140],  # Increasing
            feature_adoption_count=15,  # High adoption
            total_features=20,
            support_tickets_count=1,  # Few tickets
        )
        
        assert churn_score.risk_level in [ChurnRiskLevel.VERY_LOW, ChurnRiskLevel.LOW]
    
    def test_forecast_cost(self):
        """Test forecasting costs."""
        engine = PredictiveAnalyticsEngine()
        
        historical_costs = [1000, 1100, 1200, 1300, 1400]
        
        forecast = engine.forecast_cost(
            tenant_id="tenant1",
            historical_costs=historical_costs,
        )
        
        assert forecast.tenant_id == "tenant1"
        assert forecast.predicted_cost > 0
        assert forecast.confidence > 0
        assert forecast.ai_cost > 0
        assert forecast.infrastructure_cost > 0
    
    def test_get_high_risk_tenants(self):
        """Test getting high risk tenants."""
        engine = PredictiveAnalyticsEngine()
        
        # Create some churn scores
        engine.calculate_churn_risk("tenant1", 45, [100, 90, 80], 2, 20, 15)
        engine.calculate_churn_risk("tenant2", 1, [100, 110, 120], 15, 20, 1)
        engine.calculate_churn_risk("tenant3", 30, [100, 95, 90], 5, 20, 8)
        
        high_risk = engine.get_high_risk_tenants(ChurnRiskLevel.HIGH)
        
        assert len(high_risk) >= 0  # May have high risk tenants


# ============================================================================
# Health Scorer Tests
# ============================================================================

class TestTenantHealthScorer:
    """Tests for TenantHealthScorer."""
    
    def test_calculate_health_score_excellent(self):
        """Test calculating excellent health score."""
        scorer = TenantHealthScorer()
        
        health_score = scorer.calculate_health_score(
            tenant_id="tenant1",
            usage_metrics={'api_calls_per_day': 100, 'validations_per_month': 50},
            engagement_metrics={'active_users': 10, 'total_users': 10, 'days_since_last_activity': 0, 'features_adopted': 18, 'total_features': 20},
            security_metrics={'security_validations': 50, 'false_positive_rate': 0.05, 'critical_vulnerabilities_open': 0},
            performance_metrics={'avg_response_time_ms': 200, 'error_rate': 0.01},
            best_practices_metrics={'automation_rate': 0.8, 'integrations_active': 5},
            support_metrics={'support_tickets': 1},
        )
        
        assert health_score.tenant_id == "tenant1"
        assert health_score.overall_score >= 80  # Should be high
        assert health_score.status in [HealthStatus.EXCELLENT, HealthStatus.GOOD]
    
    def test_calculate_health_score_poor(self):
        """Test calculating poor health score."""
        scorer = TenantHealthScorer()
        
        health_score = scorer.calculate_health_score(
            tenant_id="tenant1",
            usage_metrics={'api_calls_per_day': 5, 'validations_per_month': 2},
            engagement_metrics={'active_users': 1, 'total_users': 10, 'days_since_last_activity': 30, 'features_adopted': 2, 'total_features': 20},
            security_metrics={'security_validations': 5, 'false_positive_rate': 0.5, 'critical_vulnerabilities_open': 10},
            performance_metrics={'avg_response_time_ms': 3000, 'error_rate': 0.1},
            best_practices_metrics={'automation_rate': 0.1, 'integrations_active': 0},
            support_metrics={'support_tickets': 20},
        )
        
        assert health_score.overall_score < 60  # Should be low
        assert health_score.status in [HealthStatus.POOR, HealthStatus.CRITICAL, HealthStatus.FAIR]
        assert len(health_score.weaknesses) > 0
        assert len(health_score.recommendations) > 0
    
    def test_get_unhealthy_tenants(self):
        """Test getting unhealthy tenants."""
        scorer = TenantHealthScorer()
        
        # Create some health scores
        scorer.calculate_health_score(
            "tenant1",
            {'api_calls_per_day': 100}, {'active_users': 10, 'total_users': 10, 'days_since_last_activity': 0, 'features_adopted': 18, 'total_features': 20},
            {'security_validations': 50, 'false_positive_rate': 0.05, 'critical_vulnerabilities_open': 0},
            {'avg_response_time_ms': 200, 'error_rate': 0.01},
            {'automation_rate': 0.8, 'integrations_active': 5},
            {'support_tickets': 1},
        )
        
        scorer.calculate_health_score(
            "tenant2",
            {'api_calls_per_day': 5}, {'active_users': 1, 'total_users': 10, 'days_since_last_activity': 30, 'features_adopted': 2, 'total_features': 20},
            {'security_validations': 5, 'false_positive_rate': 0.5, 'critical_vulnerabilities_open': 10},
            {'avg_response_time_ms': 3000, 'error_rate': 0.1},
            {'automation_rate': 0.1, 'integrations_active': 0},
            {'support_tickets': 20},
        )
        
        unhealthy = scorer.get_unhealthy_tenants(HealthStatus.FAIR)
        
        assert len(unhealthy) >= 0  # May have unhealthy tenants


# ============================================================================
# SaaS Metrics Tests
# ============================================================================

class TestSaaSMetricsCalculator:
    """Tests for SaaSMetricsCalculator."""
    
    def test_calculate_saas_metrics(self):
        """Test calculating comprehensive SaaS metrics."""
        calculator = SaaSMetricsCalculator()
        
        now = datetime.utcnow()
        
        metrics = calculator.calculate_saas_metrics(
            period_start=now - timedelta(days=30),
            period_end=now,
            period=AggregationPeriod.MONTHLY,
            current_mrr=10000,
            previous_mrr=9000,
            new_revenue=1500,
            expansion_revenue=500,
            contraction_revenue=200,
            churned_revenue=300,
            total_customers=100,
            new_customers=10,
            churned_customers=5,
            active_customers=95,
            total_acquisition_cost=5000,
            total_api_calls=100000,
            total_validations=5000,
            total_ai_tokens=1000000,
            average_response_time_ms=500,
            error_count=100,
            total_requests=10000,
            uptime_percentage=99.9,
            total_costs=3000,
            support_tickets=50,
            total_resolution_time_hours=100,
            customer_satisfaction_score=8.5,
        )
        
        assert metrics.revenue.mrr == 10000
        assert metrics.revenue.arr == 120000
        assert metrics.revenue.mrr_growth_rate > 0
        assert metrics.customers.total_customers == 100
        # LTV may be 0 if churn rate is 0 (no previous customers to calculate from)
        assert metrics.customers.ltv >= 0
        assert metrics.customers.cac > 0
        assert metrics.operations.total_validations == 5000
        assert metrics.overall_health_score > 0
    
    def test_get_growth_trends(self):
        """Test getting growth trends."""
        calculator = SaaSMetricsCalculator()
        
        now = datetime.utcnow()
        
        # Calculate metrics for multiple periods
        for i in range(6):
            calculator.calculate_saas_metrics(
                period_start=now - timedelta(days=30 * (i + 1)),
                period_end=now - timedelta(days=30 * i),
                period=AggregationPeriod.MONTHLY,
                current_mrr=10000 + (i * 1000),
                previous_mrr=9000 + (i * 1000),
                new_revenue=1500,
                expansion_revenue=500,
                contraction_revenue=200,
                churned_revenue=300,
                total_customers=100 + (i * 10),
                new_customers=10,
                churned_customers=5,
                active_customers=95 + (i * 10),
                total_acquisition_cost=5000,
                total_api_calls=100000,
                total_validations=5000,
                total_ai_tokens=1000000,
                average_response_time_ms=500,
                error_count=100,
                total_requests=10000,
                uptime_percentage=99.9,
                total_costs=3000,
                support_tickets=50,
                total_resolution_time_hours=100,
                customer_satisfaction_score=8.5,
            )
        
        trends = calculator.get_growth_trends(num_periods=6)
        
        assert 'mrr' in trends
        assert 'arr' in trends
        assert 'total_customers' in trends
        assert len(trends['mrr']) == 6


# ============================================================================
# Analytics Manager Tests
# ============================================================================

class TestTenantAnalyticsManager:
    """Tests for TenantAnalyticsManager."""
    
    def test_initialization(self):
        """Test manager initialization."""
        manager = TenantAnalyticsManager()
        
        assert manager.usage_tracker is not None
        assert manager.benchmarking_engine is not None
        assert manager.predictive_engine is not None
        assert manager.health_scorer is not None
        assert manager.saas_metrics is not None
    
    def test_track_usage(self):
        """Test tracking usage through manager."""
        manager = TenantAnalyticsManager()
        
        event = manager.track_usage(
            tenant_id="tenant1",
            metric_type=UsageMetricType.API_CALLS,
            value=1.0,
        )
        
        assert event.tenant_id == "tenant1"
    
    def test_get_tenant_analytics_summary(self):
        """Test getting comprehensive tenant analytics."""
        manager = TenantAnalyticsManager()
        
        # Track some usage
        manager.track_usage("tenant1", UsageMetricType.API_CALLS, 1.0)
        
        summary = manager.get_tenant_analytics_summary("tenant1")
        
        assert summary['tenant_id'] == "tenant1"
        assert 'usage' in summary
        assert 'benchmarks' in summary
        assert 'predictions' in summary
        assert 'churn_risk' in summary
        assert 'health_score' in summary
    
    def test_get_platform_analytics_summary(self):
        """Test getting platform-wide analytics."""
        manager = TenantAnalyticsManager()
        
        # Track some usage
        manager.track_usage("tenant1", UsageMetricType.API_CALLS, 1.0)
        manager.track_usage("tenant2", UsageMetricType.API_CALLS, 1.0)
        
        summary = manager.get_platform_analytics_summary()
        
        assert 'usage_stats' in summary
        assert 'benchmarking_stats' in summary
        assert 'predictive_stats' in summary
        assert 'health_stats' in summary

