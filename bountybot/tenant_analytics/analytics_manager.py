"""
Tenant Analytics Manager

Central manager that coordinates all analytics components.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from bountybot.tenant_analytics.models import (
    UsageMetricType,
    AggregationPeriod,
    BenchmarkCategory,
    PredictionType,
    ChurnRiskLevel,
    HealthStatus,
)
from bountybot.tenant_analytics.usage_tracker import UsageTracker
from bountybot.tenant_analytics.benchmarking_engine import BenchmarkingEngine
from bountybot.tenant_analytics.predictive_engine import PredictiveAnalyticsEngine
from bountybot.tenant_analytics.health_scorer import TenantHealthScorer
from bountybot.tenant_analytics.saas_metrics import SaaSMetricsCalculator


logger = logging.getLogger(__name__)


class TenantAnalyticsManager:
    """Central manager for tenant analytics."""
    
    def __init__(self):
        """Initialize analytics manager."""
        self.usage_tracker = UsageTracker()
        self.benchmarking_engine = BenchmarkingEngine()
        self.predictive_engine = PredictiveAnalyticsEngine()
        self.health_scorer = TenantHealthScorer()
        self.saas_metrics = SaaSMetricsCalculator()
        
        logger.info("Tenant Analytics Manager initialized")
    
    # ========================================================================
    # Usage Tracking
    # ========================================================================
    
    def track_usage(
        self,
        tenant_id: str,
        metric_type: UsageMetricType,
        value: float = 1.0,
        metadata: Optional[Dict] = None,
    ):
        """Track a usage event."""
        return self.usage_tracker.track_event(tenant_id, metric_type, value, metadata)
    
    def get_tenant_usage(
        self,
        tenant_id: str,
        period: AggregationPeriod = AggregationPeriod.DAILY,
    ):
        """Get usage metrics for a tenant."""
        return self.usage_tracker.aggregate_metrics(tenant_id, period)
    
    def get_usage_trend(
        self,
        tenant_id: str,
        metric_type: UsageMetricType,
        num_periods: int = 7,
    ):
        """Get usage trend over time."""
        return self.usage_tracker.get_usage_trend(tenant_id, metric_type, num_periods)
    
    # ========================================================================
    # Benchmarking
    # ========================================================================
    
    def calculate_benchmarks(
        self,
        metric_name: str,
        category: BenchmarkCategory,
        tenant_values: Dict[str, float],
        description: str = "",
    ):
        """Calculate benchmark statistics."""
        return self.benchmarking_engine.calculate_benchmark(
            metric_name, category, tenant_values, description
        )
    
    def compare_tenant_to_benchmark(
        self,
        tenant_id: str,
        metric_name: str,
        tenant_value: float,
    ):
        """Compare tenant against benchmark."""
        return self.benchmarking_engine.compare_tenant(tenant_id, metric_name, tenant_value)
    
    def get_tenant_benchmarks(
        self,
        tenant_id: str,
        category: Optional[BenchmarkCategory] = None,
    ):
        """Get all benchmark comparisons for a tenant."""
        return self.benchmarking_engine.get_tenant_benchmarks(tenant_id, category)
    
    def get_top_performers(
        self,
        metric_name: str,
        limit: int = 10,
    ):
        """Get top performing tenants."""
        return self.benchmarking_engine.get_top_performers(metric_name, limit)
    
    # ========================================================================
    # Predictive Analytics
    # ========================================================================
    
    def predict_usage(
        self,
        tenant_id: str,
        metric_type: UsageMetricType,
        historical_values: List[float],
        forecast_period: AggregationPeriod = AggregationPeriod.MONTHLY,
    ):
        """Predict future usage."""
        return self.predictive_engine.predict_usage(
            tenant_id, metric_type, historical_values, forecast_period
        )
    
    def calculate_churn_risk(
        self,
        tenant_id: str,
        days_since_last_activity: int,
        usage_values: List[float],
        feature_adoption_count: int,
        total_features: int,
        support_tickets_count: int = 0,
    ):
        """Calculate churn risk score."""
        return self.predictive_engine.calculate_churn_risk(
            tenant_id,
            days_since_last_activity,
            usage_values,
            feature_adoption_count,
            total_features,
            support_tickets_count,
        )
    
    def forecast_cost(
        self,
        tenant_id: str,
        historical_costs: List[float],
        forecast_period: AggregationPeriod = AggregationPeriod.MONTHLY,
    ):
        """Forecast future costs."""
        return self.predictive_engine.forecast_cost(tenant_id, historical_costs, forecast_period)
    
    def get_high_risk_tenants(
        self,
        min_risk_level: ChurnRiskLevel = ChurnRiskLevel.HIGH,
    ):
        """Get tenants with high churn risk."""
        return self.predictive_engine.get_high_risk_tenants(min_risk_level)
    
    # ========================================================================
    # Health Scoring
    # ========================================================================
    
    def calculate_tenant_health(
        self,
        tenant_id: str,
        usage_metrics: Dict[str, float],
        engagement_metrics: Dict[str, float],
        security_metrics: Dict[str, float],
        performance_metrics: Dict[str, float],
        best_practices_metrics: Dict[str, float],
        support_metrics: Dict[str, float],
        previous_score: Optional[float] = None,
    ):
        """Calculate tenant health score."""
        return self.health_scorer.calculate_health_score(
            tenant_id,
            usage_metrics,
            engagement_metrics,
            security_metrics,
            performance_metrics,
            best_practices_metrics,
            support_metrics,
            previous_score,
        )
    
    def get_tenant_health(self, tenant_id: str):
        """Get health score for a tenant."""
        return self.health_scorer.get_health_score(tenant_id)
    
    def get_unhealthy_tenants(
        self,
        max_status: HealthStatus = HealthStatus.FAIR,
    ):
        """Get tenants with poor health."""
        return self.health_scorer.get_unhealthy_tenants(max_status)
    
    # ========================================================================
    # SaaS Metrics
    # ========================================================================
    
    def calculate_saas_metrics(
        self,
        period_start: datetime,
        period_end: datetime,
        period: AggregationPeriod,
        **kwargs,
    ):
        """Calculate comprehensive SaaS metrics."""
        return self.saas_metrics.calculate_saas_metrics(
            period_start, period_end, period, **kwargs
        )
    
    def get_latest_saas_metrics(self):
        """Get the most recent SaaS metrics."""
        return self.saas_metrics.get_latest_metrics()
    
    def get_saas_metrics_history(
        self,
        period: Optional[AggregationPeriod] = None,
        limit: Optional[int] = None,
    ):
        """Get historical SaaS metrics."""
        return self.saas_metrics.get_metrics_history(period, limit)
    
    def get_growth_trends(self, num_periods: int = 6):
        """Get growth trends over time."""
        return self.saas_metrics.get_growth_trends(num_periods)
    
    # ========================================================================
    # Comprehensive Analytics
    # ========================================================================
    
    def get_tenant_analytics_summary(self, tenant_id: str) -> Dict:
        """
        Get comprehensive analytics summary for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Dictionary with all analytics for the tenant
        """
        summary = {
            'tenant_id': tenant_id,
            'usage': None,
            'benchmarks': [],
            'predictions': [],
            'churn_risk': None,
            'health_score': None,
        }
        
        # Usage
        try:
            usage = self.usage_tracker.aggregate_metrics(tenant_id, AggregationPeriod.DAILY)
            summary['usage'] = {
                'total_events': usage.total_events,
                'metrics': {k.value: v.to_dict() for k, v in usage.metrics.items()},
            }
        except Exception as e:
            logger.error(f"Error getting usage for tenant {tenant_id}: {e}")
        
        # Benchmarks
        try:
            benchmarks = self.benchmarking_engine.get_tenant_benchmarks(tenant_id)
            summary['benchmarks'] = [b.to_dict() for b in benchmarks]
        except Exception as e:
            logger.error(f"Error getting benchmarks for tenant {tenant_id}: {e}")
        
        # Predictions
        try:
            predictions = self.predictive_engine.get_predictions(tenant_id)
            summary['predictions'] = [p.to_dict() for p in predictions]
        except Exception as e:
            logger.error(f"Error getting predictions for tenant {tenant_id}: {e}")
        
        # Churn risk
        try:
            churn_risk = self.predictive_engine.get_churn_risk(tenant_id)
            if churn_risk:
                summary['churn_risk'] = {
                    'risk_score': churn_risk.risk_score,
                    'risk_level': churn_risk.risk_level.value,
                    'factors': churn_risk.factors,
                    'retention_actions': churn_risk.retention_actions,
                }
        except Exception as e:
            logger.error(f"Error getting churn risk for tenant {tenant_id}: {e}")
        
        # Health score
        try:
            health = self.health_scorer.get_health_score(tenant_id)
            if health:
                summary['health_score'] = health.to_dict()
        except Exception as e:
            logger.error(f"Error getting health score for tenant {tenant_id}: {e}")
        
        return summary
    
    def get_platform_analytics_summary(self) -> Dict:
        """
        Get platform-wide analytics summary.
        
        Returns:
            Dictionary with platform-wide analytics
        """
        summary = {
            'usage_stats': self.usage_tracker.get_stats(),
            'benchmarking_stats': self.benchmarking_engine.get_stats(),
            'predictive_stats': self.predictive_engine.get_stats(),
            'health_stats': self.health_scorer.get_stats(),
            'saas_metrics': None,
        }
        
        # Latest SaaS metrics
        latest_saas = self.saas_metrics.get_latest_metrics()
        if latest_saas:
            summary['saas_metrics'] = latest_saas.to_dict()
        
        return summary
    
    def get_stats(self) -> Dict:
        """Get comprehensive statistics."""
        return {
            'usage_tracker': self.usage_tracker.get_stats(),
            'benchmarking_engine': self.benchmarking_engine.get_stats(),
            'predictive_engine': self.predictive_engine.get_stats(),
            'health_scorer': self.health_scorer.get_stats(),
            'saas_metrics': self.saas_metrics.get_stats(),
        }

