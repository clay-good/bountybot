"""
Multi-Tenant Analytics & Insights

Comprehensive analytics system for multi-tenant SaaS operations including:
- Tenant usage analytics and tracking
- Cross-tenant benchmarking
- Predictive analytics and forecasting
- Tenant health scoring
- SaaS metrics (MRR, churn, LTV, CAC)
"""

from bountybot.tenant_analytics.models import (
    # Usage tracking
    UsageMetric,
    UsageMetricType,
    UsageEvent,
    UsageAggregation,
    AggregationPeriod,
    
    # Benchmarking
    BenchmarkMetric,
    BenchmarkCategory,
    BenchmarkComparison,
    PercentileRank,
    
    # Predictions
    UsagePrediction,
    PredictionType,
    ChurnRiskScore,
    ChurnRiskLevel,
    CostForecast,
    
    # Health scoring
    TenantHealthScore,
    HealthDimension,
    HealthStatus,
    HealthFactor,
    
    # SaaS metrics
    SaaSMetrics,
    RevenueMetrics,
    CustomerMetrics,
    OperationalMetrics,
)

from bountybot.tenant_analytics.usage_tracker import (
    UsageTracker,
)

from bountybot.tenant_analytics.benchmarking_engine import (
    BenchmarkingEngine,
)

from bountybot.tenant_analytics.predictive_engine import (
    PredictiveAnalyticsEngine,
)

from bountybot.tenant_analytics.health_scorer import (
    TenantHealthScorer,
)

from bountybot.tenant_analytics.saas_metrics import (
    SaaSMetricsCalculator,
)

from bountybot.tenant_analytics.analytics_manager import (
    TenantAnalyticsManager,
)


__all__ = [
    # Models
    'UsageMetric',
    'UsageMetricType',
    'UsageEvent',
    'UsageAggregation',
    'AggregationPeriod',
    'BenchmarkMetric',
    'BenchmarkCategory',
    'BenchmarkComparison',
    'PercentileRank',
    'UsagePrediction',
    'PredictionType',
    'ChurnRiskScore',
    'ChurnRiskLevel',
    'CostForecast',
    'TenantHealthScore',
    'HealthDimension',
    'HealthStatus',
    'HealthFactor',
    'SaaSMetrics',
    'RevenueMetrics',
    'CustomerMetrics',
    'OperationalMetrics',
    
    # Components
    'UsageTracker',
    'BenchmarkingEngine',
    'PredictiveAnalyticsEngine',
    'TenantHealthScorer',
    'SaaSMetricsCalculator',
    'TenantAnalyticsManager',
]

