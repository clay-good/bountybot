"""
Multi-Tenant Analytics Data Models
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4


# ============================================================================
# Usage Tracking Models
# ============================================================================

class UsageMetricType(str, Enum):
    """Types of usage metrics."""
    API_CALLS = "api_calls"
    VALIDATIONS = "validations"
    AI_TOKENS = "ai_tokens"
    STORAGE_BYTES = "storage_bytes"
    USERS_ACTIVE = "users_active"
    REPORTS_PROCESSED = "reports_processed"
    SCANS_EXECUTED = "scans_executed"
    WEBHOOKS_SENT = "webhooks_sent"
    INTEGRATIONS_USED = "integrations_used"
    FEATURES_ADOPTED = "features_adopted"


class AggregationPeriod(str, Enum):
    """Time periods for aggregation."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"


@dataclass
class UsageEvent:
    """Individual usage event."""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    tenant_id: str = ""
    metric_type: UsageMetricType = UsageMetricType.API_CALLS
    value: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'event_id': self.event_id,
            'tenant_id': self.tenant_id,
            'metric_type': self.metric_type.value,
            'value': self.value,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata,
        }


@dataclass
class UsageMetric:
    """Aggregated usage metric."""
    metric_id: str = field(default_factory=lambda: str(uuid4()))
    tenant_id: str = ""
    metric_type: UsageMetricType = UsageMetricType.API_CALLS
    period: AggregationPeriod = AggregationPeriod.DAILY
    period_start: datetime = field(default_factory=datetime.utcnow)
    period_end: datetime = field(default_factory=datetime.utcnow)
    
    # Aggregated values
    total: float = 0.0
    average: float = 0.0
    minimum: float = 0.0
    maximum: float = 0.0
    count: int = 0
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'metric_id': self.metric_id,
            'tenant_id': self.tenant_id,
            'metric_type': self.metric_type.value,
            'period': self.period.value,
            'period_start': self.period_start.isoformat(),
            'period_end': self.period_end.isoformat(),
            'total': self.total,
            'average': self.average,
            'minimum': self.minimum,
            'maximum': self.maximum,
            'count': self.count,
            'metadata': self.metadata,
        }


@dataclass
class UsageAggregation:
    """Usage aggregation summary."""
    tenant_id: str
    period: AggregationPeriod
    metrics: Dict[UsageMetricType, UsageMetric] = field(default_factory=dict)
    total_events: int = 0
    period_start: datetime = field(default_factory=datetime.utcnow)
    period_end: datetime = field(default_factory=datetime.utcnow)


# ============================================================================
# Benchmarking Models
# ============================================================================

class BenchmarkCategory(str, Enum):
    """Benchmark categories."""
    USAGE = "usage"
    PERFORMANCE = "performance"
    SECURITY = "security"
    EFFICIENCY = "efficiency"
    ENGAGEMENT = "engagement"
    QUALITY = "quality"


@dataclass
class PercentileRank:
    """Percentile ranking."""
    percentile: float  # 0-100
    value: float
    rank: int  # 1-based rank
    total_tenants: int


@dataclass
class BenchmarkMetric:
    """Benchmark metric."""
    metric_id: str = field(default_factory=lambda: str(uuid4()))
    category: BenchmarkCategory = BenchmarkCategory.USAGE
    name: str = ""
    description: str = ""
    
    # Statistical values across all tenants
    mean: float = 0.0
    median: float = 0.0
    std_dev: float = 0.0
    min_value: float = 0.0
    max_value: float = 0.0
    
    # Percentiles
    p25: float = 0.0  # 25th percentile
    p50: float = 0.0  # 50th percentile (median)
    p75: float = 0.0  # 75th percentile
    p90: float = 0.0  # 90th percentile
    p95: float = 0.0  # 95th percentile
    p99: float = 0.0  # 99th percentile
    
    # Metadata
    sample_size: int = 0
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'metric_id': self.metric_id,
            'category': self.category.value,
            'name': self.name,
            'description': self.description,
            'mean': self.mean,
            'median': self.median,
            'std_dev': self.std_dev,
            'min_value': self.min_value,
            'max_value': self.max_value,
            'p25': self.p25,
            'p50': self.p50,
            'p75': self.p75,
            'p90': self.p90,
            'p95': self.p95,
            'p99': self.p99,
            'sample_size': self.sample_size,
            'last_updated': self.last_updated.isoformat(),
        }


@dataclass
class BenchmarkComparison:
    """Tenant comparison against benchmarks."""
    tenant_id: str
    metric_name: str
    tenant_value: float
    benchmark: BenchmarkMetric
    percentile_rank: PercentileRank
    
    # Comparison insights
    above_average: bool = False
    performance_tier: str = ""  # "top", "above_average", "average", "below_average", "bottom"
    improvement_potential: float = 0.0  # % improvement to reach next tier
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'tenant_id': self.tenant_id,
            'metric_name': self.metric_name,
            'tenant_value': self.tenant_value,
            'benchmark': self.benchmark.to_dict(),
            'percentile': self.percentile_rank.percentile,
            'rank': self.percentile_rank.rank,
            'above_average': self.above_average,
            'performance_tier': self.performance_tier,
            'improvement_potential': self.improvement_potential,
        }


# ============================================================================
# Predictive Analytics Models
# ============================================================================

class PredictionType(str, Enum):
    """Types of predictions."""
    USAGE_FORECAST = "usage_forecast"
    COST_FORECAST = "cost_forecast"
    CHURN_RISK = "churn_risk"
    CAPACITY_PLANNING = "capacity_planning"
    REVENUE_FORECAST = "revenue_forecast"


class ChurnRiskLevel(str, Enum):
    """Churn risk levels."""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class UsagePrediction:
    """Usage prediction."""
    prediction_id: str = field(default_factory=lambda: str(uuid4()))
    tenant_id: str = ""
    prediction_type: PredictionType = PredictionType.USAGE_FORECAST
    metric_type: UsageMetricType = UsageMetricType.API_CALLS
    
    # Prediction details
    predicted_value: float = 0.0
    confidence: float = 0.0  # 0-1
    prediction_date: datetime = field(default_factory=datetime.utcnow)
    forecast_period: AggregationPeriod = AggregationPeriod.MONTHLY
    
    # Historical context
    historical_average: float = 0.0
    trend: str = ""  # "increasing", "decreasing", "stable"
    growth_rate: float = 0.0  # % change
    
    # Metadata
    model_version: str = "1.0"
    features_used: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'prediction_id': self.prediction_id,
            'tenant_id': self.tenant_id,
            'prediction_type': self.prediction_type.value,
            'metric_type': self.metric_type.value,
            'predicted_value': self.predicted_value,
            'confidence': self.confidence,
            'prediction_date': self.prediction_date.isoformat(),
            'forecast_period': self.forecast_period.value,
            'historical_average': self.historical_average,
            'trend': self.trend,
            'growth_rate': self.growth_rate,
            'model_version': self.model_version,
        }


@dataclass
class ChurnRiskScore:
    """Churn risk assessment."""
    tenant_id: str
    risk_score: float  # 0-1, higher = more risk
    risk_level: ChurnRiskLevel
    
    # Risk factors
    factors: List[str] = field(default_factory=list)
    
    # Engagement metrics
    days_since_last_activity: int = 0
    usage_trend: str = ""  # "increasing", "decreasing", "stable"
    feature_adoption_rate: float = 0.0
    support_tickets_count: int = 0
    
    # Predictions
    churn_probability_30d: float = 0.0
    churn_probability_90d: float = 0.0
    
    # Recommendations
    retention_actions: List[str] = field(default_factory=list)
    
    calculated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CostForecast:
    """Cost forecast."""
    tenant_id: str
    forecast_period: AggregationPeriod
    
    # Cost predictions
    predicted_cost: float = 0.0
    confidence: float = 0.0
    
    # Cost breakdown
    ai_cost: float = 0.0
    infrastructure_cost: float = 0.0
    storage_cost: float = 0.0
    other_costs: float = 0.0
    
    # Historical context
    historical_average_cost: float = 0.0
    cost_trend: str = ""  # "increasing", "decreasing", "stable"
    
    forecast_date: datetime = field(default_factory=datetime.utcnow)


# ============================================================================
# Health Scoring Models
# ============================================================================

class HealthDimension(str, Enum):
    """Health score dimensions."""
    USAGE = "usage"
    ENGAGEMENT = "engagement"
    SECURITY = "security"
    PERFORMANCE = "performance"
    BEST_PRACTICES = "best_practices"
    SUPPORT = "support"


class HealthStatus(str, Enum):
    """Overall health status."""
    EXCELLENT = "excellent"  # 90-100
    GOOD = "good"  # 75-89
    FAIR = "fair"  # 60-74
    POOR = "poor"  # 40-59
    CRITICAL = "critical"  # 0-39


@dataclass
class HealthFactor:
    """Individual health factor."""
    name: str
    dimension: HealthDimension
    score: float  # 0-100
    weight: float  # 0-1
    description: str = ""
    recommendations: List[str] = field(default_factory=list)


@dataclass
class TenantHealthScore:
    """Comprehensive tenant health score."""
    tenant_id: str
    overall_score: float  # 0-100
    status: HealthStatus

    # Dimension scores
    dimension_scores: Dict[HealthDimension, float] = field(default_factory=dict)

    # Individual factors
    factors: List[HealthFactor] = field(default_factory=list)

    # Trends
    score_trend: str = ""  # "improving", "declining", "stable"
    previous_score: Optional[float] = None
    score_change: float = 0.0

    # Insights
    strengths: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    calculated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'tenant_id': self.tenant_id,
            'overall_score': self.overall_score,
            'status': self.status.value,
            'dimension_scores': {k.value: v for k, v in self.dimension_scores.items()},
            'score_trend': self.score_trend,
            'previous_score': self.previous_score,
            'score_change': self.score_change,
            'strengths': self.strengths,
            'weaknesses': self.weaknesses,
            'recommendations': self.recommendations,
            'calculated_at': self.calculated_at.isoformat(),
        }


# ============================================================================
# SaaS Metrics Models
# ============================================================================

@dataclass
class RevenueMetrics:
    """Revenue-related metrics."""
    # Monthly Recurring Revenue
    mrr: float = 0.0
    mrr_growth_rate: float = 0.0  # % month-over-month

    # Annual Recurring Revenue
    arr: float = 0.0
    arr_growth_rate: float = 0.0  # % year-over-year

    # Average Revenue Per User
    arpu: float = 0.0
    arpu_growth_rate: float = 0.0

    # Revenue breakdown
    new_revenue: float = 0.0
    expansion_revenue: float = 0.0
    contraction_revenue: float = 0.0
    churned_revenue: float = 0.0

    # Net Revenue Retention
    nrr: float = 0.0  # %

    # Gross Revenue Retention
    grr: float = 0.0  # %


@dataclass
class CustomerMetrics:
    """Customer-related metrics."""
    # Customer counts
    total_customers: int = 0
    new_customers: int = 0
    churned_customers: int = 0
    active_customers: int = 0

    # Churn rates
    customer_churn_rate: float = 0.0  # %
    revenue_churn_rate: float = 0.0  # %

    # Customer Lifetime Value
    ltv: float = 0.0

    # Customer Acquisition Cost
    cac: float = 0.0

    # LTV:CAC ratio
    ltv_cac_ratio: float = 0.0

    # Payback period (months)
    cac_payback_period: float = 0.0

    # Customer health
    healthy_customers: int = 0
    at_risk_customers: int = 0
    critical_customers: int = 0


@dataclass
class OperationalMetrics:
    """Operational metrics."""
    # Usage metrics
    total_api_calls: int = 0
    total_validations: int = 0
    total_ai_tokens: int = 0

    # Performance metrics
    average_response_time_ms: float = 0.0
    error_rate: float = 0.0  # %
    uptime: float = 0.0  # %

    # Efficiency metrics
    cost_per_validation: float = 0.0
    cost_per_customer: float = 0.0
    gross_margin: float = 0.0  # %

    # Support metrics
    support_tickets: int = 0
    average_resolution_time_hours: float = 0.0
    customer_satisfaction_score: float = 0.0  # 0-10


@dataclass
class SaaSMetrics:
    """Comprehensive SaaS metrics."""
    period_start: datetime
    period_end: datetime
    period: AggregationPeriod

    # Metric categories
    revenue: RevenueMetrics = field(default_factory=RevenueMetrics)
    customers: CustomerMetrics = field(default_factory=CustomerMetrics)
    operations: OperationalMetrics = field(default_factory=OperationalMetrics)

    # Overall health
    overall_health_score: float = 0.0

    calculated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'period_start': self.period_start.isoformat(),
            'period_end': self.period_end.isoformat(),
            'period': self.period.value,
            'revenue': {
                'mrr': self.revenue.mrr,
                'mrr_growth_rate': self.revenue.mrr_growth_rate,
                'arr': self.revenue.arr,
                'nrr': self.revenue.nrr,
                'grr': self.revenue.grr,
            },
            'customers': {
                'total_customers': self.customers.total_customers,
                'new_customers': self.customers.new_customers,
                'churned_customers': self.customers.churned_customers,
                'customer_churn_rate': self.customers.customer_churn_rate,
                'ltv': self.customers.ltv,
                'cac': self.customers.cac,
                'ltv_cac_ratio': self.customers.ltv_cac_ratio,
            },
            'operations': {
                'total_validations': self.operations.total_validations,
                'average_response_time_ms': self.operations.average_response_time_ms,
                'error_rate': self.operations.error_rate,
                'uptime': self.operations.uptime,
                'cost_per_validation': self.operations.cost_per_validation,
                'gross_margin': self.operations.gross_margin,
            },
            'overall_health_score': self.overall_health_score,
            'calculated_at': self.calculated_at.isoformat(),
        }

