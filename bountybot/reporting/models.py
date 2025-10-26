"""
Data models for reporting and analytics.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional
from uuid import uuid4


class ReportType(Enum):
    """Report types."""
    EXECUTIVE_SUMMARY = "executive_summary"
    DETAILED_ANALYSIS = "detailed_analysis"
    ROI_REPORT = "roi_report"
    TREND_ANALYSIS = "trend_analysis"
    COMPLIANCE_REPORT = "compliance_report"
    SECURITY_POSTURE = "security_posture"
    VULNERABILITY_REPORT = "vulnerability_report"
    PERFORMANCE_REPORT = "performance_report"
    CUSTOM = "custom"


class ReportFormat(Enum):
    """Report output formats."""
    PDF = "pdf"
    HTML = "html"
    EXCEL = "excel"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"


class ReportPeriod(Enum):
    """Report time periods."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"
    CUSTOM = "custom"


class WidgetType(Enum):
    """Dashboard widget types."""
    METRIC_CARD = "metric_card"
    LINE_CHART = "line_chart"
    BAR_CHART = "bar_chart"
    PIE_CHART = "pie_chart"
    TABLE = "table"
    HEATMAP = "heatmap"
    GAUGE = "gauge"
    TIMELINE = "timeline"
    MAP = "map"
    CUSTOM = "custom"


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    report_id: str = field(default_factory=lambda: str(uuid4()))
    report_type: ReportType = ReportType.EXECUTIVE_SUMMARY
    report_format: ReportFormat = ReportFormat.PDF
    period: ReportPeriod = ReportPeriod.MONTHLY
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    
    # Filters
    severity_filter: Optional[List[str]] = None
    vulnerability_type_filter: Optional[List[str]] = None
    status_filter: Optional[List[str]] = None
    
    # Options
    include_executive_summary: bool = True
    include_detailed_findings: bool = True
    include_charts: bool = True
    include_recommendations: bool = True
    include_roi_metrics: bool = True
    include_trend_analysis: bool = True
    include_benchmarks: bool = False
    
    # Branding
    company_name: Optional[str] = None
    company_logo_url: Optional[str] = None
    report_title: Optional[str] = None
    report_subtitle: Optional[str] = None
    
    # Recipients
    recipients: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class ReportMetrics:
    """Core metrics for reports."""
    # Volume metrics
    total_reports_processed: int = 0
    total_vulnerabilities_found: int = 0
    total_vulnerabilities_fixed: int = 0
    total_false_positives: int = 0
    
    # Severity breakdown
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Status breakdown
    open_count: int = 0
    in_progress_count: int = 0
    fixed_count: int = 0
    verified_count: int = 0
    closed_count: int = 0
    
    # Time metrics (in hours)
    avg_time_to_validate: float = 0.0
    avg_time_to_triage: float = 0.0
    avg_time_to_fix: float = 0.0
    avg_time_to_verify: float = 0.0
    avg_total_lifecycle_time: float = 0.0
    
    # Quality metrics
    avg_confidence_score: float = 0.0
    false_positive_rate: float = 0.0
    fix_success_rate: float = 0.0
    regression_rate: float = 0.0
    
    # Performance metrics
    avg_validation_time_seconds: float = 0.0
    total_validations: int = 0
    successful_validations: int = 0
    failed_validations: int = 0
    
    # Cost metrics
    total_ai_cost: float = 0.0
    avg_cost_per_validation: float = 0.0
    total_tokens_used: int = 0


@dataclass
class ExecutiveSummary:
    """Executive summary for reports."""
    period_start: datetime
    period_end: datetime
    
    # Key highlights
    total_reports: int
    critical_vulnerabilities: int
    vulnerabilities_fixed: int
    avg_fix_time_hours: float
    
    # Trends (vs previous period)
    reports_trend_percent: float = 0.0  # +10% = improvement
    critical_trend_percent: float = 0.0
    fix_time_trend_percent: float = 0.0
    fix_rate_trend_percent: float = 0.0
    
    # Top findings
    top_vulnerability_types: List[Dict[str, Any]] = field(default_factory=list)
    top_affected_systems: List[Dict[str, Any]] = field(default_factory=list)
    
    # Recommendations
    key_recommendations: List[str] = field(default_factory=list)
    
    # Risk assessment
    overall_risk_score: float = 0.0  # 0-100
    risk_trend: str = "stable"  # improving, degrading, stable
    
    # Summary text
    summary_text: str = ""


@dataclass
class ROIMetrics:
    """Return on Investment metrics."""
    # Time savings
    manual_hours_saved: float = 0.0
    automation_rate: float = 0.0  # 0-1
    avg_time_saved_per_report: float = 0.0  # hours
    
    # Cost savings
    labor_cost_saved: float = 0.0
    incident_cost_avoided: float = 0.0
    total_cost_saved: float = 0.0
    
    # Investment
    bountybot_cost: float = 0.0
    ai_api_cost: float = 0.0
    infrastructure_cost: float = 0.0
    total_investment: float = 0.0
    
    # ROI calculation
    net_savings: float = 0.0
    roi_percent: float = 0.0
    payback_period_months: float = 0.0
    
    # Productivity metrics
    reports_processed_per_day: float = 0.0
    vulnerabilities_fixed_per_day: float = 0.0
    productivity_improvement_percent: float = 0.0
    
    # Quality improvements
    false_positive_reduction_percent: float = 0.0
    mean_time_to_remediate_improvement_percent: float = 0.0


@dataclass
class TrendData:
    """Trend analysis data."""
    metric_name: str
    time_series: List[Dict[str, Any]] = field(default_factory=list)  # [{timestamp, value}]
    
    # Trend analysis
    trend_direction: str = "stable"  # increasing, decreasing, stable
    trend_strength: float = 0.0  # 0-1
    
    # Statistical analysis
    mean: float = 0.0
    median: float = 0.0
    std_dev: float = 0.0
    min_value: float = 0.0
    max_value: float = 0.0
    
    # Forecasting
    forecast_next_period: Optional[float] = None
    forecast_confidence: float = 0.0
    
    # Anomalies
    anomalies: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class BenchmarkData:
    """Benchmark comparison data."""
    metric_name: str
    
    # Current performance
    current_value: float
    
    # Benchmarks
    industry_average: Optional[float] = None
    industry_best: Optional[float] = None
    industry_percentile: Optional[float] = None  # 0-100
    
    # Comparison
    vs_average_percent: float = 0.0
    vs_best_percent: float = 0.0
    performance_rating: str = "average"  # excellent, good, average, below_average, poor
    
    # Context
    sample_size: int = 0
    data_source: str = ""
    last_updated: Optional[datetime] = None


@dataclass
class DashboardConfig:
    """Dashboard configuration."""
    dashboard_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = "Default Dashboard"
    description: str = ""
    
    # Layout
    layout: str = "grid"  # grid, flex, custom
    columns: int = 3
    
    # Widgets
    widgets: List['DashboardWidget'] = field(default_factory=list)
    
    # Refresh
    auto_refresh: bool = True
    refresh_interval_seconds: int = 60
    
    # Access control
    owner: Optional[str] = None
    shared_with: List[str] = field(default_factory=list)
    is_public: bool = False
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)


@dataclass
class DashboardWidget:
    """Dashboard widget configuration."""
    widget_id: str = field(default_factory=lambda: str(uuid4()))
    widget_type: WidgetType = WidgetType.METRIC_CARD
    title: str = ""
    
    # Position and size
    row: int = 0
    column: int = 0
    width: int = 1
    height: int = 1
    
    # Data source
    data_source: str = ""  # metric name or query
    query_params: Dict[str, Any] = field(default_factory=dict)
    
    # Visualization options
    chart_options: Dict[str, Any] = field(default_factory=dict)
    color_scheme: str = "default"
    show_legend: bool = True
    show_labels: bool = True
    
    # Thresholds for alerts
    warning_threshold: Optional[float] = None
    critical_threshold: Optional[float] = None
    
    # Refresh
    refresh_interval_seconds: Optional[int] = None


@dataclass
class AnalyticsQuery:
    """Analytics query configuration."""
    query_id: str = field(default_factory=lambda: str(uuid4()))
    query_type: str = "aggregate"  # aggregate, timeseries, comparison
    
    # Time range
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    period: ReportPeriod = ReportPeriod.DAILY
    
    # Metrics to query
    metrics: List[str] = field(default_factory=list)
    
    # Filters
    filters: Dict[str, Any] = field(default_factory=dict)
    
    # Grouping
    group_by: Optional[List[str]] = None
    
    # Aggregation
    aggregation: str = "sum"  # sum, avg, min, max, count
    
    # Sorting
    sort_by: Optional[str] = None
    sort_order: str = "desc"  # asc, desc
    
    # Pagination
    limit: Optional[int] = None
    offset: int = 0
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)

