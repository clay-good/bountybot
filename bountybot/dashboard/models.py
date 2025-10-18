"""
Dashboard Data Models

Pydantic models for dashboard API requests and responses.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from pydantic import BaseModel, Field


class TimeRange(str, Enum):
    """Time range for analytics queries."""
    HOUR = "1h"
    DAY = "24h"
    WEEK = "7d"
    MONTH = "30d"
    QUARTER = "90d"
    YEAR = "365d"
    ALL = "all"


class ReportStatus(str, Enum):
    """Report processing status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class IntegrationStatusEnum(str, Enum):
    """Integration health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"


@dataclass
class DashboardConfig:
    """Dashboard configuration."""
    title: str = "BountyBot Dashboard"
    refresh_interval: int = 30  # seconds
    max_reports_display: int = 100
    enable_realtime: bool = True
    enable_notifications: bool = True
    theme: str = "dark"  # dark or light


class ReportSummary(BaseModel):
    """Summary of a validation report."""
    report_id: str
    title: str
    vulnerability_type: str
    verdict: str
    confidence: float
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    priority_level: Optional[str] = None
    researcher: Optional[str] = None
    submitted_at: datetime
    processed_at: Optional[datetime] = None
    processing_time: Optional[float] = None
    status: ReportStatus
    integration_count: int = 0
    has_poc: bool = False
    is_duplicate: bool = False
    is_false_positive: bool = False


class AnalyticsSummary(BaseModel):
    """Analytics summary for dashboard."""
    time_range: TimeRange
    total_reports: int
    valid_reports: int
    invalid_reports: int
    uncertain_reports: int
    duplicate_reports: int
    false_positive_reports: int
    average_confidence: float
    average_processing_time: float
    total_cost: float
    average_cost_per_report: float
    
    # Severity distribution
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    
    # Vulnerability type distribution
    vulnerability_distribution: Dict[str, int] = Field(default_factory=dict)
    
    # Verdict trend (time series)
    verdict_trend: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Top researchers
    top_researchers: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Processing metrics
    processing_metrics: Dict[str, Any] = Field(default_factory=dict)


class IntegrationStatus(BaseModel):
    """Integration health status."""
    integration_name: str
    integration_type: str
    status: IntegrationStatusEnum
    enabled: bool
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    success_rate: float = 0.0
    average_response_time: Optional[float] = None
    error_message: Optional[str] = None


class WebhookSummary(BaseModel):
    """Webhook configuration summary."""
    webhook_id: str
    url: str
    events: List[str]
    status: str
    description: Optional[str] = None
    created_at: datetime
    last_triggered: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    success_rate: float = 0.0


class DashboardStats(BaseModel):
    """Real-time dashboard statistics."""
    total_reports: int
    reports_today: int
    reports_this_week: int
    reports_this_month: int
    
    valid_count: int
    invalid_count: int
    uncertain_count: int
    
    average_confidence: float
    average_processing_time: float
    
    total_cost: float
    cost_today: float
    
    active_integrations: int
    healthy_integrations: int
    
    active_webhooks: int
    
    system_uptime: float
    api_requests_today: int


class ReportListRequest(BaseModel):
    """Request for listing reports."""
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
    verdict: Optional[str] = None
    severity: Optional[str] = None
    vulnerability_type: Optional[str] = None
    researcher: Optional[str] = None
    status: Optional[ReportStatus] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    search_query: Optional[str] = None
    sort_by: str = "submitted_at"
    sort_order: str = "desc"


class ReportListResponse(BaseModel):
    """Response for listing reports."""
    reports: List[ReportSummary]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool


class AnalyticsRequest(BaseModel):
    """Request for analytics data."""
    time_range: TimeRange = TimeRange.WEEK
    group_by: Optional[str] = None  # hour, day, week, month
    include_trends: bool = True
    include_distribution: bool = True
    include_researchers: bool = True


class BatchJobSummary(BaseModel):
    """Summary of a batch processing job."""
    job_id: str
    status: str
    total_reports: int
    processed: int
    failed: int
    progress: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    processing_time: Optional[float] = None
    results_url: Optional[str] = None


class SystemHealth(BaseModel):
    """System health status."""
    status: str  # healthy, degraded, down
    uptime: float
    version: str
    
    # Component health
    database: Dict[str, Any]
    ai_provider: Dict[str, Any]
    integrations: Dict[str, Any]
    webhooks: Dict[str, Any]
    
    # Resource usage
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    
    # Performance metrics
    average_response_time: float
    requests_per_minute: float
    error_rate: float


class NotificationSettings(BaseModel):
    """User notification preferences."""
    email_enabled: bool = True
    slack_enabled: bool = False
    webhook_enabled: bool = False
    
    notify_on_valid: bool = True
    notify_on_invalid: bool = False
    notify_on_uncertain: bool = True
    notify_on_critical: bool = True
    notify_on_high: bool = True
    notify_on_medium: bool = False
    notify_on_low: bool = False
    
    min_confidence: int = 70


class DashboardUser(BaseModel):
    """Dashboard user information."""
    user_id: str
    username: str
    email: str
    role: str  # admin, analyst, viewer
    created_at: datetime
    last_login: Optional[datetime] = None
    notification_settings: NotificationSettings = Field(default_factory=NotificationSettings)

