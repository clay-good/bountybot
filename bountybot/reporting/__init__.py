"""
Advanced Reporting & Analytics Module

Provides comprehensive reporting, analytics, and dashboard capabilities:
- Executive dashboards with high-level metrics
- ROI calculation and cost-benefit analysis
- Trend analysis and forecasting
- Exportable reports (PDF, HTML, Excel)
- Real-time analytics with WebSocket support
- Comparative benchmarking
"""

from bountybot.reporting.models import (
    ReportType,
    ReportFormat,
    ReportPeriod,
    ReportConfig,
    ReportMetrics,
    ExecutiveSummary,
    ROIMetrics,
    TrendData,
    BenchmarkData,
    DashboardConfig,
    AnalyticsQuery,
)

from bountybot.reporting.report_generator import (
    ReportGenerator,
    PDFReportGenerator,
    HTMLReportGenerator,
    ExcelReportGenerator,
)

from bountybot.reporting.analytics_engine import (
    AnalyticsEngine,
    TrendAnalyzer,
    ROICalculator,
    BenchmarkAnalyzer,
)

from bountybot.reporting.dashboard_manager import (
    DashboardManager,
    DashboardWidget,
    WidgetType,
)

__all__ = [
    # Models
    'ReportType',
    'ReportFormat',
    'ReportPeriod',
    'ReportConfig',
    'ReportMetrics',
    'ExecutiveSummary',
    'ROIMetrics',
    'TrendData',
    'BenchmarkData',
    'DashboardConfig',
    'AnalyticsQuery',
    
    # Report Generation
    'ReportGenerator',
    'PDFReportGenerator',
    'HTMLReportGenerator',
    'ExcelReportGenerator',
    
    # Analytics
    'AnalyticsEngine',
    'TrendAnalyzer',
    'ROICalculator',
    'BenchmarkAnalyzer',
    
    # Dashboard
    'DashboardManager',
    'DashboardWidget',
    'WidgetType',
]

