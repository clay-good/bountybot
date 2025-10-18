"""
Dashboard Module

Provides web-based UI for:
- Report management and tracking
- Real-time analytics and visualizations
- Integration status monitoring
- Webhook management
- Batch processing interface
- Historical trends and metrics

Built with FastAPI and modern web technologies.
"""

from .app import create_dashboard_app
from .models import (
    DashboardConfig,
    ReportSummary,
    AnalyticsSummary,
    IntegrationStatus
)

__all__ = [
    'create_dashboard_app',
    'DashboardConfig',
    'ReportSummary',
    'AnalyticsSummary',
    'IntegrationStatus'
]

