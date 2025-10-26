"""
Dashboard management for real-time analytics and visualization.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from uuid import uuid4

from bountybot.reporting.models import (
    DashboardConfig,
    DashboardWidget,
    WidgetType,
    AnalyticsQuery,
    ReportMetrics,
)

logger = logging.getLogger(__name__)


class DashboardManager:
    """Manage dashboards and widgets."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize dashboard manager."""
        self.config = config or {}
        self.dashboards: Dict[str, DashboardConfig] = {}
        self.widget_data_cache: Dict[str, Any] = {}
        self.cache_ttl_seconds = self.config.get('cache_ttl_seconds', 60)
    
    def create_dashboard(
        self,
        name: str,
        description: str = "",
        layout: str = "grid",
        columns: int = 3,
        owner: Optional[str] = None
    ) -> DashboardConfig:
        """
        Create a new dashboard.
        
        Args:
            name: Dashboard name
            description: Dashboard description
            layout: Layout type (grid, flex, custom)
            columns: Number of columns
            owner: Dashboard owner
        
        Returns:
            Dashboard configuration
        """
        logger.info(f"Creating dashboard: {name}")
        
        dashboard = DashboardConfig(
            name=name,
            description=description,
            layout=layout,
            columns=columns,
            owner=owner
        )
        
        self.dashboards[dashboard.dashboard_id] = dashboard
        
        logger.info(f"Dashboard created: {dashboard.dashboard_id}")
        return dashboard
    
    def add_widget(
        self,
        dashboard_id: str,
        widget_type: WidgetType,
        title: str,
        data_source: str,
        row: int = 0,
        column: int = 0,
        width: int = 1,
        height: int = 1,
        **options
    ) -> DashboardWidget:
        """
        Add widget to dashboard.
        
        Args:
            dashboard_id: Dashboard ID
            widget_type: Widget type
            title: Widget title
            data_source: Data source (metric name or query)
            row: Row position
            column: Column position
            width: Widget width
            height: Widget height
            **options: Additional widget options
        
        Returns:
            Dashboard widget
        """
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            raise ValueError(f"Dashboard not found: {dashboard_id}")
        
        logger.info(f"Adding widget to dashboard {dashboard_id}: {title}")
        
        widget = DashboardWidget(
            widget_type=widget_type,
            title=title,
            row=row,
            column=column,
            width=width,
            height=height,
            data_source=data_source,
            query_params=options.get('query_params', {}),
            chart_options=options.get('chart_options', {}),
            color_scheme=options.get('color_scheme', 'default'),
            show_legend=options.get('show_legend', True),
            show_labels=options.get('show_labels', True),
            warning_threshold=options.get('warning_threshold'),
            critical_threshold=options.get('critical_threshold'),
            refresh_interval_seconds=options.get('refresh_interval_seconds')
        )
        
        dashboard.widgets.append(widget)
        dashboard.updated_at = datetime.utcnow()
        
        logger.info(f"Widget added: {widget.widget_id}")
        return widget
    
    def get_dashboard(self, dashboard_id: str) -> Optional[DashboardConfig]:
        """Get dashboard by ID."""
        return self.dashboards.get(dashboard_id)
    
    def list_dashboards(self, owner: Optional[str] = None) -> List[DashboardConfig]:
        """List dashboards, optionally filtered by owner."""
        if owner:
            return [d for d in self.dashboards.values() if d.owner == owner or d.is_public]
        return list(self.dashboards.values())
    
    def update_dashboard(
        self,
        dashboard_id: str,
        **updates
    ) -> DashboardConfig:
        """Update dashboard configuration."""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            raise ValueError(f"Dashboard not found: {dashboard_id}")
        
        logger.info(f"Updating dashboard: {dashboard_id}")
        
        for key, value in updates.items():
            if hasattr(dashboard, key):
                setattr(dashboard, key, value)
        
        dashboard.updated_at = datetime.utcnow()
        
        return dashboard
    
    def delete_dashboard(self, dashboard_id: str) -> bool:
        """Delete dashboard."""
        if dashboard_id in self.dashboards:
            logger.info(f"Deleting dashboard: {dashboard_id}")
            del self.dashboards[dashboard_id]
            return True
        return False
    
    def get_widget_data(
        self,
        widget: DashboardWidget,
        metrics: Optional[ReportMetrics] = None
    ) -> Dict[str, Any]:
        """
        Get data for widget.
        
        Args:
            widget: Dashboard widget
            metrics: Report metrics (optional, will query if not provided)
        
        Returns:
            Widget data
        """
        cache_key = f"{widget.widget_id}:{widget.data_source}"
        
        # Check cache
        if cache_key in self.widget_data_cache:
            cached_data, cached_time = self.widget_data_cache[cache_key]
            if (datetime.utcnow() - cached_time).total_seconds() < self.cache_ttl_seconds:
                logger.debug(f"Using cached data for widget: {widget.widget_id}")
                return cached_data
        
        # Fetch fresh data
        logger.debug(f"Fetching fresh data for widget: {widget.widget_id}")
        data = self._fetch_widget_data(widget, metrics)
        
        # Cache data
        self.widget_data_cache[cache_key] = (data, datetime.utcnow())
        
        return data
    
    def _fetch_widget_data(
        self,
        widget: DashboardWidget,
        metrics: Optional[ReportMetrics]
    ) -> Dict[str, Any]:
        """Fetch widget data from data source."""
        # In production, this would query the database or metrics system
        # For now, use provided metrics or generate sample data
        
        if metrics:
            return self._extract_metric_data(widget.data_source, metrics)
        else:
            return self._generate_sample_data(widget)
    
    def _extract_metric_data(
        self,
        data_source: str,
        metrics: ReportMetrics
    ) -> Dict[str, Any]:
        """Extract metric data from ReportMetrics."""
        metric_map = {
            'total_reports': metrics.total_reports_processed,
            'total_vulnerabilities': metrics.total_vulnerabilities_found,
            'critical_count': metrics.critical_count,
            'high_count': metrics.high_count,
            'medium_count': metrics.medium_count,
            'low_count': metrics.low_count,
            'avg_time_to_fix': metrics.avg_time_to_fix,
            'fix_success_rate': metrics.fix_success_rate * 100,
            'false_positive_rate': metrics.false_positive_rate * 100,
            'regression_rate': metrics.regression_rate * 100,
        }
        
        value = metric_map.get(data_source, 0)
        
        return {
            'value': value,
            'timestamp': datetime.utcnow().isoformat(),
            'metric': data_source
        }
    
    def _generate_sample_data(self, widget: DashboardWidget) -> Dict[str, Any]:
        """Generate sample data for widget."""
        if widget.widget_type == WidgetType.METRIC_CARD:
            return {
                'value': 42,
                'change': 5.2,
                'trend': 'up'
            }
        elif widget.widget_type == WidgetType.LINE_CHART:
            return {
                'labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
                'datasets': [{
                    'label': widget.title,
                    'data': [10, 15, 12, 18, 20]
                }]
            }
        elif widget.widget_type == WidgetType.PIE_CHART:
            return {
                'labels': ['Critical', 'High', 'Medium', 'Low'],
                'data': [5, 15, 30, 50]
            }
        elif widget.widget_type == WidgetType.BAR_CHART:
            return {
                'labels': ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                'datasets': [{
                    'label': widget.title,
                    'data': [25, 30, 28, 35]
                }]
            }
        else:
            return {'message': 'No data available'}
    
    def create_executive_dashboard(self, owner: Optional[str] = None) -> DashboardConfig:
        """Create pre-configured executive dashboard."""
        logger.info("Creating executive dashboard")
        
        dashboard = self.create_dashboard(
            name="Executive Dashboard",
            description="High-level security metrics for executives",
            layout="grid",
            columns=3,
            owner=owner
        )
        
        # Row 1: Key metrics
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.METRIC_CARD,
            "Total Reports",
            "total_reports",
            row=0, column=0
        )
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.METRIC_CARD,
            "Critical Vulnerabilities",
            "critical_count",
            row=0, column=1,
            critical_threshold=10
        )
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.METRIC_CARD,
            "Avg Fix Time (hours)",
            "avg_time_to_fix",
            row=0, column=2,
            warning_threshold=48,
            critical_threshold=72
        )
        
        # Row 2: Charts
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.LINE_CHART,
            "Vulnerability Trend",
            "vulnerability_trend",
            row=1, column=0, width=2
        )
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.PIE_CHART,
            "Severity Distribution",
            "severity_distribution",
            row=1, column=2
        )
        
        # Row 3: Performance metrics
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.GAUGE,
            "Fix Success Rate",
            "fix_success_rate",
            row=2, column=0
        )
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.GAUGE,
            "False Positive Rate",
            "false_positive_rate",
            row=2, column=1
        )
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.GAUGE,
            "Regression Rate",
            "regression_rate",
            row=2, column=2
        )
        
        logger.info(f"Executive dashboard created: {dashboard.dashboard_id}")
        return dashboard
    
    def create_operations_dashboard(self, owner: Optional[str] = None) -> DashboardConfig:
        """Create pre-configured operations dashboard."""
        logger.info("Creating operations dashboard")
        
        dashboard = self.create_dashboard(
            name="Operations Dashboard",
            description="Operational metrics for security teams",
            layout="grid",
            columns=3,
            owner=owner
        )
        
        # Row 1: Volume metrics
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.METRIC_CARD,
            "Reports Processed",
            "total_reports",
            row=0, column=0
        )
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.METRIC_CARD,
            "Vulnerabilities Found",
            "total_vulnerabilities",
            row=0, column=1
        )
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.METRIC_CARD,
            "Vulnerabilities Fixed",
            "vulnerabilities_fixed",
            row=0, column=2
        )
        
        # Row 2: Time metrics
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.BAR_CHART,
            "Time Metrics",
            "time_metrics",
            row=1, column=0, width=3
        )
        
        # Row 3: Status breakdown
        self.add_widget(
            dashboard.dashboard_id,
            WidgetType.TABLE,
            "Status Breakdown",
            "status_breakdown",
            row=2, column=0, width=3
        )
        
        logger.info(f"Operations dashboard created: {dashboard.dashboard_id}")
        return dashboard
    
    def export_dashboard_config(self, dashboard_id: str) -> Dict[str, Any]:
        """Export dashboard configuration as JSON."""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            raise ValueError(f"Dashboard not found: {dashboard_id}")
        
        return {
            'dashboard_id': dashboard.dashboard_id,
            'name': dashboard.name,
            'description': dashboard.description,
            'layout': dashboard.layout,
            'columns': dashboard.columns,
            'widgets': [
                {
                    'widget_id': w.widget_id,
                    'widget_type': w.widget_type.value,
                    'title': w.title,
                    'row': w.row,
                    'column': w.column,
                    'width': w.width,
                    'height': w.height,
                    'data_source': w.data_source,
                    'query_params': w.query_params,
                    'chart_options': w.chart_options,
                }
                for w in dashboard.widgets
            ],
            'auto_refresh': dashboard.auto_refresh,
            'refresh_interval_seconds': dashboard.refresh_interval_seconds,
            'created_at': dashboard.created_at.isoformat(),
            'updated_at': dashboard.updated_at.isoformat(),
        }
    
    def import_dashboard_config(self, config: Dict[str, Any]) -> DashboardConfig:
        """Import dashboard configuration from JSON."""
        logger.info(f"Importing dashboard: {config.get('name')}")
        
        dashboard = DashboardConfig(
            dashboard_id=config.get('dashboard_id', str(uuid4())),
            name=config['name'],
            description=config.get('description', ''),
            layout=config.get('layout', 'grid'),
            columns=config.get('columns', 3),
            auto_refresh=config.get('auto_refresh', True),
            refresh_interval_seconds=config.get('refresh_interval_seconds', 60)
        )
        
        # Import widgets
        for widget_config in config.get('widgets', []):
            widget = DashboardWidget(
                widget_id=widget_config.get('widget_id', str(uuid4())),
                widget_type=WidgetType(widget_config['widget_type']),
                title=widget_config['title'],
                row=widget_config['row'],
                column=widget_config['column'],
                width=widget_config.get('width', 1),
                height=widget_config.get('height', 1),
                data_source=widget_config['data_source'],
                query_params=widget_config.get('query_params', {}),
                chart_options=widget_config.get('chart_options', {})
            )
            dashboard.widgets.append(widget)
        
        self.dashboards[dashboard.dashboard_id] = dashboard
        
        logger.info(f"Dashboard imported: {dashboard.dashboard_id}")
        return dashboard

