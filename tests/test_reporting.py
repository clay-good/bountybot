"""
Tests for reporting and analytics module.
"""

import pytest
from datetime import datetime, timedelta
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
    DashboardWidget,
    WidgetType,
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
from bountybot.reporting.dashboard_manager import DashboardManager


class TestReportModels:
    """Test report data models."""
    
    def test_report_config_creation(self):
        """Test report config creation."""
        config = ReportConfig(
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.PDF,
            period=ReportPeriod.MONTHLY
        )
        
        assert config.report_type == ReportType.EXECUTIVE_SUMMARY
        assert config.report_format == ReportFormat.PDF
        assert config.period == ReportPeriod.MONTHLY
        assert config.report_id is not None
    
    def test_report_metrics_creation(self):
        """Test report metrics creation."""
        metrics = ReportMetrics(
            total_reports_processed=100,
            total_vulnerabilities_found=50,
            critical_count=5,
            high_count=15,
            avg_time_to_fix=48.5
        )
        
        assert metrics.total_reports_processed == 100
        assert metrics.total_vulnerabilities_found == 50
        assert metrics.critical_count == 5
        assert metrics.avg_time_to_fix == 48.5
    
    def test_executive_summary_creation(self):
        """Test executive summary creation."""
        summary = ExecutiveSummary(
            period_start=datetime(2024, 1, 1),
            period_end=datetime(2024, 1, 31),
            total_reports=100,
            critical_vulnerabilities=5,
            vulnerabilities_fixed=45,
            avg_fix_time_hours=48.5
        )
        
        assert summary.total_reports == 100
        assert summary.critical_vulnerabilities == 5
        assert summary.vulnerabilities_fixed == 45
    
    def test_roi_metrics_creation(self):
        """Test ROI metrics creation."""
        roi = ROIMetrics(
            manual_hours_saved=250.0,
            automation_rate=0.85,
            total_cost_saved=25000.0,
            total_investment=5000.0,
            roi_percent=400.0
        )
        
        assert roi.manual_hours_saved == 250.0
        assert roi.automation_rate == 0.85
        assert roi.roi_percent == 400.0


class TestReportGenerator:
    """Test report generation."""
    
    def test_pdf_generator_creation(self):
        """Test PDF generator creation."""
        generator = PDFReportGenerator()
        assert generator is not None
    
    def test_html_generator_creation(self):
        """Test HTML generator creation."""
        generator = HTMLReportGenerator()
        assert generator is not None
    
    def test_excel_generator_creation(self):
        """Test Excel generator creation."""
        generator = ExcelReportGenerator()
        assert generator is not None
    
    def test_report_generator_creation(self):
        """Test main report generator creation."""
        generator = ReportGenerator()
        assert generator is not None
        assert ReportFormat.PDF in generator.generators
        assert ReportFormat.HTML in generator.generators
        assert ReportFormat.EXCEL in generator.generators
    
    def test_generate_pdf_report(self):
        """Test PDF report generation."""
        generator = ReportGenerator()
        
        config = ReportConfig(
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.PDF
        )
        
        metrics = ReportMetrics(
            total_reports_processed=100,
            total_vulnerabilities_found=50,
            critical_count=5
        )
        
        report_bytes = generator.generate_report(config, metrics)
        
        assert report_bytes is not None
        assert len(report_bytes) > 0
    
    def test_generate_html_report(self):
        """Test HTML report generation."""
        generator = ReportGenerator()
        
        config = ReportConfig(
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.HTML
        )
        
        metrics = ReportMetrics(
            total_reports_processed=100,
            total_vulnerabilities_found=50,
            critical_count=5
        )
        
        report_bytes = generator.generate_report(config, metrics)
        
        assert report_bytes is not None
        assert len(report_bytes) > 0
        assert b'<!DOCTYPE html>' in report_bytes
    
    def test_generate_excel_report(self):
        """Test Excel report generation."""
        generator = ReportGenerator()
        
        config = ReportConfig(
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.EXCEL
        )
        
        metrics = ReportMetrics(
            total_reports_processed=100,
            total_vulnerabilities_found=50,
            critical_count=5
        )
        
        report_bytes = generator.generate_report(config, metrics)
        
        assert report_bytes is not None
        assert len(report_bytes) > 0


class TestTrendAnalyzer:
    """Test trend analysis."""
    
    def test_trend_analyzer_creation(self):
        """Test trend analyzer creation."""
        analyzer = TrendAnalyzer()
        assert analyzer is not None
    
    def test_analyze_increasing_trend(self):
        """Test analyzing increasing trend."""
        analyzer = TrendAnalyzer()
        
        time_series = [
            {'timestamp': datetime(2024, 1, i).isoformat(), 'value': i * 10}
            for i in range(1, 11)
        ]
        
        trend = analyzer.analyze_trend("test_metric", time_series)
        
        assert trend.metric_name == "test_metric"
        assert trend.trend_direction == "increasing"
        assert trend.trend_strength > 0.9  # Strong trend
    
    def test_analyze_decreasing_trend(self):
        """Test analyzing decreasing trend."""
        analyzer = TrendAnalyzer()
        
        time_series = [
            {'timestamp': datetime(2024, 1, i).isoformat(), 'value': 100 - i * 10}
            for i in range(1, 11)
        ]
        
        trend = analyzer.analyze_trend("test_metric", time_series)
        
        assert trend.metric_name == "test_metric"
        assert trend.trend_direction == "decreasing"
        assert trend.trend_strength > 0.9
    
    def test_analyze_stable_trend(self):
        """Test analyzing stable trend."""
        analyzer = TrendAnalyzer()
        
        time_series = [
            {'timestamp': datetime(2024, 1, i).isoformat(), 'value': 50.0}
            for i in range(1, 11)
        ]
        
        trend = analyzer.analyze_trend("test_metric", time_series)
        
        assert trend.metric_name == "test_metric"
        assert trend.trend_direction == "stable"
    
    def test_detect_anomalies(self):
        """Test anomaly detection."""
        analyzer = TrendAnalyzer()
        
        # Normal values with one anomaly
        time_series = [
            {'timestamp': datetime(2024, 1, i).isoformat(), 'value': 50.0}
            for i in range(1, 10)
        ]
        time_series.append({'timestamp': datetime(2024, 1, 10).isoformat(), 'value': 200.0})
        
        trend = analyzer.analyze_trend("test_metric", time_series)
        
        assert len(trend.anomalies) > 0
        assert trend.anomalies[0]['value'] == 200.0


class TestROICalculator:
    """Test ROI calculation."""
    
    def test_roi_calculator_creation(self):
        """Test ROI calculator creation."""
        calculator = ROICalculator()
        assert calculator is not None
    
    def test_calculate_roi(self):
        """Test ROI calculation."""
        calculator = ROICalculator()
        
        metrics = ReportMetrics(
            total_reports_processed=100,
            total_vulnerabilities_fixed=50,
            total_ai_cost=500.0
        )
        
        roi = calculator.calculate_roi(
            metrics,
            period_months=1,
            manual_hours_per_report=2.5,
            automation_rate=0.85,
            incidents_prevented=2
        )
        
        assert roi.manual_hours_saved > 0
        assert roi.total_cost_saved > 0
        assert roi.roi_percent > 0
        assert roi.payback_period_months > 0
    
    def test_roi_with_high_automation(self):
        """Test ROI with high automation rate."""
        calculator = ROICalculator()
        
        metrics = ReportMetrics(
            total_reports_processed=1000,
            total_vulnerabilities_fixed=500,
            total_ai_cost=2000.0
        )
        
        roi = calculator.calculate_roi(
            metrics,
            period_months=3,
            manual_hours_per_report=3.0,
            automation_rate=0.95,
            incidents_prevented=5
        )
        
        assert roi.automation_rate == 0.95
        assert roi.roi_percent > 100  # Should have positive ROI
        assert roi.net_savings > 0


class TestBenchmarkAnalyzer:
    """Test benchmark analysis."""
    
    def test_benchmark_analyzer_creation(self):
        """Test benchmark analyzer creation."""
        analyzer = BenchmarkAnalyzer()
        assert analyzer is not None
    
    def test_benchmark_excellent_performance(self):
        """Test benchmarking excellent performance."""
        analyzer = BenchmarkAnalyzer()
        
        # Better than industry best
        benchmark = analyzer.benchmark_metric("avg_time_to_fix", 20.0)
        
        assert benchmark.metric_name == "avg_time_to_fix"
        assert benchmark.current_value == 20.0
        assert benchmark.performance_rating == "excellent"
    
    def test_benchmark_average_performance(self):
        """Test benchmarking average performance."""
        analyzer = BenchmarkAnalyzer()
        
        # Around industry average
        benchmark = analyzer.benchmark_metric("avg_time_to_fix", 72.0)
        
        assert benchmark.metric_name == "avg_time_to_fix"
        assert benchmark.performance_rating in ["good", "average"]
    
    def test_benchmark_poor_performance(self):
        """Test benchmarking poor performance."""
        analyzer = BenchmarkAnalyzer()
        
        # Much worse than average
        benchmark = analyzer.benchmark_metric("avg_time_to_fix", 200.0)
        
        assert benchmark.metric_name == "avg_time_to_fix"
        assert benchmark.performance_rating in ["below_average", "poor"]


class TestAnalyticsEngine:
    """Test analytics engine."""
    
    def test_analytics_engine_creation(self):
        """Test analytics engine creation."""
        engine = AnalyticsEngine()
        assert engine is not None
        assert engine.trend_analyzer is not None
        assert engine.roi_calculator is not None
        assert engine.benchmark_analyzer is not None
    
    def test_generate_executive_summary(self):
        """Test executive summary generation."""
        engine = AnalyticsEngine()
        
        current_metrics = ReportMetrics(
            total_reports_processed=100,
            critical_count=5,
            total_vulnerabilities_fixed=45,
            avg_time_to_fix=48.5,
            fix_success_rate=0.90
        )
        
        previous_metrics = ReportMetrics(
            total_reports_processed=80,
            critical_count=8,
            total_vulnerabilities_fixed=35,
            avg_time_to_fix=60.0,
            fix_success_rate=0.85
        )
        
        summary = engine.generate_executive_summary(
            current_metrics,
            previous_metrics,
            datetime(2024, 1, 1),
            datetime(2024, 1, 31)
        )
        
        assert summary.total_reports == 100
        assert summary.critical_vulnerabilities == 5
        assert summary.reports_trend_percent > 0  # Increased
        assert summary.critical_trend_percent < 0  # Decreased (good)
        assert len(summary.key_recommendations) > 0


class TestDashboardManager:
    """Test dashboard management."""
    
    def test_dashboard_manager_creation(self):
        """Test dashboard manager creation."""
        manager = DashboardManager()
        assert manager is not None
    
    def test_create_dashboard(self):
        """Test dashboard creation."""
        manager = DashboardManager()
        
        dashboard = manager.create_dashboard(
            name="Test Dashboard",
            description="Test description",
            owner="test_user"
        )
        
        assert dashboard.name == "Test Dashboard"
        assert dashboard.description == "Test description"
        assert dashboard.owner == "test_user"
        assert dashboard.dashboard_id is not None
    
    def test_add_widget(self):
        """Test adding widget to dashboard."""
        manager = DashboardManager()
        
        dashboard = manager.create_dashboard("Test Dashboard")
        
        widget = manager.add_widget(
            dashboard.dashboard_id,
            WidgetType.METRIC_CARD,
            "Total Reports",
            "total_reports",
            row=0,
            column=0
        )
        
        assert widget.title == "Total Reports"
        assert widget.widget_type == WidgetType.METRIC_CARD
        assert len(dashboard.widgets) == 1
    
    def test_get_dashboard(self):
        """Test getting dashboard."""
        manager = DashboardManager()
        
        dashboard = manager.create_dashboard("Test Dashboard")
        
        retrieved = manager.get_dashboard(dashboard.dashboard_id)
        
        assert retrieved is not None
        assert retrieved.dashboard_id == dashboard.dashboard_id
    
    def test_list_dashboards(self):
        """Test listing dashboards."""
        manager = DashboardManager()
        
        manager.create_dashboard("Dashboard 1", owner="user1")
        manager.create_dashboard("Dashboard 2", owner="user2")
        
        all_dashboards = manager.list_dashboards()
        assert len(all_dashboards) == 2
        
        user1_dashboards = manager.list_dashboards(owner="user1")
        assert len(user1_dashboards) == 1
    
    def test_create_executive_dashboard(self):
        """Test creating pre-configured executive dashboard."""
        manager = DashboardManager()
        
        dashboard = manager.create_executive_dashboard(owner="exec_user")
        
        assert dashboard.name == "Executive Dashboard"
        assert len(dashboard.widgets) > 0
        assert any(w.title == "Total Reports" for w in dashboard.widgets)
        assert any(w.title == "Critical Vulnerabilities" for w in dashboard.widgets)
    
    def test_create_operations_dashboard(self):
        """Test creating pre-configured operations dashboard."""
        manager = DashboardManager()
        
        dashboard = manager.create_operations_dashboard(owner="ops_user")
        
        assert dashboard.name == "Operations Dashboard"
        assert len(dashboard.widgets) > 0
    
    def test_export_import_dashboard(self):
        """Test exporting and importing dashboard configuration."""
        manager = DashboardManager()
        
        # Create dashboard
        dashboard = manager.create_dashboard("Test Dashboard")
        manager.add_widget(
            dashboard.dashboard_id,
            WidgetType.METRIC_CARD,
            "Test Widget",
            "test_metric"
        )
        
        # Export
        config = manager.export_dashboard_config(dashboard.dashboard_id)
        
        assert config['name'] == "Test Dashboard"
        assert len(config['widgets']) == 1
        
        # Import
        imported = manager.import_dashboard_config(config)
        
        assert imported.name == "Test Dashboard"
        assert len(imported.widgets) == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

