"""
Report generation engine with multiple format support.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

from bountybot.reporting.models import (
    ReportConfig,
    ReportFormat,
    ReportType,
    ReportPeriod,
    ReportMetrics,
    ExecutiveSummary,
    ROIMetrics,
    TrendData,
)

logger = logging.getLogger(__name__)


class BaseReportGenerator(ABC):
    """Base class for report generators."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize report generator."""
        self.config = config or {}
        self.template_dir = Path(self.config.get('template_dir', 'templates/reports'))
    
    @abstractmethod
    def generate(
        self,
        report_config: ReportConfig,
        metrics: ReportMetrics,
        executive_summary: Optional[ExecutiveSummary] = None,
        roi_metrics: Optional[ROIMetrics] = None,
        trends: Optional[List[TrendData]] = None,
        **kwargs
    ) -> bytes:
        """
        Generate report in specific format.
        
        Args:
            report_config: Report configuration
            metrics: Report metrics
            executive_summary: Executive summary (optional)
            roi_metrics: ROI metrics (optional)
            trends: Trend data (optional)
            **kwargs: Additional data
        
        Returns:
            Report content as bytes
        """
        pass
    
    def _format_date(self, dt: datetime) -> str:
        """Format datetime for display."""
        return dt.strftime("%B %d, %Y")
    
    def _format_number(self, value: float, decimals: int = 2) -> str:
        """Format number with commas."""
        return f"{value:,.{decimals}f}"
    
    def _format_percent(self, value: float, decimals: int = 1) -> str:
        """Format percentage."""
        return f"{value:.{decimals}f}%"
    
    def _format_currency(self, value: float) -> str:
        """Format currency."""
        return f"${value:,.2f}"
    
    def _calculate_trend_indicator(self, current: float, previous: float) -> str:
        """Calculate trend indicator (↑, ↓, →)."""
        if current > previous * 1.05:
            return "↑"
        elif current < previous * 0.95:
            return "↓"
        else:
            return "→"


class PDFReportGenerator(BaseReportGenerator):
    """Generate PDF reports."""
    
    def generate(
        self,
        report_config: ReportConfig,
        metrics: ReportMetrics,
        executive_summary: Optional[ExecutiveSummary] = None,
        roi_metrics: Optional[ROIMetrics] = None,
        trends: Optional[List[TrendData]] = None,
        **kwargs
    ) -> bytes:
        """Generate PDF report."""
        logger.info(f"Generating PDF report: {report_config.report_type.value}")
        
        # Build HTML content first
        html_content = self._build_html_content(
            report_config, metrics, executive_summary, roi_metrics, trends, **kwargs
        )
        
        # Convert HTML to PDF (would use library like weasyprint or pdfkit)
        # For now, return HTML as bytes (in production, convert to PDF)
        pdf_content = self._html_to_pdf(html_content)
        
        logger.info(f"PDF report generated: {len(pdf_content)} bytes")
        return pdf_content
    
    def _build_html_content(
        self,
        report_config: ReportConfig,
        metrics: ReportMetrics,
        executive_summary: Optional[ExecutiveSummary],
        roi_metrics: Optional[ROIMetrics],
        trends: Optional[List[TrendData]],
        **kwargs
    ) -> str:
        """Build HTML content for PDF."""
        html_parts = []
        
        # Header
        html_parts.append(self._build_header(report_config))
        
        # Executive Summary
        if executive_summary and report_config.include_executive_summary:
            html_parts.append(self._build_executive_summary_section(executive_summary))
        
        # Key Metrics
        html_parts.append(self._build_metrics_section(metrics))
        
        # ROI Section
        if roi_metrics and report_config.include_roi_metrics:
            html_parts.append(self._build_roi_section(roi_metrics))
        
        # Trends Section
        if trends and report_config.include_trend_analysis:
            html_parts.append(self._build_trends_section(trends))
        
        # Recommendations
        if executive_summary and report_config.include_recommendations:
            html_parts.append(self._build_recommendations_section(executive_summary))
        
        # Footer
        html_parts.append(self._build_footer(report_config))
        
        return "\n".join(html_parts)
    
    def _build_header(self, report_config: ReportConfig) -> str:
        """Build report header."""
        title = report_config.report_title or f"{report_config.report_type.value.replace('_', ' ').title()} Report"
        company = report_config.company_name or "BountyBot"
        
        return f"""
        <div class="header">
            <h1>{title}</h1>
            <h2>{company}</h2>
            <p>Generated: {self._format_date(datetime.utcnow())}</p>
            {f'<p>Period: {self._format_date(report_config.start_date)} - {self._format_date(report_config.end_date)}</p>' if report_config.start_date else ''}
        </div>
        """
    
    def _build_executive_summary_section(self, summary: ExecutiveSummary) -> str:
        """Build executive summary section."""
        return f"""
        <div class="section executive-summary">
            <h2>Executive Summary</h2>
            <p>{summary.summary_text}</p>
            
            <div class="key-metrics">
                <div class="metric">
                    <h3>{self._format_number(summary.total_reports, 0)}</h3>
                    <p>Total Reports</p>
                    <span class="trend">{self._format_percent(summary.reports_trend_percent)}</span>
                </div>
                <div class="metric">
                    <h3>{summary.critical_vulnerabilities}</h3>
                    <p>Critical Vulnerabilities</p>
                    <span class="trend">{self._format_percent(summary.critical_trend_percent)}</span>
                </div>
                <div class="metric">
                    <h3>{summary.vulnerabilities_fixed}</h3>
                    <p>Vulnerabilities Fixed</p>
                    <span class="trend">{self._format_percent(summary.fix_rate_trend_percent)}</span>
                </div>
                <div class="metric">
                    <h3>{self._format_number(summary.avg_fix_time_hours, 1)}h</h3>
                    <p>Avg Fix Time</p>
                    <span class="trend">{self._format_percent(summary.fix_time_trend_percent)}</span>
                </div>
            </div>
            
            <div class="risk-assessment">
                <h3>Overall Risk Score: {self._format_number(summary.overall_risk_score, 0)}/100</h3>
                <p>Trend: {summary.risk_trend.title()}</p>
            </div>
        </div>
        """
    
    def _build_metrics_section(self, metrics: ReportMetrics) -> str:
        """Build metrics section."""
        return f"""
        <div class="section metrics">
            <h2>Detailed Metrics</h2>
            
            <h3>Volume Metrics</h3>
            <table>
                <tr><td>Total Reports Processed</td><td>{metrics.total_reports_processed}</td></tr>
                <tr><td>Total Vulnerabilities Found</td><td>{metrics.total_vulnerabilities_found}</td></tr>
                <tr><td>Total Vulnerabilities Fixed</td><td>{metrics.total_vulnerabilities_fixed}</td></tr>
                <tr><td>False Positives</td><td>{metrics.total_false_positives}</td></tr>
            </table>
            
            <h3>Severity Breakdown</h3>
            <table>
                <tr><td>Critical</td><td>{metrics.critical_count}</td></tr>
                <tr><td>High</td><td>{metrics.high_count}</td></tr>
                <tr><td>Medium</td><td>{metrics.medium_count}</td></tr>
                <tr><td>Low</td><td>{metrics.low_count}</td></tr>
                <tr><td>Info</td><td>{metrics.info_count}</td></tr>
            </table>
            
            <h3>Time Metrics</h3>
            <table>
                <tr><td>Avg Time to Validate</td><td>{self._format_number(metrics.avg_time_to_validate, 1)}h</td></tr>
                <tr><td>Avg Time to Triage</td><td>{self._format_number(metrics.avg_time_to_triage, 1)}h</td></tr>
                <tr><td>Avg Time to Fix</td><td>{self._format_number(metrics.avg_time_to_fix, 1)}h</td></tr>
                <tr><td>Avg Time to Verify</td><td>{self._format_number(metrics.avg_time_to_verify, 1)}h</td></tr>
                <tr><td>Avg Total Lifecycle</td><td>{self._format_number(metrics.avg_total_lifecycle_time, 1)}h</td></tr>
            </table>
            
            <h3>Quality Metrics</h3>
            <table>
                <tr><td>Avg Confidence Score</td><td>{self._format_percent(metrics.avg_confidence_score * 100)}</td></tr>
                <tr><td>False Positive Rate</td><td>{self._format_percent(metrics.false_positive_rate * 100)}</td></tr>
                <tr><td>Fix Success Rate</td><td>{self._format_percent(metrics.fix_success_rate * 100)}</td></tr>
                <tr><td>Regression Rate</td><td>{self._format_percent(metrics.regression_rate * 100)}</td></tr>
            </table>
        </div>
        """
    
    def _build_roi_section(self, roi_metrics: ROIMetrics) -> str:
        """Build ROI section."""
        return f"""
        <div class="section roi">
            <h2>Return on Investment</h2>
            
            <div class="roi-summary">
                <div class="roi-metric">
                    <h3>{self._format_currency(roi_metrics.total_cost_saved)}</h3>
                    <p>Total Cost Saved</p>
                </div>
                <div class="roi-metric">
                    <h3>{self._format_percent(roi_metrics.roi_percent)}</h3>
                    <p>ROI</p>
                </div>
                <div class="roi-metric">
                    <h3>{self._format_number(roi_metrics.payback_period_months, 1)} months</h3>
                    <p>Payback Period</p>
                </div>
            </div>
            
            <h3>Time Savings</h3>
            <table>
                <tr><td>Manual Hours Saved</td><td>{self._format_number(roi_metrics.manual_hours_saved, 0)}h</td></tr>
                <tr><td>Automation Rate</td><td>{self._format_percent(roi_metrics.automation_rate * 100)}</td></tr>
                <tr><td>Avg Time Saved per Report</td><td>{self._format_number(roi_metrics.avg_time_saved_per_report, 1)}h</td></tr>
            </table>
            
            <h3>Cost Analysis</h3>
            <table>
                <tr><td>Labor Cost Saved</td><td>{self._format_currency(roi_metrics.labor_cost_saved)}</td></tr>
                <tr><td>Incident Cost Avoided</td><td>{self._format_currency(roi_metrics.incident_cost_avoided)}</td></tr>
                <tr><td>Total Investment</td><td>{self._format_currency(roi_metrics.total_investment)}</td></tr>
                <tr><td>Net Savings</td><td>{self._format_currency(roi_metrics.net_savings)}</td></tr>
            </table>
        </div>
        """
    
    def _build_trends_section(self, trends: List[TrendData]) -> str:
        """Build trends section."""
        trends_html = []
        
        for trend in trends[:5]:  # Top 5 trends
            trends_html.append(f"""
            <div class="trend">
                <h4>{trend.metric_name}</h4>
                <p>Trend: {trend.trend_direction.title()} (Strength: {self._format_percent(trend.trend_strength * 100)})</p>
                <p>Mean: {self._format_number(trend.mean)} | Median: {self._format_number(trend.median)}</p>
                {f'<p>Forecast: {self._format_number(trend.forecast_next_period)} (Confidence: {self._format_percent(trend.forecast_confidence * 100)})</p>' if trend.forecast_next_period else ''}
            </div>
            """)
        
        return f"""
        <div class="section trends">
            <h2>Trend Analysis</h2>
            {''.join(trends_html)}
        </div>
        """
    
    def _build_recommendations_section(self, summary: ExecutiveSummary) -> str:
        """Build recommendations section."""
        recommendations_html = "\n".join([f"<li>{rec}</li>" for rec in summary.key_recommendations])
        
        return f"""
        <div class="section recommendations">
            <h2>Key Recommendations</h2>
            <ul>
                {recommendations_html}
            </ul>
        </div>
        """
    
    def _build_footer(self, report_config: ReportConfig) -> str:
        """Build report footer."""
        return f"""
        <div class="footer">
            <p>Generated by BountyBot v2.12.0</p>
            <p>Report ID: {report_config.report_id}</p>
            <p>© {datetime.utcnow().year} {report_config.company_name or 'BountyBot'}</p>
        </div>
        """
    
    def _html_to_pdf(self, html_content: str) -> bytes:
        """Convert HTML to PDF (placeholder)."""
        # In production, use weasyprint, pdfkit, or similar
        # For now, return HTML as bytes
        return html_content.encode('utf-8')


class HTMLReportGenerator(BaseReportGenerator):
    """Generate HTML reports."""
    
    def generate(
        self,
        report_config: ReportConfig,
        metrics: ReportMetrics,
        executive_summary: Optional[ExecutiveSummary] = None,
        roi_metrics: Optional[ROIMetrics] = None,
        trends: Optional[List[TrendData]] = None,
        **kwargs
    ) -> bytes:
        """Generate HTML report."""
        logger.info(f"Generating HTML report: {report_config.report_type.value}")
        
        # Use PDF generator's HTML builder
        pdf_gen = PDFReportGenerator(self.config)
        html_content = pdf_gen._build_html_content(
            report_config, metrics, executive_summary, roi_metrics, trends, **kwargs
        )
        
        # Wrap in full HTML document
        full_html = self._wrap_html(html_content, report_config)
        
        logger.info(f"HTML report generated: {len(full_html)} bytes")
        return full_html.encode('utf-8')
    
    def _wrap_html(self, content: str, report_config: ReportConfig) -> str:
        """Wrap content in full HTML document."""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_config.report_title or 'BountyBot Report'}</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    {content}
</body>
</html>
        """
    
    def _get_css(self) -> str:
        """Get CSS styles for HTML report."""
        return """
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { text-align: center; margin-bottom: 40px; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .section { margin-bottom: 40px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
        h3 { color: #7f8c8d; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        table td { padding: 10px; border-bottom: 1px solid #eee; }
        table td:first-child { font-weight: bold; width: 40%; }
        .key-metrics { display: flex; justify-content: space-around; margin: 30px 0; }
        .metric { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }
        .metric h3 { font-size: 2em; margin: 0; color: #2c3e50; }
        .metric p { margin: 10px 0 0 0; color: #7f8c8d; }
        .trend { color: #27ae60; font-weight: bold; }
        .roi-summary { display: flex; justify-content: space-around; margin: 30px 0; }
        .roi-metric { text-align: center; padding: 20px; background: #e8f5e9; border-radius: 8px; }
        .footer { text-align: center; margin-top: 60px; padding-top: 20px; border-top: 2px solid #333; color: #7f8c8d; }
        """


class ExcelReportGenerator(BaseReportGenerator):
    """Generate Excel reports."""
    
    def generate(
        self,
        report_config: ReportConfig,
        metrics: ReportMetrics,
        executive_summary: Optional[ExecutiveSummary] = None,
        roi_metrics: Optional[ROIMetrics] = None,
        trends: Optional[List[TrendData]] = None,
        **kwargs
    ) -> bytes:
        """Generate Excel report."""
        logger.info(f"Generating Excel report: {report_config.report_type.value}")
        
        # In production, use openpyxl or xlsxwriter
        # For now, generate CSV-like content
        csv_content = self._build_csv_content(
            report_config, metrics, executive_summary, roi_metrics, trends
        )
        
        logger.info(f"Excel report generated: {len(csv_content)} bytes")
        return csv_content.encode('utf-8')
    
    def _build_csv_content(
        self,
        report_config: ReportConfig,
        metrics: ReportMetrics,
        executive_summary: Optional[ExecutiveSummary],
        roi_metrics: Optional[ROIMetrics],
        trends: Optional[List[TrendData]]
    ) -> str:
        """Build CSV content."""
        lines = []
        
        # Header
        lines.append(f"BountyBot Report - {report_config.report_type.value}")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append("")
        
        # Metrics
        lines.append("Metric,Value")
        lines.append(f"Total Reports,{metrics.total_reports_processed}")
        lines.append(f"Total Vulnerabilities,{metrics.total_vulnerabilities_found}")
        lines.append(f"Vulnerabilities Fixed,{metrics.total_vulnerabilities_fixed}")
        lines.append(f"Critical Count,{metrics.critical_count}")
        lines.append(f"High Count,{metrics.high_count}")
        lines.append(f"Avg Time to Fix (hours),{metrics.avg_time_to_fix}")
        lines.append(f"Fix Success Rate,{metrics.fix_success_rate}")
        
        if roi_metrics:
            lines.append("")
            lines.append("ROI Metrics")
            lines.append(f"Total Cost Saved,{roi_metrics.total_cost_saved}")
            lines.append(f"ROI Percent,{roi_metrics.roi_percent}")
            lines.append(f"Manual Hours Saved,{roi_metrics.manual_hours_saved}")
        
        return "\n".join(lines)


class ReportGenerator:
    """Main report generator that delegates to format-specific generators."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize report generator."""
        self.config = config or {}
        self.generators = {
            ReportFormat.PDF: PDFReportGenerator(config),
            ReportFormat.HTML: HTMLReportGenerator(config),
            ReportFormat.EXCEL: ExcelReportGenerator(config),
        }
    
    def generate_report(
        self,
        report_config: ReportConfig,
        metrics: ReportMetrics,
        executive_summary: Optional[ExecutiveSummary] = None,
        roi_metrics: Optional[ROIMetrics] = None,
        trends: Optional[List[TrendData]] = None,
        **kwargs
    ) -> bytes:
        """
        Generate report in specified format.
        
        Args:
            report_config: Report configuration
            metrics: Report metrics
            executive_summary: Executive summary (optional)
            roi_metrics: ROI metrics (optional)
            trends: Trend data (optional)
            **kwargs: Additional data
        
        Returns:
            Report content as bytes
        """
        generator = self.generators.get(report_config.report_format)
        if not generator:
            raise ValueError(f"Unsupported report format: {report_config.report_format}")
        
        return generator.generate(
            report_config, metrics, executive_summary, roi_metrics, trends, **kwargs
        )

