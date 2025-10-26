"""
Demo script for BountyBot Advanced Reporting & Analytics (v2.12.0).

Demonstrates:
1. Report generation (PDF, HTML, Excel)
2. Trend analysis and forecasting
3. ROI calculation
4. Benchmark analysis
5. Executive dashboards
6. Real-time analytics
"""

import asyncio
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

from bountybot.reporting.models import (
    ReportType,
    ReportFormat,
    ReportPeriod,
    ReportConfig,
    ReportMetrics,
    WidgetType,
)
from bountybot.reporting.report_generator import ReportGenerator
from bountybot.reporting.analytics_engine import (
    AnalyticsEngine,
    TrendAnalyzer,
    ROICalculator,
    BenchmarkAnalyzer,
)
from bountybot.reporting.dashboard_manager import DashboardManager

console = Console()


def print_header():
    """Print demo header."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]BountyBot v2.12.0[/bold cyan]\n"
        "[yellow]Advanced Reporting & Analytics Dashboard[/yellow]\n"
        "[dim]Transform security data into actionable insights[/dim]",
        border_style="cyan"
    ))
    console.print()


def demo_report_generation():
    """Demonstrate report generation."""
    console.print("[bold]1. Report Generation[/bold]")
    console.print()
    
    # Create sample metrics
    metrics = ReportMetrics(
        total_reports_processed=250,
        total_vulnerabilities_found=125,
        total_vulnerabilities_fixed=110,
        total_false_positives=15,
        critical_count=12,
        high_count=35,
        medium_count=48,
        low_count=25,
        info_count=5,
        open_count=15,
        in_progress_count=20,
        fixed_count=90,
        verified_count=85,
        closed_count=80,
        avg_time_to_validate=2.5,
        avg_time_to_triage=4.0,
        avg_time_to_fix=42.0,
        avg_time_to_verify=6.0,
        avg_total_lifecycle_time=54.5,
        avg_confidence_score=0.92,
        false_positive_rate=0.12,
        fix_success_rate=0.88,
        regression_rate=0.03,
        avg_validation_time_seconds=45.0,
        total_validations=250,
        successful_validations=245,
        failed_validations=5,
        total_ai_cost=1250.50,
        avg_cost_per_validation=5.00,
        total_tokens_used=2500000
    )
    
    # Create report generator
    generator = ReportGenerator()
    
    # Generate reports in different formats
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Generating reports...", total=3)
        
        # PDF Report
        pdf_config = ReportConfig(
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.PDF,
            period=ReportPeriod.MONTHLY,
            company_name="Acme Corp",
            report_title="Monthly Security Report"
        )
        pdf_report = generator.generate_report(pdf_config, metrics)
        progress.advance(task)
        
        # HTML Report
        html_config = ReportConfig(
            report_type=ReportType.DETAILED_ANALYSIS,
            report_format=ReportFormat.HTML,
            period=ReportPeriod.MONTHLY
        )
        html_report = generator.generate_report(html_config, metrics)
        progress.advance(task)
        
        # Excel Report
        excel_config = ReportConfig(
            report_type=ReportType.ROI_REPORT,
            report_format=ReportFormat.EXCEL,
            period=ReportPeriod.QUARTERLY
        )
        excel_report = generator.generate_report(excel_config, metrics)
        progress.advance(task)
    
    # Display results
    table = Table(title="Generated Reports", box=box.ROUNDED)
    table.add_column("Format", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Size", style="yellow", justify="right")
    
    table.add_row("PDF", "Executive Summary", f"{len(pdf_report):,} bytes")
    table.add_row("HTML", "Detailed Analysis", f"{len(html_report):,} bytes")
    table.add_row("Excel", "ROI Report", f"{len(excel_report):,} bytes")
    
    console.print(table)
    console.print()


def demo_trend_analysis():
    """Demonstrate trend analysis."""
    console.print("[bold]2. Trend Analysis & Forecasting[/bold]")
    console.print()
    
    # Create sample time series data
    time_series = [
        {'timestamp': (datetime.utcnow() - timedelta(days=30-i)).isoformat(), 'value': 40 + i * 2 + (i % 3) * 5}
        for i in range(30)
    ]
    
    # Analyze trend
    analyzer = TrendAnalyzer()
    trend = analyzer.analyze_trend("vulnerabilities_fixed_per_day", time_series)
    
    # Display results
    table = Table(title="Trend Analysis: Vulnerabilities Fixed Per Day", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="yellow")
    
    table.add_row("Trend Direction", f"[green]{trend.trend_direction.upper()}[/green]")
    table.add_row("Trend Strength", f"{trend.trend_strength:.1%}")
    table.add_row("Mean", f"{trend.mean:.2f}")
    table.add_row("Median", f"{trend.median:.2f}")
    table.add_row("Std Dev", f"{trend.std_dev:.2f}")
    table.add_row("Min", f"{trend.min_value:.2f}")
    table.add_row("Max", f"{trend.max_value:.2f}")
    
    if trend.forecast_next_period:
        table.add_row(
            "Forecast (Next Period)",
            f"[bold]{trend.forecast_next_period:.2f}[/bold] (Confidence: {trend.forecast_confidence:.1%})"
        )
    
    if trend.anomalies:
        table.add_row("Anomalies Detected", f"[red]{len(trend.anomalies)}[/red]")
    
    console.print(table)
    console.print()


def demo_roi_calculation():
    """Demonstrate ROI calculation."""
    console.print("[bold]3. Return on Investment (ROI) Analysis[/bold]")
    console.print()
    
    # Create sample metrics
    metrics = ReportMetrics(
        total_reports_processed=1000,
        total_vulnerabilities_fixed=450,
        total_ai_cost=5000.0
    )
    
    # Calculate ROI
    calculator = ROICalculator()
    roi = calculator.calculate_roi(
        metrics,
        period_months=3,
        manual_hours_per_report=2.5,
        automation_rate=0.85,
        incidents_prevented=5
    )
    
    # Display results
    console.print(Panel(
        f"[bold green]${roi.net_savings:,.2f}[/bold green] Net Savings\n"
        f"[bold cyan]{roi.roi_percent:.1f}%[/bold cyan] ROI\n"
        f"[bold yellow]{roi.payback_period_months:.1f} months[/bold yellow] Payback Period",
        title="[bold]ROI Summary[/bold]",
        border_style="green"
    ))
    console.print()
    
    # Detailed breakdown
    table = Table(title="ROI Breakdown", box=box.ROUNDED)
    table.add_column("Category", style="cyan")
    table.add_column("Metric", style="magenta")
    table.add_column("Value", style="yellow", justify="right")
    
    table.add_row("Time Savings", "Manual Hours Saved", f"{roi.manual_hours_saved:,.0f}h")
    table.add_row("", "Automation Rate", f"{roi.automation_rate:.1%}")
    table.add_row("", "Avg Time Saved/Report", f"{roi.avg_time_saved_per_report:.1f}h")
    
    table.add_row("Cost Savings", "Labor Cost Saved", f"${roi.labor_cost_saved:,.2f}")
    table.add_row("", "Incident Cost Avoided", f"${roi.incident_cost_avoided:,.2f}")
    table.add_row("", "Total Cost Saved", f"[bold]${roi.total_cost_saved:,.2f}[/bold]")
    
    table.add_row("Investment", "BountyBot Cost", f"${roi.bountybot_cost:,.2f}")
    table.add_row("", "AI API Cost", f"${roi.ai_api_cost:,.2f}")
    table.add_row("", "Infrastructure Cost", f"${roi.infrastructure_cost:,.2f}")
    table.add_row("", "Total Investment", f"[bold]${roi.total_investment:,.2f}[/bold]")
    
    table.add_row("Productivity", "Reports/Day", f"{roi.reports_processed_per_day:.1f}")
    table.add_row("", "Vulnerabilities Fixed/Day", f"{roi.vulnerabilities_fixed_per_day:.1f}")
    table.add_row("", "Productivity Improvement", f"{roi.productivity_improvement_percent:.1f}%")
    
    console.print(table)
    console.print()


def demo_benchmark_analysis():
    """Demonstrate benchmark analysis."""
    console.print("[bold]4. Industry Benchmark Comparison[/bold]")
    console.print()
    
    # Analyze multiple metrics
    analyzer = BenchmarkAnalyzer()
    
    benchmarks = [
        analyzer.benchmark_metric("avg_time_to_fix", 42.0),
        analyzer.benchmark_metric("fix_success_rate", 0.88),
        analyzer.benchmark_metric("false_positive_rate", 0.12),
        analyzer.benchmark_metric("automation_rate", 0.85)
    ]
    
    # Display results
    table = Table(title="Performance vs Industry Benchmarks", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Current", style="yellow")
    table.add_column("Industry Avg", style="magenta")
    table.add_column("Industry Best", style="green")
    table.add_column("Percentile", style="blue", justify="right")
    table.add_column("Rating", style="bold")
    
    for benchmark in benchmarks:
        # Format values based on metric type
        if "rate" in benchmark.metric_name:
            current = f"{benchmark.current_value:.1%}"
            avg = f"{benchmark.industry_average:.1%}" if benchmark.industry_average else "N/A"
            best = f"{benchmark.industry_best:.1%}" if benchmark.industry_best else "N/A"
        else:
            current = f"{benchmark.current_value:.1f}h"
            avg = f"{benchmark.industry_average:.1f}h" if benchmark.industry_average else "N/A"
            best = f"{benchmark.industry_best:.1f}h" if benchmark.industry_best else "N/A"
        
        # Color code rating
        rating_colors = {
            "excellent": "green",
            "good": "cyan",
            "average": "yellow",
            "below_average": "orange",
            "poor": "red"
        }
        rating_color = rating_colors.get(benchmark.performance_rating, "white")
        rating = f"[{rating_color}]{benchmark.performance_rating.upper()}[/{rating_color}]"
        
        table.add_row(
            benchmark.metric_name.replace("_", " ").title(),
            current,
            avg,
            best,
            f"{benchmark.industry_percentile:.0f}th" if benchmark.industry_percentile else "N/A",
            rating
        )
    
    console.print(table)
    console.print()


def demo_executive_dashboard():
    """Demonstrate executive dashboard."""
    console.print("[bold]5. Executive Dashboard[/bold]")
    console.print()
    
    # Create dashboard manager
    manager = DashboardManager()
    
    # Create executive dashboard
    dashboard = manager.create_executive_dashboard(owner="ceo@acme.com")
    
    console.print(f"[cyan]Dashboard Created:[/cyan] {dashboard.name}")
    console.print(f"[dim]Dashboard ID: {dashboard.dashboard_id}[/dim]")
    console.print()
    
    # Display widgets
    table = Table(title="Dashboard Widgets", box=box.ROUNDED)
    table.add_column("Position", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Title", style="yellow")
    table.add_column("Data Source", style="green")
    
    for widget in dashboard.widgets:
        position = f"Row {widget.row}, Col {widget.column}"
        if widget.width > 1 or widget.height > 1:
            position += f" ({widget.width}x{widget.height})"
        
        table.add_row(
            position,
            widget.widget_type.value.replace("_", " ").title(),
            widget.title,
            widget.data_source
        )
    
    console.print(table)
    console.print()
    
    # Show sample widget data
    console.print("[bold]Sample Widget Data:[/bold]")
    console.print()
    
    metrics = ReportMetrics(
        total_reports_processed=250,
        critical_count=12,
        avg_time_to_fix=42.0,
        fix_success_rate=0.88
    )
    
    for widget in dashboard.widgets[:3]:  # Show first 3 widgets
        data = manager.get_widget_data(widget, metrics)
        console.print(f"[cyan]{widget.title}:[/cyan] {data.get('value', 'N/A')}")
    
    console.print()


def demo_analytics_engine():
    """Demonstrate analytics engine."""
    console.print("[bold]6. Comprehensive Analytics Engine[/bold]")
    console.print()
    
    # Create analytics engine
    engine = AnalyticsEngine()
    
    # Create sample metrics
    current_metrics = ReportMetrics(
        total_reports_processed=250,
        critical_count=12,
        total_vulnerabilities_fixed=110,
        avg_time_to_fix=42.0,
        fix_success_rate=0.88
    )
    
    previous_metrics = ReportMetrics(
        total_reports_processed=200,
        critical_count=18,
        total_vulnerabilities_fixed=85,
        avg_time_to_fix=58.0,
        fix_success_rate=0.82
    )
    
    # Generate executive summary
    summary = engine.generate_executive_summary(
        current_metrics,
        previous_metrics,
        datetime.utcnow() - timedelta(days=30),
        datetime.utcnow()
    )
    
    # Display summary
    console.print(Panel(
        summary.summary_text,
        title="[bold]Executive Summary[/bold]",
        border_style="cyan"
    ))
    console.print()
    
    # Display trends
    table = Table(title="Period-over-Period Trends", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Change", style="yellow", justify="right")
    table.add_column("Trend", style="green")
    
    trends = [
        ("Total Reports", summary.reports_trend_percent, "↑" if summary.reports_trend_percent > 0 else "↓"),
        ("Critical Vulnerabilities", summary.critical_trend_percent, "↓" if summary.critical_trend_percent < 0 else "↑"),
        ("Fix Time", summary.fix_time_trend_percent, "↑" if summary.fix_time_trend_percent > 0 else "↓"),
        ("Fix Rate", summary.fix_rate_trend_percent, "↑" if summary.fix_rate_trend_percent > 0 else "↓"),
    ]
    
    for metric, change, indicator in trends:
        color = "green" if (metric == "Critical Vulnerabilities" and change < 0) or (metric != "Critical Vulnerabilities" and change > 0) else "red"
        table.add_row(
            metric,
            f"[{color}]{change:+.1f}%[/{color}]",
            f"[{color}]{indicator}[/{color}]"
        )
    
    console.print(table)
    console.print()
    
    # Display risk assessment
    console.print(Panel(
        f"[bold]Overall Risk Score:[/bold] {summary.overall_risk_score:.0f}/100\n"
        f"[bold]Risk Trend:[/bold] {summary.risk_trend.upper()}",
        title="[bold]Risk Assessment[/bold]",
        border_style="yellow"
    ))
    console.print()
    
    # Display recommendations
    console.print("[bold]Key Recommendations:[/bold]")
    for i, rec in enumerate(summary.key_recommendations, 1):
        console.print(f"  {i}. {rec}")
    console.print()


def main():
    """Run all demos."""
    print_header()
    
    demo_report_generation()
    demo_trend_analysis()
    demo_roi_calculation()
    demo_benchmark_analysis()
    demo_executive_dashboard()
    demo_analytics_engine()
    
    console.print(Panel.fit(
        "[bold green]✓ Demo Complete![/bold green]\n"
        "[yellow]BountyBot v2.12.0 - Advanced Reporting & Analytics[/yellow]\n"
        "[dim]Transform security data into actionable insights for executives and stakeholders[/dim]",
        border_style="green"
    ))


if __name__ == '__main__':
    main()

