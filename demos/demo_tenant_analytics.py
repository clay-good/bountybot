#!/usr/bin/env python3
"""
BountyBot v2.16.0 - Multi-Tenant Analytics Demo

Demonstrates:
- Usage tracking and aggregation
- Cross-tenant benchmarking
- Predictive analytics (usage forecasts, churn risk, cost forecasting)
- Tenant health scoring
- SaaS metrics calculation
- Comprehensive analytics dashboard
"""

import asyncio
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from bountybot.tenant_analytics import (
    TenantAnalyticsManager,
    UsageMetricType,
    AggregationPeriod,
    BenchmarkCategory,
    ChurnRiskLevel,
    HealthStatus,
)


console = Console()


def print_header(title: str):
    """Print a formatted header."""
    console.print(f"\n[bold cyan]{'=' * 80}[/bold cyan]")
    console.print(f"[bold cyan]{title.center(80)}[/bold cyan]")
    console.print(f"[bold cyan]{'=' * 80}[/bold cyan]\n")


def demo_usage_tracking():
    """Demonstrate usage tracking."""
    print_header("1. Usage Tracking & Aggregation")
    
    manager = TenantAnalyticsManager()
    
    console.print("[bold]Tracking usage events for multiple tenants...[/bold]\n")
    
    # Simulate usage for 3 tenants over 7 days
    tenants = ["acme-corp", "globex-inc", "initech-llc"]
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Tracking events...", total=None)
        
        for day in range(7):
            for tenant in tenants:
                # Different usage patterns
                if tenant == "acme-corp":
                    api_calls = 100 + (day * 10)  # Growing
                elif tenant == "globex-inc":
                    api_calls = 200 - (day * 5)  # Declining
                else:
                    api_calls = 150  # Stable
                
                for _ in range(api_calls):
                    manager.track_usage(tenant, UsageMetricType.API_CALLS, 1.0)
                
                # Track other metrics
                manager.track_usage(tenant, UsageMetricType.VALIDATIONS, day * 5)
                manager.track_usage(tenant, UsageMetricType.AI_TOKENS, 1000 * (day + 1))
    
    console.print("[green]✓[/green] Tracked usage events\n")
    
    # Show usage summary
    table = Table(title="Usage Summary (Last 7 Days)")
    table.add_column("Tenant", style="cyan")
    table.add_column("API Calls", justify="right")
    table.add_column("Validations", justify="right")
    table.add_column("AI Tokens", justify="right")
    
    for tenant in tenants:
        agg = manager.get_tenant_usage(tenant, AggregationPeriod.WEEKLY)
        
        api_calls = agg.metrics.get(UsageMetricType.API_CALLS)
        validations = agg.metrics.get(UsageMetricType.VALIDATIONS)
        ai_tokens = agg.metrics.get(UsageMetricType.AI_TOKENS)
        
        table.add_row(
            tenant,
            f"{int(api_calls.total) if api_calls else 0:,}",
            f"{int(validations.total) if validations else 0:,}",
            f"{int(ai_tokens.total) if ai_tokens else 0:,}",
        )
    
    console.print(table)
    
    return manager


def demo_benchmarking(manager: TenantAnalyticsManager):
    """Demonstrate cross-tenant benchmarking."""
    print_header("2. Cross-Tenant Benchmarking")
    
    console.print("[bold]Calculating benchmarks across all tenants...[/bold]\n")
    
    # Calculate benchmarks
    tenants = ["acme-corp", "globex-inc", "initech-llc"]
    tenant_values = {}
    
    for tenant in tenants:
        agg = manager.get_tenant_usage(tenant, AggregationPeriod.WEEKLY)
        api_calls = agg.metrics.get(UsageMetricType.API_CALLS)
        if api_calls:
            tenant_values[tenant] = api_calls.total
    
    benchmark = manager.calculate_benchmarks(
        metric_name="api_calls_per_week",
        category=BenchmarkCategory.USAGE,
        tenant_values=tenant_values,
        description="API calls per week",
    )
    
    console.print(f"[green]✓[/green] Calculated benchmark: {benchmark.name}\n")
    
    # Show benchmark statistics
    stats_table = Table(title="Benchmark Statistics")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", justify="right")
    
    stats_table.add_row("Mean", f"{benchmark.mean:,.0f}")
    stats_table.add_row("Median", f"{benchmark.median:,.0f}")
    stats_table.add_row("Std Dev", f"{benchmark.std_dev:,.0f}")
    stats_table.add_row("Min", f"{benchmark.min_value:,.0f}")
    stats_table.add_row("Max", f"{benchmark.max_value:,.0f}")
    stats_table.add_row("P50", f"{benchmark.p50:,.0f}")
    stats_table.add_row("P75", f"{benchmark.p75:,.0f}")
    stats_table.add_row("P90", f"{benchmark.p90:,.0f}")
    stats_table.add_row("P95", f"{benchmark.p95:,.0f}")
    
    console.print(stats_table)
    console.print()
    
    # Show tenant comparisons
    comparison_table = Table(title="Tenant Performance Comparison")
    comparison_table.add_column("Tenant", style="cyan")
    comparison_table.add_column("Value", justify="right")
    comparison_table.add_column("Percentile", justify="right")
    comparison_table.add_column("Tier", style="bold")
    comparison_table.add_column("vs Average", justify="right")
    
    for tenant, value in tenant_values.items():
        comparison = manager.compare_tenant_to_benchmark(tenant, "api_calls_per_week", value)
        
        tier_color = {
            "top": "green",
            "above_average": "blue",
            "average": "yellow",
            "below_average": "orange",
            "bottom": "red",
        }.get(comparison.performance_tier, "white")
        
        vs_avg = ((value - benchmark.mean) / benchmark.mean) * 100
        vs_avg_str = f"{vs_avg:+.1f}%"
        
        comparison_table.add_row(
            tenant,
            f"{value:,.0f}",
            f"{comparison.percentile_rank.percentile:.1f}%",
            f"[{tier_color}]{comparison.performance_tier}[/{tier_color}]",
            vs_avg_str,
        )
    
    console.print(comparison_table)


def demo_predictive_analytics(manager: TenantAnalyticsManager):
    """Demonstrate predictive analytics."""
    print_header("3. Predictive Analytics")
    
    console.print("[bold]Generating predictions for tenants...[/bold]\n")
    
    # Usage prediction
    console.print("[cyan]Usage Forecasting:[/cyan]")
    historical_values = [1000, 1100, 1200, 1300, 1400, 1500, 1600]
    
    prediction = manager.predict_usage(
        tenant_id="acme-corp",
        metric_type=UsageMetricType.API_CALLS,
        historical_values=historical_values,
        forecast_period=AggregationPeriod.WEEKLY,
    )
    
    console.print(f"  Predicted API calls next week: [bold]{prediction.predicted_value:,.0f}[/bold]")
    console.print(f"  Trend: [bold]{prediction.trend}[/bold]")
    console.print(f"  Growth rate: [bold]{prediction.growth_rate:+.1f}%[/bold]")
    console.print(f"  Confidence: [bold]{prediction.confidence:.1%}[/bold]\n")
    
    # Churn risk assessment
    console.print("[cyan]Churn Risk Assessment:[/cyan]")
    
    # High risk tenant
    churn_high = manager.calculate_churn_risk(
        tenant_id="globex-inc",
        days_since_last_activity=30,
        usage_values=[200, 180, 160, 140, 120],  # Declining
        feature_adoption_count=3,
        total_features=20,
        support_tickets_count=12,
    )
    
    console.print(f"\n  [bold]globex-inc:[/bold]")
    console.print(f"    Risk Level: [red bold]{churn_high.risk_level.value}[/red bold]")
    console.print(f"    Risk Score: {churn_high.risk_score:.2f}")
    console.print(f"    30-day churn probability: {churn_high.churn_probability_30d:.1%}")
    console.print(f"    Risk Factors:")
    for factor in churn_high.factors[:3]:
        console.print(f"      • {factor}")
    console.print(f"    Retention Actions:")
    for action in churn_high.retention_actions[:3]:
        console.print(f"      → {action}")
    
    # Low risk tenant
    churn_low = manager.calculate_churn_risk(
        tenant_id="acme-corp",
        days_since_last_activity=1,
        usage_values=[1000, 1100, 1200, 1300, 1400],  # Growing
        feature_adoption_count=16,
        total_features=20,
        support_tickets_count=2,
    )
    
    console.print(f"\n  [bold]acme-corp:[/bold]")
    console.print(f"    Risk Level: [green bold]{churn_low.risk_level.value}[/green bold]")
    console.print(f"    Risk Score: {churn_low.risk_score:.2f}")
    console.print(f"    30-day churn probability: {churn_low.churn_probability_30d:.1%}\n")
    
    # Cost forecasting
    console.print("[cyan]Cost Forecasting:[/cyan]")
    historical_costs = [1000, 1100, 1150, 1200, 1250]
    
    cost_forecast = manager.forecast_cost(
        tenant_id="acme-corp",
        historical_costs=historical_costs,
        forecast_period=AggregationPeriod.MONTHLY,
    )
    
    console.print(f"  Predicted monthly cost: [bold]${cost_forecast.predicted_cost:,.2f}[/bold]")
    console.print(f"  Cost trend: [bold]{cost_forecast.cost_trend}[/bold]")
    console.print(f"  Confidence: [bold]{cost_forecast.confidence:.1%}[/bold]")
    console.print(f"  Breakdown:")
    console.print(f"    AI costs: ${cost_forecast.ai_cost:,.2f}")
    console.print(f"    Infrastructure: ${cost_forecast.infrastructure_cost:,.2f}")
    console.print(f"    Storage: ${cost_forecast.storage_cost:,.2f}")


def demo_health_scoring(manager: TenantAnalyticsManager):
    """Demonstrate tenant health scoring."""
    print_header("4. Tenant Health Scoring")
    
    console.print("[bold]Calculating health scores for tenants...[/bold]\n")
    
    # Healthy tenant
    health_good = manager.calculate_tenant_health(
        tenant_id="acme-corp",
        usage_metrics={'api_calls_per_day': 200, 'validations_per_month': 100},
        engagement_metrics={
            'active_users': 15,
            'total_users': 15,
            'days_since_last_activity': 0,
            'features_adopted': 16,
            'total_features': 20,
        },
        security_metrics={
            'security_validations': 100,
            'false_positive_rate': 0.05,
            'critical_vulnerabilities_open': 1,
        },
        performance_metrics={'avg_response_time_ms': 300, 'error_rate': 0.01},
        best_practices_metrics={'automation_rate': 0.8, 'integrations_active': 5},
        support_metrics={'support_tickets': 2},
    )
    
    # Unhealthy tenant
    health_poor = manager.calculate_tenant_health(
        tenant_id="globex-inc",
        usage_metrics={'api_calls_per_day': 20, 'validations_per_month': 5},
        engagement_metrics={
            'active_users': 2,
            'total_users': 10,
            'days_since_last_activity': 30,
            'features_adopted': 3,
            'total_features': 20,
        },
        security_metrics={
            'security_validations': 5,
            'false_positive_rate': 0.4,
            'critical_vulnerabilities_open': 8,
        },
        performance_metrics={'avg_response_time_ms': 2500, 'error_rate': 0.08},
        best_practices_metrics={'automation_rate': 0.1, 'integrations_active': 0},
        support_metrics={'support_tickets': 15},
    )
    
    # Display health scores
    health_table = Table(title="Tenant Health Scores")
    health_table.add_column("Tenant", style="cyan")
    health_table.add_column("Score", justify="right")
    health_table.add_column("Status", style="bold")
    health_table.add_column("Strengths", style="green")
    health_table.add_column("Weaknesses", style="red")
    
    for health in [health_good, health_poor]:
        status_color = {
            HealthStatus.EXCELLENT: "green",
            HealthStatus.GOOD: "blue",
            HealthStatus.FAIR: "yellow",
            HealthStatus.POOR: "orange",
            HealthStatus.CRITICAL: "red",
        }.get(health.status, "white")
        
        strengths = "\n".join(health.strengths[:2]) if health.strengths else "None"
        weaknesses = "\n".join(health.weaknesses[:2]) if health.weaknesses else "None"
        
        health_table.add_row(
            health.tenant_id,
            f"{health.overall_score:.1f}/100",
            f"[{status_color}]{health.status.value}[/{status_color}]",
            strengths,
            weaknesses,
        )
    
    console.print(health_table)
    
    # Show recommendations for unhealthy tenant
    console.print(f"\n[bold]Recommendations for {health_poor.tenant_id}:[/bold]")
    for i, rec in enumerate(health_poor.recommendations[:5], 1):
        console.print(f"  {i}. {rec}")


def demo_saas_metrics(manager: TenantAnalyticsManager):
    """Demonstrate SaaS metrics calculation."""
    print_header("5. SaaS Metrics Dashboard")
    
    console.print("[bold]Calculating comprehensive SaaS metrics...[/bold]\n")
    
    now = datetime.utcnow()
    
    metrics = manager.calculate_saas_metrics(
        period_start=now - timedelta(days=30),
        period_end=now,
        period=AggregationPeriod.MONTHLY,
        current_mrr=50000,
        previous_mrr=45000,
        new_revenue=8000,
        expansion_revenue=2000,
        contraction_revenue=500,
        churned_revenue=1500,
        total_customers=50,
        new_customers=5,
        churned_customers=2,
        active_customers=48,
        total_acquisition_cost=10000,
        total_api_calls=500000,
        total_validations=25000,
        total_ai_tokens=5000000,
        average_response_time_ms=400,
        error_count=500,
        total_requests=50000,
        uptime_percentage=99.95,
        total_costs=15000,
        support_tickets=100,
        total_resolution_time_hours=200,
        customer_satisfaction_score=8.7,
        previous_arr=540000,
        previous_total_customers=47,
    )
    
    # Revenue metrics
    revenue_table = Table(title="Revenue Metrics")
    revenue_table.add_column("Metric", style="cyan")
    revenue_table.add_column("Value", justify="right", style="bold")
    
    revenue_table.add_row("MRR", f"${metrics.revenue.mrr:,.0f}")
    revenue_table.add_row("MRR Growth", f"{metrics.revenue.mrr_growth_rate:+.1f}%")
    revenue_table.add_row("ARR", f"${metrics.revenue.arr:,.0f}")
    revenue_table.add_row("ARPU", f"${metrics.revenue.arpu:,.2f}")
    revenue_table.add_row("NRR", f"{metrics.revenue.nrr:.1f}%")
    revenue_table.add_row("GRR", f"{metrics.revenue.grr:.1f}%")
    
    console.print(revenue_table)
    console.print()
    
    # Customer metrics
    customer_table = Table(title="Customer Metrics")
    customer_table.add_column("Metric", style="cyan")
    customer_table.add_column("Value", justify="right", style="bold")
    
    customer_table.add_row("Total Customers", f"{metrics.customers.total_customers}")
    customer_table.add_row("New Customers", f"+{metrics.customers.new_customers}")
    customer_table.add_row("Churned Customers", f"-{metrics.customers.churned_customers}")
    customer_table.add_row("Churn Rate", f"{metrics.customers.customer_churn_rate:.1f}%")
    customer_table.add_row("LTV", f"${metrics.customers.ltv:,.2f}")
    customer_table.add_row("CAC", f"${metrics.customers.cac:,.2f}")
    customer_table.add_row("LTV:CAC Ratio", f"{metrics.customers.ltv_cac_ratio:.2f}x")
    customer_table.add_row("CAC Payback", f"{metrics.customers.cac_payback_period:.1f} months")
    
    console.print(customer_table)
    console.print()
    
    # Operational metrics
    ops_table = Table(title="Operational Metrics")
    ops_table.add_column("Metric", style="cyan")
    ops_table.add_column("Value", justify="right", style="bold")
    
    ops_table.add_row("API Calls", f"{metrics.operations.total_api_calls:,}")
    ops_table.add_row("Validations", f"{metrics.operations.total_validations:,}")
    ops_table.add_row("Avg Response Time", f"{metrics.operations.average_response_time_ms:.0f}ms")
    ops_table.add_row("Error Rate", f"{metrics.operations.error_rate:.2f}%")
    ops_table.add_row("Uptime", f"{metrics.operations.uptime:.2f}%")
    ops_table.add_row("Cost per Validation", f"${metrics.operations.cost_per_validation:.2f}")
    ops_table.add_row("Gross Margin", f"{metrics.operations.gross_margin:.1f}%")
    ops_table.add_row("CSAT Score", f"{metrics.operations.customer_satisfaction_score:.1f}/10")
    
    console.print(ops_table)
    console.print()
    
    # Overall health
    health_score = metrics.overall_health_score
    health_color = "green" if health_score >= 80 else "yellow" if health_score >= 60 else "red"
    
    console.print(Panel(
        f"[{health_color} bold]Overall Business Health: {health_score:.1f}/100[/{health_color} bold]",
        title="Business Health Score",
        border_style=health_color,
    ))


def main():
    """Run the demo."""
    console.print(Panel.fit(
        "[bold cyan]BountyBot v2.16.0[/bold cyan]\n"
        "[white]Advanced Multi-Tenant Analytics & Insights[/white]\n\n"
        "[dim]Comprehensive analytics for enterprise SaaS operations[/dim]",
        border_style="cyan",
    ))
    
    # Run demos
    manager = demo_usage_tracking()
    demo_benchmarking(manager)
    demo_predictive_analytics(manager)
    demo_health_scoring(manager)
    demo_saas_metrics(manager)
    
    # Final summary
    print_header("Summary")
    
    stats = manager.get_stats()
    
    summary_table = Table(title="Analytics Platform Statistics")
    summary_table.add_column("Component", style="cyan")
    summary_table.add_column("Metrics", justify="right")
    
    summary_table.add_row("Usage Events Tracked", f"{stats['usage_tracker']['total_events']:,}")
    summary_table.add_row("Benchmarks Calculated", f"{stats['benchmarking_engine']['total_benchmarks']}")
    summary_table.add_row("Predictions Generated", f"{stats['predictive_engine']['total_predictions']}")
    summary_table.add_row("Health Scores Calculated", f"{stats['health_scorer']['total_scores_calculated']}")
    summary_table.add_row("SaaS Metrics Periods", f"{stats['saas_metrics']['metrics_history_count']}")
    
    console.print(summary_table)
    
    console.print("\n[bold green]✓ Demo completed successfully![/bold green]")
    console.print("[dim]Multi-tenant analytics system is production ready.[/dim]\n")


if __name__ == "__main__":
    main()

