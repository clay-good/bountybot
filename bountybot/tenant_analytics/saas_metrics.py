"""
SaaS Metrics Calculator

Calculates comprehensive SaaS metrics including MRR, churn, LTV, CAC, and operational metrics.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from bountybot.tenant_analytics.models import (
    SaaSMetrics,
    RevenueMetrics,
    CustomerMetrics,
    OperationalMetrics,
    AggregationPeriod,
)


logger = logging.getLogger(__name__)


class SaaSMetricsCalculator:
    """Calculates SaaS business metrics."""
    
    def __init__(self):
        """Initialize SaaS metrics calculator."""
        self.metrics_history: List[SaaSMetrics] = []
        self.stats = {
            'total_calculations': 0,
        }
    
    def calculate_saas_metrics(
        self,
        period_start: datetime,
        period_end: datetime,
        period: AggregationPeriod,
        
        # Revenue data
        current_mrr: float,
        previous_mrr: float,
        new_revenue: float,
        expansion_revenue: float,
        contraction_revenue: float,
        churned_revenue: float,
        
        # Customer data
        total_customers: int,
        new_customers: int,
        churned_customers: int,
        active_customers: int,
        
        # Cost data
        total_acquisition_cost: float,
        
        # Usage data
        total_api_calls: int,
        total_validations: int,
        total_ai_tokens: int,
        
        # Performance data
        average_response_time_ms: float,
        error_count: int,
        total_requests: int,
        uptime_percentage: float,
        
        # Cost data
        total_costs: float,
        
        # Support data
        support_tickets: int,
        total_resolution_time_hours: float,
        customer_satisfaction_score: float,
        
        # Previous period data for growth calculations
        previous_arr: Optional[float] = None,
        previous_arpu: Optional[float] = None,
        previous_total_customers: Optional[int] = None,
    ) -> SaaSMetrics:
        """
        Calculate comprehensive SaaS metrics.
        
        Args:
            period_start: Start of period
            period_end: End of period
            period: Aggregation period
            ... (many parameters for different metrics)
            
        Returns:
            Comprehensive SaaS metrics
        """
        # ===== Revenue Metrics =====
        revenue = RevenueMetrics()
        
        # MRR and growth
        revenue.mrr = current_mrr
        if previous_mrr > 0:
            revenue.mrr_growth_rate = ((current_mrr - previous_mrr) / previous_mrr) * 100
        
        # ARR (Annual Recurring Revenue)
        revenue.arr = current_mrr * 12
        if previous_arr and previous_arr > 0:
            revenue.arr_growth_rate = ((revenue.arr - previous_arr) / previous_arr) * 100
        
        # ARPU (Average Revenue Per User)
        if active_customers > 0:
            revenue.arpu = current_mrr / active_customers
            if previous_arpu and previous_arpu > 0:
                revenue.arpu_growth_rate = ((revenue.arpu - previous_arpu) / previous_arpu) * 100
        
        # Revenue breakdown
        revenue.new_revenue = new_revenue
        revenue.expansion_revenue = expansion_revenue
        revenue.contraction_revenue = contraction_revenue
        revenue.churned_revenue = churned_revenue
        
        # Net Revenue Retention (NRR)
        # NRR = (Starting MRR + Expansion - Contraction - Churn) / Starting MRR
        if previous_mrr > 0:
            retained_revenue = previous_mrr + expansion_revenue - contraction_revenue - churned_revenue
            revenue.nrr = (retained_revenue / previous_mrr) * 100
        
        # Gross Revenue Retention (GRR)
        # GRR = (Starting MRR - Churn) / Starting MRR
        if previous_mrr > 0:
            revenue.grr = ((previous_mrr - churned_revenue) / previous_mrr) * 100
        
        # ===== Customer Metrics =====
        customers = CustomerMetrics()
        
        customers.total_customers = total_customers
        customers.new_customers = new_customers
        customers.churned_customers = churned_customers
        customers.active_customers = active_customers
        
        # Churn rates
        if previous_total_customers and previous_total_customers > 0:
            customers.customer_churn_rate = (churned_customers / previous_total_customers) * 100
        
        if previous_mrr > 0:
            customers.revenue_churn_rate = (churned_revenue / previous_mrr) * 100
        
        # Customer Lifetime Value (LTV)
        # LTV = ARPU / Churn Rate
        if customers.customer_churn_rate > 0:
            monthly_churn_rate = customers.customer_churn_rate / 100
            if monthly_churn_rate > 0:
                customers.ltv = revenue.arpu / monthly_churn_rate
        
        # Customer Acquisition Cost (CAC)
        if new_customers > 0:
            customers.cac = total_acquisition_cost / new_customers
        
        # LTV:CAC ratio
        if customers.cac > 0:
            customers.ltv_cac_ratio = customers.ltv / customers.cac
        
        # CAC Payback Period (months)
        # Payback = CAC / (ARPU * Gross Margin)
        if revenue.arpu > 0 and total_costs > 0:
            gross_margin = 1 - (total_costs / current_mrr) if current_mrr > 0 else 0
            if gross_margin > 0:
                customers.cac_payback_period = customers.cac / (revenue.arpu * gross_margin)
        
        # Customer health (placeholder - would come from health scorer)
        customers.healthy_customers = int(active_customers * 0.7)  # Estimate
        customers.at_risk_customers = int(active_customers * 0.2)  # Estimate
        customers.critical_customers = int(active_customers * 0.1)  # Estimate
        
        # ===== Operational Metrics =====
        operations = OperationalMetrics()
        
        operations.total_api_calls = total_api_calls
        operations.total_validations = total_validations
        operations.total_ai_tokens = total_ai_tokens
        
        # Performance
        operations.average_response_time_ms = average_response_time_ms
        if total_requests > 0:
            operations.error_rate = (error_count / total_requests) * 100
        operations.uptime = uptime_percentage
        
        # Efficiency
        if total_validations > 0:
            operations.cost_per_validation = total_costs / total_validations
        if active_customers > 0:
            operations.cost_per_customer = total_costs / active_customers
        if current_mrr > 0:
            operations.gross_margin = ((current_mrr - total_costs) / current_mrr) * 100
        
        # Support
        operations.support_tickets = support_tickets
        if support_tickets > 0:
            operations.average_resolution_time_hours = total_resolution_time_hours / support_tickets
        operations.customer_satisfaction_score = customer_satisfaction_score
        
        # ===== Overall Health Score =====
        # Simple weighted average of key metrics
        health_components = []
        
        # Revenue health (30%)
        if revenue.mrr_growth_rate > 10:
            health_components.append(100 * 0.3)
        elif revenue.mrr_growth_rate > 5:
            health_components.append(80 * 0.3)
        elif revenue.mrr_growth_rate > 0:
            health_components.append(60 * 0.3)
        else:
            health_components.append(40 * 0.3)
        
        # Customer health (30%)
        if customers.customer_churn_rate < 2:
            health_components.append(100 * 0.3)
        elif customers.customer_churn_rate < 5:
            health_components.append(80 * 0.3)
        elif customers.customer_churn_rate < 10:
            health_components.append(60 * 0.3)
        else:
            health_components.append(40 * 0.3)
        
        # LTV:CAC ratio health (20%)
        if customers.ltv_cac_ratio > 3:
            health_components.append(100 * 0.2)
        elif customers.ltv_cac_ratio > 2:
            health_components.append(80 * 0.2)
        elif customers.ltv_cac_ratio > 1:
            health_components.append(60 * 0.2)
        else:
            health_components.append(40 * 0.2)
        
        # Operational health (20%)
        if operations.error_rate < 1 and operations.uptime > 99.9:
            health_components.append(100 * 0.2)
        elif operations.error_rate < 2 and operations.uptime > 99.5:
            health_components.append(80 * 0.2)
        elif operations.error_rate < 5 and operations.uptime > 99:
            health_components.append(60 * 0.2)
        else:
            health_components.append(40 * 0.2)
        
        overall_health_score = sum(health_components)
        
        # ===== Create SaaS Metrics =====
        saas_metrics = SaaSMetrics(
            period_start=period_start,
            period_end=period_end,
            period=period,
            revenue=revenue,
            customers=customers,
            operations=operations,
            overall_health_score=overall_health_score,
        )
        
        # Store metrics
        self.metrics_history.append(saas_metrics)
        self.stats['total_calculations'] += 1
        
        logger.info(
            f"Calculated SaaS metrics for period {period.value}: "
            f"MRR=${current_mrr:.2f}, Customers={total_customers}, Health={overall_health_score:.1f}"
        )
        
        return saas_metrics
    
    def get_latest_metrics(self) -> Optional[SaaSMetrics]:
        """Get the most recent SaaS metrics."""
        if not self.metrics_history:
            return None
        return self.metrics_history[-1]
    
    def get_metrics_history(
        self,
        period: Optional[AggregationPeriod] = None,
        limit: Optional[int] = None,
    ) -> List[SaaSMetrics]:
        """
        Get historical SaaS metrics.
        
        Args:
            period: Filter by period (optional)
            limit: Limit number of results (optional)
            
        Returns:
            List of SaaS metrics
        """
        metrics = self.metrics_history
        
        if period:
            metrics = [m for m in metrics if m.period == period]
        
        # Sort by period start descending (most recent first)
        metrics.sort(key=lambda m: m.period_start, reverse=True)
        
        if limit:
            metrics = metrics[:limit]
        
        return metrics
    
    def get_growth_trends(self, num_periods: int = 6) -> Dict[str, List[float]]:
        """
        Get growth trends over time.
        
        Args:
            num_periods: Number of periods to analyze
            
        Returns:
            Dictionary of metric -> values over time
        """
        recent_metrics = self.get_metrics_history(limit=num_periods)
        recent_metrics.reverse()  # Oldest to newest
        
        trends = {
            'mrr': [m.revenue.mrr for m in recent_metrics],
            'arr': [m.revenue.arr for m in recent_metrics],
            'total_customers': [m.customers.total_customers for m in recent_metrics],
            'churn_rate': [m.customers.customer_churn_rate for m in recent_metrics],
            'ltv_cac_ratio': [m.customers.ltv_cac_ratio for m in recent_metrics],
            'nrr': [m.revenue.nrr for m in recent_metrics],
            'health_score': [m.overall_health_score for m in recent_metrics],
        }
        
        return trends
    
    def get_stats(self) -> Dict:
        """Get SaaS metrics calculator statistics."""
        latest = self.get_latest_metrics()
        
        stats = {
            'total_calculations': self.stats['total_calculations'],
            'metrics_history_count': len(self.metrics_history),
        }
        
        if latest:
            stats.update({
                'latest_mrr': latest.revenue.mrr,
                'latest_arr': latest.revenue.arr,
                'latest_customers': latest.customers.total_customers,
                'latest_health_score': latest.overall_health_score,
            })
        
        return stats

