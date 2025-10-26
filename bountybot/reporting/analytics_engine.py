"""
Analytics engine for trend analysis, ROI calculation, and benchmarking.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from statistics import mean, median, stdev

from bountybot.reporting.models import (
    ReportMetrics,
    ExecutiveSummary,
    ROIMetrics,
    TrendData,
    BenchmarkData,
    AnalyticsQuery,
)

logger = logging.getLogger(__name__)


class TrendAnalyzer:
    """Analyze trends in metrics over time."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize trend analyzer."""
        self.config = config or {}
        self.min_data_points = self.config.get('min_data_points', 3)
        self.anomaly_threshold = self.config.get('anomaly_threshold', 2.0)  # std devs
    
    def analyze_trend(
        self,
        metric_name: str,
        time_series: List[Dict[str, Any]]
    ) -> TrendData:
        """
        Analyze trend for a metric.
        
        Args:
            metric_name: Name of the metric
            time_series: List of {timestamp, value} dicts
        
        Returns:
            TrendData with analysis results
        """
        logger.info(f"Analyzing trend for {metric_name} ({len(time_series)} data points)")
        
        if len(time_series) < self.min_data_points:
            logger.warning(f"Insufficient data points for trend analysis: {len(time_series)}")
            return TrendData(metric_name=metric_name, time_series=time_series)
        
        # Extract values
        values = [point['value'] for point in time_series]
        
        # Calculate statistics
        mean_val = mean(values)
        median_val = median(values)
        std_dev = stdev(values) if len(values) > 1 else 0.0
        min_val = min(values)
        max_val = max(values)
        
        # Determine trend direction and strength
        trend_direction, trend_strength = self._calculate_trend(values)
        
        # Detect anomalies
        anomalies = self._detect_anomalies(time_series, mean_val, std_dev)
        
        # Forecast next period
        forecast_value, forecast_confidence = self._forecast_next_period(values)
        
        return TrendData(
            metric_name=metric_name,
            time_series=time_series,
            trend_direction=trend_direction,
            trend_strength=trend_strength,
            mean=mean_val,
            median=median_val,
            std_dev=std_dev,
            min_value=min_val,
            max_value=max_val,
            forecast_next_period=forecast_value,
            forecast_confidence=forecast_confidence,
            anomalies=anomalies
        )
    
    def _calculate_trend(self, values: List[float]) -> tuple[str, float]:
        """Calculate trend direction and strength."""
        if len(values) < 2:
            return "stable", 0.0
        
        # Simple linear regression
        n = len(values)
        x = list(range(n))
        x_mean = mean(x)
        y_mean = mean(values)
        
        # Calculate slope
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return "stable", 0.0
        
        slope = numerator / denominator
        
        # Calculate R-squared for strength
        y_pred = [slope * (i - x_mean) + y_mean for i in x]
        ss_res = sum((values[i] - y_pred[i]) ** 2 for i in range(n))
        ss_tot = sum((values[i] - y_mean) ** 2 for i in range(n))
        r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0.0
        
        # Determine direction
        if abs(slope) < 0.01 * abs(y_mean):  # Less than 1% change
            direction = "stable"
        elif slope > 0:
            direction = "increasing"
        else:
            direction = "decreasing"
        
        return direction, abs(r_squared)
    
    def _detect_anomalies(
        self,
        time_series: List[Dict[str, Any]],
        mean_val: float,
        std_dev: float
    ) -> List[Dict[str, Any]]:
        """Detect anomalies in time series."""
        if std_dev == 0:
            return []
        
        anomalies = []
        for point in time_series:
            z_score = abs((point['value'] - mean_val) / std_dev)
            if z_score > self.anomaly_threshold:
                anomalies.append({
                    'timestamp': point['timestamp'],
                    'value': point['value'],
                    'z_score': z_score,
                    'deviation': point['value'] - mean_val
                })
        
        return anomalies
    
    def _forecast_next_period(self, values: List[float]) -> tuple[Optional[float], float]:
        """Forecast next period value using simple moving average."""
        if len(values) < 3:
            return None, 0.0
        
        # Use last 3 values for forecast
        recent_values = values[-3:]
        forecast = mean(recent_values)
        
        # Confidence based on recent stability
        recent_std = stdev(recent_values) if len(recent_values) > 1 else 0.0
        confidence = max(0.0, 1.0 - (recent_std / abs(forecast)) if forecast != 0 else 0.5)
        
        return forecast, confidence


class ROICalculator:
    """Calculate Return on Investment metrics."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize ROI calculator."""
        self.config = config or {}
        
        # Cost assumptions (configurable)
        self.hourly_rate = self.config.get('hourly_rate', 75.0)  # $/hour for security engineer
        self.avg_incident_cost = self.config.get('avg_incident_cost', 50000.0)  # $ per incident
        self.bountybot_monthly_cost = self.config.get('bountybot_monthly_cost', 1000.0)  # $/month
    
    def calculate_roi(
        self,
        metrics: ReportMetrics,
        period_months: int = 1,
        manual_hours_per_report: float = 2.5,
        automation_rate: float = 0.85,
        incidents_prevented: int = 0,
        ai_cost: Optional[float] = None
    ) -> ROIMetrics:
        """
        Calculate ROI metrics.
        
        Args:
            metrics: Report metrics
            period_months: Period in months
            manual_hours_per_report: Manual hours per report without automation
            automation_rate: Automation rate (0-1)
            incidents_prevented: Number of incidents prevented
            ai_cost: AI API cost (optional, uses metrics if not provided)
        
        Returns:
            ROI metrics
        """
        logger.info(f"Calculating ROI for {period_months} months")
        
        # Time savings
        total_reports = metrics.total_reports_processed
        manual_hours_saved = total_reports * manual_hours_per_report * automation_rate
        avg_time_saved_per_report = manual_hours_per_report * automation_rate
        
        # Cost savings
        labor_cost_saved = manual_hours_saved * self.hourly_rate
        incident_cost_avoided = incidents_prevented * self.avg_incident_cost
        total_cost_saved = labor_cost_saved + incident_cost_avoided
        
        # Investment
        bountybot_cost = self.bountybot_monthly_cost * period_months
        ai_api_cost = ai_cost if ai_cost is not None else metrics.total_ai_cost
        infrastructure_cost = self.config.get('infrastructure_monthly_cost', 500.0) * period_months
        total_investment = bountybot_cost + ai_api_cost + infrastructure_cost
        
        # ROI calculation
        net_savings = total_cost_saved - total_investment
        roi_percent = (net_savings / total_investment * 100) if total_investment > 0 else 0.0
        payback_period_months = (total_investment / (total_cost_saved / period_months)) if total_cost_saved > 0 else 0.0
        
        # Productivity metrics
        reports_per_day = total_reports / (period_months * 30)
        vulnerabilities_per_day = metrics.total_vulnerabilities_fixed / (period_months * 30)
        productivity_improvement = automation_rate * 100
        
        # Quality improvements
        baseline_fp_rate = 0.15  # Assume 15% baseline false positive rate
        fp_reduction = ((baseline_fp_rate - metrics.false_positive_rate) / baseline_fp_rate * 100) if baseline_fp_rate > 0 else 0.0
        
        baseline_mttr = 168.0  # Assume 1 week baseline MTTR
        mttr_improvement = ((baseline_mttr - metrics.avg_total_lifecycle_time) / baseline_mttr * 100) if baseline_mttr > 0 else 0.0
        
        return ROIMetrics(
            manual_hours_saved=manual_hours_saved,
            automation_rate=automation_rate,
            avg_time_saved_per_report=avg_time_saved_per_report,
            labor_cost_saved=labor_cost_saved,
            incident_cost_avoided=incident_cost_avoided,
            total_cost_saved=total_cost_saved,
            bountybot_cost=bountybot_cost,
            ai_api_cost=ai_api_cost,
            infrastructure_cost=infrastructure_cost,
            total_investment=total_investment,
            net_savings=net_savings,
            roi_percent=roi_percent,
            payback_period_months=payback_period_months,
            reports_processed_per_day=reports_per_day,
            vulnerabilities_fixed_per_day=vulnerabilities_per_day,
            productivity_improvement_percent=productivity_improvement,
            false_positive_reduction_percent=fp_reduction,
            mean_time_to_remediate_improvement_percent=mttr_improvement
        )


class BenchmarkAnalyzer:
    """Analyze performance against industry benchmarks."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize benchmark analyzer."""
        self.config = config or {}
        
        # Industry benchmarks (configurable)
        self.benchmarks = {
            'avg_time_to_fix': {
                'average': 72.0,  # hours
                'best': 24.0,
                'source': 'Industry Survey 2024',
                'lower_is_better': True  # Lower time is better
            },
            'fix_success_rate': {
                'average': 0.85,
                'best': 0.95,
                'source': 'Industry Survey 2024'
            },
            'false_positive_rate': {
                'average': 0.15,
                'best': 0.05,
                'source': 'Industry Survey 2024',
                'lower_is_better': True
            },
            'automation_rate': {
                'average': 0.60,
                'best': 0.90,
                'source': 'Industry Survey 2024'
            }
        }
    
    def benchmark_metric(
        self,
        metric_name: str,
        current_value: float
    ) -> BenchmarkData:
        """
        Benchmark a metric against industry standards.
        
        Args:
            metric_name: Name of the metric
            current_value: Current value
        
        Returns:
            Benchmark data
        """
        logger.info(f"Benchmarking {metric_name}: {current_value}")
        
        benchmark = self.benchmarks.get(metric_name)
        if not benchmark:
            logger.warning(f"No benchmark data for {metric_name}")
            return BenchmarkData(
                metric_name=metric_name,
                current_value=current_value,
                performance_rating="unknown"
            )
        
        industry_average = benchmark['average']
        industry_best = benchmark['best']
        lower_is_better = benchmark.get('lower_is_better', False)
        
        # Calculate vs average
        if lower_is_better:
            vs_average_percent = ((industry_average - current_value) / industry_average * 100) if industry_average > 0 else 0.0
            vs_best_percent = ((industry_best - current_value) / industry_best * 100) if industry_best > 0 else 0.0
        else:
            vs_average_percent = ((current_value - industry_average) / industry_average * 100) if industry_average > 0 else 0.0
            vs_best_percent = ((current_value - industry_best) / industry_best * 100) if industry_best > 0 else 0.0
        
        # Calculate percentile (simplified)
        if lower_is_better:
            # For metrics where lower is better (e.g., time to fix)
            if current_value <= industry_best:
                percentile = 95.0
            elif current_value <= industry_average:
                percentile = 70.0
            elif current_value <= industry_average * 1.5:
                percentile = 40.0
            else:
                percentile = 20.0
        else:
            # For metrics where higher is better (e.g., fix success rate)
            if current_value >= industry_best:
                percentile = 95.0
            elif current_value >= industry_average:
                percentile = 70.0
            elif current_value >= industry_average * 0.8:
                percentile = 40.0
            else:
                percentile = 20.0
        
        # Determine performance rating
        if percentile >= 90:
            rating = "excellent"
        elif percentile >= 70:
            rating = "good"
        elif percentile >= 50:
            rating = "average"
        elif percentile >= 30:
            rating = "below_average"
        else:
            rating = "poor"
        
        return BenchmarkData(
            metric_name=metric_name,
            current_value=current_value,
            industry_average=industry_average,
            industry_best=industry_best,
            industry_percentile=percentile,
            vs_average_percent=vs_average_percent,
            vs_best_percent=vs_best_percent,
            performance_rating=rating,
            sample_size=1000,  # Placeholder
            data_source=benchmark['source'],
            last_updated=datetime.utcnow()
        )


class AnalyticsEngine:
    """Main analytics engine combining all analyzers."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize analytics engine."""
        self.config = config or {}
        self.trend_analyzer = TrendAnalyzer(config)
        self.roi_calculator = ROICalculator(config)
        self.benchmark_analyzer = BenchmarkAnalyzer(config)
    
    def generate_executive_summary(
        self,
        current_metrics: ReportMetrics,
        previous_metrics: Optional[ReportMetrics],
        period_start: datetime,
        period_end: datetime
    ) -> ExecutiveSummary:
        """
        Generate executive summary.
        
        Args:
            current_metrics: Current period metrics
            previous_metrics: Previous period metrics (for trends)
            period_start: Period start date
            period_end: Period end date
        
        Returns:
            Executive summary
        """
        logger.info("Generating executive summary")
        
        # Calculate trends
        if previous_metrics:
            reports_trend = self._calculate_percent_change(
                current_metrics.total_reports_processed,
                previous_metrics.total_reports_processed
            )
            critical_trend = self._calculate_percent_change(
                current_metrics.critical_count,
                previous_metrics.critical_count
            )
            fix_time_trend = self._calculate_percent_change(
                previous_metrics.avg_time_to_fix,  # Lower is better
                current_metrics.avg_time_to_fix
            )
            fix_rate_trend = self._calculate_percent_change(
                current_metrics.fix_success_rate,
                previous_metrics.fix_success_rate
            )
        else:
            reports_trend = 0.0
            critical_trend = 0.0
            fix_time_trend = 0.0
            fix_rate_trend = 0.0
        
        # Top vulnerability types (placeholder - would query database)
        top_vuln_types = [
            {'type': 'SQL Injection', 'count': current_metrics.critical_count // 3},
            {'type': 'XSS', 'count': current_metrics.high_count // 3},
            {'type': 'CSRF', 'count': current_metrics.medium_count // 3}
        ]
        
        # Key recommendations
        recommendations = self._generate_recommendations(current_metrics)
        
        # Risk assessment
        risk_score = self._calculate_risk_score(current_metrics)
        risk_trend = self._determine_risk_trend(current_metrics, previous_metrics)
        
        # Summary text
        summary_text = self._generate_summary_text(current_metrics, reports_trend, critical_trend)
        
        return ExecutiveSummary(
            period_start=period_start,
            period_end=period_end,
            total_reports=current_metrics.total_reports_processed,
            critical_vulnerabilities=current_metrics.critical_count,
            vulnerabilities_fixed=current_metrics.total_vulnerabilities_fixed,
            avg_fix_time_hours=current_metrics.avg_time_to_fix,
            reports_trend_percent=reports_trend,
            critical_trend_percent=critical_trend,
            fix_time_trend_percent=fix_time_trend,
            fix_rate_trend_percent=fix_rate_trend,
            top_vulnerability_types=top_vuln_types,
            top_affected_systems=[],  # Would query database
            key_recommendations=recommendations,
            overall_risk_score=risk_score,
            risk_trend=risk_trend,
            summary_text=summary_text
        )
    
    def _calculate_percent_change(self, current: float, previous: float) -> float:
        """Calculate percent change."""
        if previous == 0:
            return 0.0
        return ((current - previous) / previous) * 100
    
    def _generate_recommendations(self, metrics: ReportMetrics) -> List[str]:
        """Generate key recommendations."""
        recommendations = []
        
        if metrics.critical_count > 5:
            recommendations.append("Prioritize remediation of critical vulnerabilities")
        
        if metrics.false_positive_rate > 0.10:
            recommendations.append("Review validation process to reduce false positives")
        
        if metrics.avg_time_to_fix > 72:
            recommendations.append("Implement faster remediation workflows")
        
        if metrics.regression_rate > 0.05:
            recommendations.append("Strengthen regression testing and monitoring")
        
        if not recommendations:
            recommendations.append("Continue current security practices")
        
        return recommendations
    
    def _calculate_risk_score(self, metrics: ReportMetrics) -> float:
        """Calculate overall risk score (0-100)."""
        # Weighted risk calculation
        critical_risk = min(metrics.critical_count * 10, 40)
        high_risk = min(metrics.high_count * 5, 30)
        open_risk = min(metrics.open_count * 2, 20)
        regression_risk = metrics.regression_rate * 100 * 0.1
        
        total_risk = critical_risk + high_risk + open_risk + regression_risk
        return min(total_risk, 100.0)
    
    def _determine_risk_trend(
        self,
        current: ReportMetrics,
        previous: Optional[ReportMetrics]
    ) -> str:
        """Determine risk trend."""
        if not previous:
            return "stable"
        
        current_risk = self._calculate_risk_score(current)
        previous_risk = self._calculate_risk_score(previous)
        
        if current_risk < previous_risk * 0.9:
            return "improving"
        elif current_risk > previous_risk * 1.1:
            return "degrading"
        else:
            return "stable"
    
    def _generate_summary_text(
        self,
        metrics: ReportMetrics,
        reports_trend: float,
        critical_trend: float
    ) -> str:
        """Generate summary text."""
        trend_text = "increased" if reports_trend > 0 else "decreased" if reports_trend < 0 else "remained stable"
        critical_text = "up" if critical_trend > 0 else "down" if critical_trend < 0 else "stable"
        
        return f"""
During this period, {metrics.total_reports_processed} security reports were processed, 
{trend_text} from the previous period. {metrics.critical_count} critical vulnerabilities 
were identified ({critical_text} from previous period), with {metrics.total_vulnerabilities_fixed} 
vulnerabilities successfully remediated. The average time to fix was {metrics.avg_time_to_fix:.1f} hours, 
with a fix success rate of {metrics.fix_success_rate:.1%}.
        """.strip()

