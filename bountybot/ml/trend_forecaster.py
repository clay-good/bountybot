"""
Trend forecasting for vulnerability submissions.
"""

import logging
import statistics
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class TrendForecaster:
    """
    Forecast trends in vulnerability submissions.
    
    Forecasts:
    - Submission volume trends
    - Vulnerability type trends
    - Severity trends
    - Seasonal patterns
    - Emerging threats
    """
    
    def __init__(self, forecast_days: int = 30):
        """
        Initialize trend forecaster.
        
        Args:
            forecast_days: Number of days to forecast ahead
        """
        self.forecast_days = forecast_days
        
        # Historical data
        self.historical_data: List[Tuple[datetime, Any]] = []
        
        # Trend models
        self.volume_trend: Dict[str, float] = {}
        self.type_trends: Dict[str, List[float]] = defaultdict(list)
        self.severity_trends: List[float] = []
        
        logger.info(f"TrendForecaster initialized (forecast_days={forecast_days})")
    
    def analyze_historical_data(self, reports: List[Any], timestamps: List[datetime]):
        """
        Analyze historical data to build trend models.
        
        Args:
            reports: List of vulnerability reports
            timestamps: Corresponding submission timestamps
        """
        logger.info(f"Analyzing {len(reports)} historical reports for trends")
        
        # Store historical data
        self.historical_data = list(zip(timestamps, reports))
        self.historical_data.sort(key=lambda x: x[0])
        
        # Analyze volume trends
        self._analyze_volume_trends()
        
        # Analyze vulnerability type trends
        self._analyze_type_trends()
        
        # Analyze severity trends
        self._analyze_severity_trends()
        
        logger.info("Trend analysis complete")
    
    def forecast_volume(self, days_ahead: Optional[int] = None) -> Dict[str, Any]:
        """
        Forecast submission volume.
        
        Args:
            days_ahead: Number of days to forecast (default: self.forecast_days)
            
        Returns:
            Dictionary with volume forecast
        """
        days = days_ahead or self.forecast_days
        
        if not self.volume_trend:
            return {'error': 'No historical data available'}
        
        # Get current trend
        daily_avg = self.volume_trend.get('daily_average', 0.0)
        growth_rate = self.volume_trend.get('growth_rate', 0.0)
        
        # Forecast future volumes
        forecasted_volumes = []
        for day in range(1, days + 1):
            # Simple exponential growth model
            forecasted_volume = daily_avg * (1 + growth_rate) ** day
            forecasted_volumes.append(forecasted_volume)
        
        # Calculate confidence intervals
        std_dev = self.volume_trend.get('std_dev', 0.0)
        lower_bound = [max(0, v - 2 * std_dev) for v in forecasted_volumes]
        upper_bound = [v + 2 * std_dev for v in forecasted_volumes]
        
        return {
            'forecast_days': days,
            'daily_average': daily_avg,
            'growth_rate': growth_rate,
            'forecasted_volumes': forecasted_volumes,
            'lower_bound': lower_bound,
            'upper_bound': upper_bound,
            'total_forecasted': sum(forecasted_volumes),
            'confidence': self._calculate_forecast_confidence()
        }
    
    def forecast_vulnerability_types(self, days_ahead: Optional[int] = None) -> Dict[str, Any]:
        """
        Forecast vulnerability type distribution.
        
        Args:
            days_ahead: Number of days to forecast
            
        Returns:
            Dictionary with type distribution forecast
        """
        days = days_ahead or self.forecast_days
        
        if not self.type_trends:
            return {'error': 'No historical data available'}
        
        forecasts = {}
        
        for vuln_type, historical_counts in self.type_trends.items():
            if len(historical_counts) < 2:
                continue
            
            # Calculate trend
            avg_count = statistics.mean(historical_counts)
            
            # Simple linear trend
            if len(historical_counts) >= 3:
                recent_avg = statistics.mean(historical_counts[-7:])
                older_avg = statistics.mean(historical_counts[:-7]) if len(historical_counts) > 7 else avg_count
                trend = (recent_avg - older_avg) / max(older_avg, 1)
            else:
                trend = 0.0
            
            # Forecast
            forecasted_count = avg_count * (1 + trend) ** (days / 30)
            
            forecasts[vuln_type] = {
                'current_average': avg_count,
                'trend': trend,
                'forecasted_count': forecasted_count,
                'trend_direction': 'increasing' if trend > 0.1 else 'decreasing' if trend < -0.1 else 'stable'
            }
        
        # Identify emerging threats
        emerging = [
            vuln_type for vuln_type, data in forecasts.items()
            if data['trend'] > 0.3  # 30% growth
        ]
        
        # Identify declining threats
        declining = [
            vuln_type for vuln_type, data in forecasts.items()
            if data['trend'] < -0.3  # 30% decline
        ]
        
        return {
            'forecast_days': days,
            'vulnerability_types': forecasts,
            'emerging_threats': emerging,
            'declining_threats': declining,
            'most_common_forecasted': max(forecasts.items(), key=lambda x: x[1]['forecasted_count'])[0] if forecasts else None
        }
    
    def forecast_severity_distribution(self, days_ahead: Optional[int] = None) -> Dict[str, Any]:
        """
        Forecast severity distribution.
        
        Args:
            days_ahead: Number of days to forecast
            
        Returns:
            Dictionary with severity forecast
        """
        days = days_ahead or self.forecast_days
        
        if not self.severity_trends:
            return {'error': 'No historical data available'}
        
        # Calculate current distribution
        current_avg = statistics.mean(self.severity_trends)
        current_std = statistics.stdev(self.severity_trends) if len(self.severity_trends) > 1 else 0.0
        
        # Calculate trend
        if len(self.severity_trends) >= 14:
            recent_avg = statistics.mean(self.severity_trends[-7:])
            older_avg = statistics.mean(self.severity_trends[-14:-7])
            trend = recent_avg - older_avg
        else:
            trend = 0.0
        
        # Forecast average severity
        forecasted_avg = current_avg + (trend * days / 7)
        forecasted_avg = max(0.0, min(10.0, forecasted_avg))
        
        # Estimate distribution
        critical_rate = sum(1 for s in self.severity_trends if s >= 9.0) / len(self.severity_trends)
        high_rate = sum(1 for s in self.severity_trends if 7.0 <= s < 9.0) / len(self.severity_trends)
        medium_rate = sum(1 for s in self.severity_trends if 4.0 <= s < 7.0) / len(self.severity_trends)
        low_rate = sum(1 for s in self.severity_trends if s < 4.0) / len(self.severity_trends)
        
        return {
            'forecast_days': days,
            'current_average_severity': current_avg,
            'forecasted_average_severity': forecasted_avg,
            'trend': trend,
            'trend_direction': 'increasing' if trend > 0.5 else 'decreasing' if trend < -0.5 else 'stable',
            'forecasted_distribution': {
                'critical': critical_rate,
                'high': high_rate,
                'medium': medium_rate,
                'low': low_rate
            },
            'confidence': self._calculate_forecast_confidence()
        }
    
    def identify_seasonal_patterns(self) -> Dict[str, Any]:
        """Identify seasonal patterns in submissions."""
        if len(self.historical_data) < 30:
            return {'error': 'Insufficient data for seasonal analysis'}
        
        # Group by day of week
        day_of_week_counts = defaultdict(int)
        for timestamp, _ in self.historical_data:
            day_of_week_counts[timestamp.weekday()] += 1
        
        # Group by hour
        hour_counts = defaultdict(int)
        for timestamp, _ in self.historical_data:
            hour_counts[timestamp.hour] += 1
        
        # Group by month
        month_counts = defaultdict(int)
        for timestamp, _ in self.historical_data:
            month_counts[timestamp.month] += 1
        
        # Find patterns
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        busiest_day = days[max(day_of_week_counts.items(), key=lambda x: x[1])[0]]
        quietest_day = days[min(day_of_week_counts.items(), key=lambda x: x[1])[0]]
        
        busiest_hour = max(hour_counts.items(), key=lambda x: x[1])[0]
        quietest_hour = min(hour_counts.items(), key=lambda x: x[1])[0]
        
        # Weekend vs weekday
        weekend_count = day_of_week_counts[5] + day_of_week_counts[6]
        weekday_count = sum(day_of_week_counts[i] for i in range(5))
        
        return {
            'day_of_week_pattern': {
                'busiest_day': busiest_day,
                'quietest_day': quietest_day,
                'weekend_vs_weekday': {
                    'weekend': weekend_count,
                    'weekday': weekday_count,
                    'weekend_percentage': weekend_count / (weekend_count + weekday_count) * 100
                }
            },
            'hourly_pattern': {
                'busiest_hour': busiest_hour,
                'quietest_hour': quietest_hour,
                'peak_hours': [h for h, c in hour_counts.items() if c > statistics.mean(hour_counts.values()) * 1.5]
            },
            'monthly_pattern': {
                'busiest_month': max(month_counts.items(), key=lambda x: x[1])[0] if month_counts else None,
                'quietest_month': min(month_counts.items(), key=lambda x: x[1])[0] if month_counts else None
            }
        }
    
    def _analyze_volume_trends(self):
        """Analyze submission volume trends."""
        if not self.historical_data:
            return
        
        # Group by day
        daily_counts = defaultdict(int)
        for timestamp, _ in self.historical_data:
            date = timestamp.date()
            daily_counts[date] += 1
        
        # Calculate statistics
        counts = list(daily_counts.values())
        if counts:
            self.volume_trend = {
                'daily_average': statistics.mean(counts),
                'std_dev': statistics.stdev(counts) if len(counts) > 1 else 0.0,
                'min': min(counts),
                'max': max(counts),
                'growth_rate': self._calculate_growth_rate(daily_counts)
            }
    
    def _analyze_type_trends(self):
        """Analyze vulnerability type trends."""
        if not self.historical_data:
            return
        
        # Group by week and type
        weekly_types = defaultdict(lambda: defaultdict(int))
        
        for timestamp, report in self.historical_data:
            week = timestamp.isocalendar()[1]
            year = timestamp.year
            week_key = f"{year}-W{week}"
            
            vuln_type = 'unknown'
            if hasattr(report, 'vulnerability_type') and report.vulnerability_type:
                vuln_type = report.vulnerability_type.lower()
            
            weekly_types[week_key][vuln_type] += 1
        
        # Build trends for each type
        all_types = set()
        for week_data in weekly_types.values():
            all_types.update(week_data.keys())
        
        for vuln_type in all_types:
            counts = [weekly_types[week].get(vuln_type, 0) for week in sorted(weekly_types.keys())]
            self.type_trends[vuln_type] = counts
    
    def _analyze_severity_trends(self):
        """Analyze severity trends."""
        # Extract severity scores over time
        for timestamp, report in self.historical_data:
            if hasattr(report, 'cvss_score') and report.cvss_score is not None:
                self.severity_trends.append(report.cvss_score)
    
    def _calculate_growth_rate(self, daily_counts: Dict) -> float:
        """Calculate growth rate from daily counts."""
        if len(daily_counts) < 7:
            return 0.0
        
        sorted_dates = sorted(daily_counts.keys())
        
        # Compare first week to last week
        first_week = sorted_dates[:7]
        last_week = sorted_dates[-7:]
        
        first_week_avg = statistics.mean([daily_counts[d] for d in first_week])
        last_week_avg = statistics.mean([daily_counts[d] for d in last_week])
        
        if first_week_avg == 0:
            return 0.0
        
        # Daily growth rate
        days_between = (sorted_dates[-1] - sorted_dates[0]).days
        if days_between == 0:
            return 0.0
        
        growth_rate = (last_week_avg - first_week_avg) / first_week_avg / days_between
        
        return growth_rate
    
    def _calculate_forecast_confidence(self) -> float:
        """Calculate confidence in forecast."""
        # Base confidence on amount of historical data
        data_points = len(self.historical_data)
        
        if data_points < 30:
            return 0.3
        elif data_points < 90:
            return 0.6
        elif data_points < 180:
            return 0.8
        else:
            return 0.9

