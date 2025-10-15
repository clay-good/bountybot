import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class TrendType(Enum):
    """Types of trends that can be analyzed."""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"


@dataclass
class TrendData:
    """Data point for trend analysis."""
    
    timestamp: datetime
    value: float
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'value': self.value,
            'label': self.label,
            'metadata': self.metadata
        }


@dataclass
class TrendAnalysis:
    """Result of trend analysis."""
    
    trend_type: TrendType
    direction: str  # "up", "down", "flat"
    change_percentage: float
    volatility: float
    data_points: List[TrendData]
    start_value: float
    end_value: float
    average_value: float
    min_value: float
    max_value: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'trend_type': self.trend_type.value,
            'direction': self.direction,
            'change_percentage': round(self.change_percentage, 2),
            'volatility': round(self.volatility, 2),
            'statistics': {
                'start_value': round(self.start_value, 2),
                'end_value': round(self.end_value, 2),
                'average_value': round(self.average_value, 2),
                'min_value': round(self.min_value, 2),
                'max_value': round(self.max_value, 2)
            },
            'data_points': [dp.to_dict() for dp in self.data_points]
        }


class TrendAnalyzer:
    """
    Analyzes trends in bug bounty data over time.
    
    Provides insights into:
    - Report volume trends
    - Severity distribution changes
    - Researcher performance trends
    - Cost trends
    - Quality trends
    """
    
    def __init__(self):
        self.data_points: Dict[str, List[TrendData]] = defaultdict(list)
    
    def add_data_point(self, metric_name: str, value: float, timestamp: Optional[datetime] = None, 
                       label: str = "", metadata: Optional[Dict[str, Any]] = None):
        """
        Add a data point for trend analysis.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            timestamp: Timestamp (defaults to now)
            label: Optional label
            metadata: Optional metadata
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        data_point = TrendData(
            timestamp=timestamp,
            value=value,
            label=label,
            metadata=metadata or {}
        )
        
        self.data_points[metric_name].append(data_point)
        
        # Sort by timestamp
        self.data_points[metric_name].sort(key=lambda dp: dp.timestamp)
    
    def analyze_trend(self, metric_name: str, time_window: Optional[timedelta] = None) -> Optional[TrendAnalysis]:
        """
        Analyze trend for a specific metric.
        
        Args:
            metric_name: Name of the metric to analyze
            time_window: Optional time window to limit analysis
        
        Returns:
            TrendAnalysis object or None if insufficient data
        """
        if metric_name not in self.data_points:
            logger.warning(f"No data points for metric: {metric_name}")
            return None
        
        data = self.data_points[metric_name]
        
        # Filter by time window if specified
        if time_window:
            cutoff_time = datetime.now() - time_window
            data = [dp for dp in data if dp.timestamp >= cutoff_time]
        
        if len(data) < 2:
            logger.warning(f"Insufficient data points for trend analysis: {len(data)}")
            return None
        
        # Calculate statistics
        values = [dp.value for dp in data]
        start_value = values[0]
        end_value = values[-1]
        average_value = sum(values) / len(values)
        min_value = min(values)
        max_value = max(values)
        
        # Calculate change percentage
        if start_value != 0:
            change_percentage = ((end_value - start_value) / start_value) * 100
        else:
            change_percentage = 0.0
        
        # Calculate volatility (standard deviation)
        variance = sum((v - average_value) ** 2 for v in values) / len(values)
        volatility = variance ** 0.5
        
        # Determine trend type and direction
        trend_type, direction = self._classify_trend(change_percentage, volatility, average_value)
        
        return TrendAnalysis(
            trend_type=trend_type,
            direction=direction,
            change_percentage=change_percentage,
            volatility=volatility,
            data_points=data,
            start_value=start_value,
            end_value=end_value,
            average_value=average_value,
            min_value=min_value,
            max_value=max_value
        )
    
    def _classify_trend(self, change_percentage: float, volatility: float, 
                       average_value: float) -> Tuple[TrendType, str]:
        """
        Classify trend based on change and volatility.
        
        Args:
            change_percentage: Percentage change from start to end
            volatility: Standard deviation of values
            average_value: Average value
        
        Returns:
            Tuple of (TrendType, direction)
        """
        # Calculate relative volatility
        if average_value != 0:
            relative_volatility = (volatility / average_value) * 100
        else:
            relative_volatility = 0
        
        # Determine direction
        if change_percentage > 5:
            direction = "up"
        elif change_percentage < -5:
            direction = "down"
        else:
            direction = "flat"
        
        # Determine trend type
        if relative_volatility > 30:
            trend_type = TrendType.VOLATILE
        elif abs(change_percentage) > 20:
            trend_type = TrendType.INCREASING if change_percentage > 0 else TrendType.DECREASING
        elif abs(change_percentage) < 5:
            trend_type = TrendType.STABLE
        else:
            trend_type = TrendType.INCREASING if change_percentage > 0 else TrendType.DECREASING
        
        return trend_type, direction
    
    def get_time_series(self, metric_name: str, interval: timedelta = timedelta(days=1),
                       time_window: Optional[timedelta] = None) -> List[TrendData]:
        """
        Get time series data aggregated by interval.
        
        Args:
            metric_name: Name of the metric
            interval: Aggregation interval
            time_window: Optional time window
        
        Returns:
            List of aggregated TrendData points
        """
        if metric_name not in self.data_points:
            return []
        
        data = self.data_points[metric_name]
        
        # Filter by time window
        if time_window:
            cutoff_time = datetime.now() - time_window
            data = [dp for dp in data if dp.timestamp >= cutoff_time]
        
        if not data:
            return []
        
        # Group by interval
        grouped: Dict[datetime, List[float]] = defaultdict(list)
        
        for dp in data:
            # Round timestamp to interval
            interval_start = self._round_to_interval(dp.timestamp, interval)
            grouped[interval_start].append(dp.value)
        
        # Aggregate
        result = []
        for timestamp in sorted(grouped.keys()):
            values = grouped[timestamp]
            avg_value = sum(values) / len(values)
            result.append(TrendData(
                timestamp=timestamp,
                value=avg_value,
                label=f"{len(values)} samples",
                metadata={'count': len(values), 'min': min(values), 'max': max(values)}
            ))
        
        return result
    
    def _round_to_interval(self, timestamp: datetime, interval: timedelta) -> datetime:
        """Round timestamp to interval."""
        # Convert to seconds
        seconds = interval.total_seconds()
        
        # Round timestamp
        epoch = datetime(1970, 1, 1)
        timestamp_seconds = (timestamp - epoch).total_seconds()
        rounded_seconds = (timestamp_seconds // seconds) * seconds
        
        return epoch + timedelta(seconds=rounded_seconds)
    
    def compare_periods(self, metric_name: str, period1: Tuple[datetime, datetime],
                       period2: Tuple[datetime, datetime]) -> Dict[str, Any]:
        """
        Compare two time periods for a metric.
        
        Args:
            metric_name: Name of the metric
            period1: Tuple of (start, end) for first period
            period2: Tuple of (start, end) for second period
        
        Returns:
            Comparison results
        """
        if metric_name not in self.data_points:
            return {}
        
        data = self.data_points[metric_name]
        
        # Filter data for each period
        period1_data = [dp for dp in data if period1[0] <= dp.timestamp <= period1[1]]
        period2_data = [dp for dp in data if period2[0] <= dp.timestamp <= period2[1]]
        
        if not period1_data or not period2_data:
            return {'error': 'Insufficient data for comparison'}
        
        # Calculate statistics for each period
        period1_avg = sum(dp.value for dp in period1_data) / len(period1_data)
        period2_avg = sum(dp.value for dp in period2_data) / len(period2_data)
        
        # Calculate change
        if period1_avg != 0:
            change_percentage = ((period2_avg - period1_avg) / period1_avg) * 100
        else:
            change_percentage = 0.0
        
        return {
            'period1': {
                'start': period1[0].isoformat(),
                'end': period1[1].isoformat(),
                'average': round(period1_avg, 2),
                'count': len(period1_data)
            },
            'period2': {
                'start': period2[0].isoformat(),
                'end': period2[1].isoformat(),
                'average': round(period2_avg, 2),
                'count': len(period2_data)
            },
            'comparison': {
                'change_percentage': round(change_percentage, 2),
                'direction': 'increase' if change_percentage > 0 else 'decrease' if change_percentage < 0 else 'stable'
            }
        }
    
    def get_all_trends(self, time_window: Optional[timedelta] = None) -> Dict[str, TrendAnalysis]:
        """
        Get trend analysis for all metrics.
        
        Args:
            time_window: Optional time window
        
        Returns:
            Dictionary of metric_name -> TrendAnalysis
        """
        results = {}
        
        for metric_name in self.data_points.keys():
            analysis = self.analyze_trend(metric_name, time_window)
            if analysis:
                results[metric_name] = analysis
        
        return results
    
    def export_trends(self, time_window: Optional[timedelta] = None) -> Dict[str, Any]:
        """
        Export all trend analyses as dictionary.
        
        Args:
            time_window: Optional time window
        
        Returns:
            Dictionary with all trend data
        """
        trends = self.get_all_trends(time_window)
        
        return {
            'trends': {
                metric_name: analysis.to_dict()
                for metric_name, analysis in trends.items()
            },
            'summary': {
                'total_metrics': len(trends),
                'increasing_trends': sum(1 for a in trends.values() if a.trend_type == TrendType.INCREASING),
                'decreasing_trends': sum(1 for a in trends.values() if a.trend_type == TrendType.DECREASING),
                'stable_trends': sum(1 for a in trends.values() if a.trend_type == TrendType.STABLE),
                'volatile_trends': sum(1 for a in trends.values() if a.trend_type == TrendType.VOLATILE)
            }
        }

