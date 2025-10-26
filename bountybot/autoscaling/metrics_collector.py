"""
Auto-Scaling Metrics Collector

Collects and aggregates metrics for auto-scaling decisions.
"""

import logging
import time
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from collections import deque
from dataclasses import dataclass, field

# Optional psutil for resource monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ValidationMetrics:
    """Metrics for a single validation."""
    validation_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    success: bool = True
    error: Optional[str] = None


class AutoScalingMetricsCollector:
    """
    Collects metrics for auto-scaling decisions.
    
    Features:
    - Real-time metrics collection
    - Queue depth tracking
    - Latency monitoring
    - Throughput calculation
    - Resource usage tracking
    """
    
    def __init__(self, window_minutes: int = 5):
        """
        Initialize metrics collector.
        
        Args:
            window_minutes: Time window for metrics aggregation
        """
        self.window_minutes = window_minutes
        self.window_seconds = window_minutes * 60
        
        # Metrics storage
        self.active_validations: Dict[str, ValidationMetrics] = {}
        self.completed_validations: deque = deque(maxlen=1000)
        self.queue_depth_history: deque = deque(maxlen=1000)
        
        # Counters
        self.total_validations = 0
        self.total_successes = 0
        self.total_failures = 0
        
        # Start time
        self.start_time = datetime.utcnow()
        
        logger.info(f"Initialized AutoScalingMetricsCollector with window={window_minutes}min")
    
    def start_validation(self, validation_id: str):
        """
        Record start of validation.
        
        Args:
            validation_id: Unique validation identifier
        """
        metrics = ValidationMetrics(
            validation_id=validation_id,
            start_time=datetime.utcnow()
        )
        self.active_validations[validation_id] = metrics
        
        # Update queue depth
        self._record_queue_depth(len(self.active_validations))
    
    def end_validation(self, validation_id: str, success: bool = True, 
                      error: Optional[str] = None):
        """
        Record end of validation.
        
        Args:
            validation_id: Unique validation identifier
            success: Whether validation succeeded
            error: Error message if failed
        """
        if validation_id not in self.active_validations:
            logger.warning(f"Validation {validation_id} not found in active validations")
            return
        
        metrics = self.active_validations.pop(validation_id)
        metrics.end_time = datetime.utcnow()
        metrics.duration_seconds = (metrics.end_time - metrics.start_time).total_seconds()
        metrics.success = success
        metrics.error = error
        
        # Add to completed
        self.completed_validations.append(metrics)
        
        # Update counters
        self.total_validations += 1
        if success:
            self.total_successes += 1
        else:
            self.total_failures += 1
        
        # Update queue depth
        self._record_queue_depth(len(self.active_validations))
    
    def _record_queue_depth(self, depth: int):
        """Record queue depth with timestamp."""
        self.queue_depth_history.append({
            'timestamp': datetime.utcnow(),
            'depth': depth
        })
    
    def get_current_metrics(self) -> Dict:
        """
        Get current metrics for scaling decisions.
        
        Returns:
            Dictionary with current metrics
        """
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.window_seconds)
        
        # Get recent completed validations
        recent_validations = [
            v for v in self.completed_validations
            if v.end_time and v.end_time >= window_start
        ]
        
        # Calculate metrics
        queue_depth = len(self.active_validations)
        
        if recent_validations:
            # Validations per minute
            time_span = (now - recent_validations[0].end_time).total_seconds() / 60.0
            validations_per_minute = len(recent_validations) / max(time_span, 1.0)
            
            # Average latency
            latencies = [v.duration_seconds for v in recent_validations]
            avg_latency = sum(latencies) / len(latencies)
            max_latency = max(latencies)
            min_latency = min(latencies)
            
            # Success rate
            successes = sum(1 for v in recent_validations if v.success)
            success_rate = successes / len(recent_validations)
        else:
            validations_per_minute = 0.0
            avg_latency = 0.0
            max_latency = 0.0
            min_latency = 0.0
            success_rate = 1.0
        
        # Get resource usage (if psutil available)
        if PSUTIL_AVAILABLE:
            cpu_usage = psutil.cpu_percent(interval=0.1)
            memory_info = psutil.virtual_memory()
            memory_usage = memory_info.percent
        else:
            cpu_usage = 0.0
            memory_usage = 0.0
        
        return {
            'timestamp': now.isoformat(),
            'queue_depth': queue_depth,
            'validations_per_minute': validations_per_minute,
            'avg_latency_seconds': avg_latency,
            'max_latency_seconds': max_latency,
            'min_latency_seconds': min_latency,
            'success_rate': success_rate,
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'active_validations': len(self.active_validations),
            'window_minutes': self.window_minutes
        }
    
    def get_queue_depth_trend(self) -> str:
        """
        Get queue depth trend (increasing/decreasing/stable).
        
        Returns:
            Trend description
        """
        if len(self.queue_depth_history) < 10:
            return "insufficient_data"
        
        # Get recent depths
        recent = list(self.queue_depth_history)[-10:]
        depths = [d['depth'] for d in recent]
        
        # Calculate trend
        first_half = sum(depths[:5]) / 5
        second_half = sum(depths[5:]) / 5
        
        if second_half > first_half * 1.2:
            return "increasing"
        elif second_half < first_half * 0.8:
            return "decreasing"
        else:
            return "stable"
    
    def get_latency_trend(self) -> str:
        """
        Get latency trend (increasing/decreasing/stable).
        
        Returns:
            Trend description
        """
        if len(self.completed_validations) < 10:
            return "insufficient_data"
        
        # Get recent latencies
        recent = list(self.completed_validations)[-10:]
        latencies = [v.duration_seconds for v in recent]
        
        # Calculate trend
        first_half = sum(latencies[:5]) / 5
        second_half = sum(latencies[5:]) / 5
        
        if second_half > first_half * 1.2:
            return "increasing"
        elif second_half < first_half * 0.8:
            return "decreasing"
        else:
            return "stable"
    
    def get_statistics(self) -> Dict:
        """
        Get comprehensive statistics.
        
        Returns:
            Dictionary with statistics
        """
        uptime = (datetime.utcnow() - self.start_time).total_seconds()
        
        current_metrics = self.get_current_metrics()
        
        return {
            'uptime_seconds': uptime,
            'total_validations': self.total_validations,
            'total_successes': self.total_successes,
            'total_failures': self.total_failures,
            'overall_success_rate': self.total_successes / max(self.total_validations, 1),
            'current_metrics': current_metrics,
            'queue_depth_trend': self.get_queue_depth_trend(),
            'latency_trend': self.get_latency_trend(),
            'active_validations': len(self.active_validations),
            'completed_validations': len(self.completed_validations)
        }
    
    def reset(self):
        """Reset all metrics."""
        self.active_validations.clear()
        self.completed_validations.clear()
        self.queue_depth_history.clear()
        self.total_validations = 0
        self.total_successes = 0
        self.total_failures = 0
        self.start_time = datetime.utcnow()
        logger.info("Metrics reset")
    
    def export_metrics(self) -> Dict:
        """
        Export metrics for external monitoring.
        
        Returns:
            Dictionary with exportable metrics
        """
        stats = self.get_statistics()
        
        return {
            'bountybot_autoscaling_queue_depth': stats['current_metrics']['queue_depth'],
            'bountybot_autoscaling_validations_per_minute': stats['current_metrics']['validations_per_minute'],
            'bountybot_autoscaling_avg_latency_seconds': stats['current_metrics']['avg_latency_seconds'],
            'bountybot_autoscaling_success_rate': stats['current_metrics']['success_rate'],
            'bountybot_autoscaling_cpu_usage': stats['current_metrics']['cpu_usage'],
            'bountybot_autoscaling_memory_usage': stats['current_metrics']['memory_usage'],
            'bountybot_autoscaling_total_validations': stats['total_validations'],
            'bountybot_autoscaling_total_successes': stats['total_successes'],
            'bountybot_autoscaling_total_failures': stats['total_failures'],
            'bountybot_autoscaling_uptime_seconds': stats['uptime_seconds']
        }


# Global metrics collector instance
_metrics_collector: Optional[AutoScalingMetricsCollector] = None


def get_metrics_collector() -> AutoScalingMetricsCollector:
    """Get global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = AutoScalingMetricsCollector()
    return _metrics_collector


def reset_metrics_collector():
    """Reset global metrics collector."""
    global _metrics_collector
    _metrics_collector = None

