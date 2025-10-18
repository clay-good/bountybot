"""
Metrics Collection

Collects and tracks various metrics for monitoring and observability.
"""

import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from functools import wraps
import threading

logger = logging.getLogger(__name__)


@dataclass
class Metric:
    """Individual metric data point."""
    name: str
    value: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    labels: Dict[str, str] = field(default_factory=dict)
    metric_type: str = "gauge"  # gauge, counter, histogram


@dataclass
class MetricSummary:
    """Summary statistics for a metric."""
    count: int = 0
    sum: float = 0.0
    min: float = float('inf')
    max: float = float('-inf')
    avg: float = 0.0
    p50: float = 0.0
    p95: float = 0.0
    p99: float = 0.0


class MetricsCollector:
    """
    Collects and aggregates metrics for monitoring.
    
    Tracks:
    - Validation metrics (count, duration, success rate)
    - API metrics (requests, latency, errors)
    - AI provider metrics (requests, tokens, cost, latency)
    - Database metrics (queries, connections, latency)
    - System metrics (CPU, memory, disk)
    """
    
    def __init__(self, retention_hours: int = 24):
        """
        Initialize metrics collector.
        
        Args:
            retention_hours: How long to retain metrics in memory
        """
        self.retention_hours = retention_hours
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
        
        logger.info("Initialized MetricsCollector")
    
    # ==================== Core Metric Methods ====================
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric."""
        with self.lock:
            key = self._make_key(name, labels)
            self.counters[key] += value
            
            metric = Metric(
                name=name,
                value=value,
                labels=labels or {},
                metric_type="counter"
            )
            self.metrics[key].append(metric)
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric."""
        with self.lock:
            key = self._make_key(name, labels)
            self.gauges[key] = value
            
            metric = Metric(
                name=name,
                value=value,
                labels=labels or {},
                metric_type="gauge"
            )
            self.metrics[key].append(metric)
    
    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Observe a value for histogram metric."""
        with self.lock:
            key = self._make_key(name, labels)
            self.histograms[key].append(value)
            
            metric = Metric(
                name=name,
                value=value,
                labels=labels or {},
                metric_type="histogram"
            )
            self.metrics[key].append(metric)
    
    def _make_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        """Create a unique key for metric with labels."""
        if not labels:
            return name
        
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
    
    # ==================== Validation Metrics ====================
    
    def track_validation_start(self, report_id: str):
        """Track validation start."""
        self.increment_counter("validations_started_total")
        self.set_gauge(f"validation_in_progress:{report_id}", 1.0)
    
    def track_validation_complete(
        self,
        report_id: str,
        duration_seconds: float,
        verdict: str,
        confidence: float,
        success: bool = True
    ):
        """Track validation completion."""
        self.increment_counter("validations_completed_total", labels={"verdict": verdict})
        self.observe_histogram("validation_duration_seconds", duration_seconds)
        self.observe_histogram("validation_confidence", confidence)
        self.set_gauge(f"validation_in_progress:{report_id}", 0.0)
        
        if not success:
            self.increment_counter("validations_failed_total")
    
    def track_validation_error(self, error_type: str):
        """Track validation error."""
        self.increment_counter("validation_errors_total", labels={"error_type": error_type})
    
    # ==================== API Metrics ====================
    
    def track_api_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        duration_seconds: float
    ):
        """Track API request."""
        labels = {
            "method": method,
            "endpoint": endpoint,
            "status": str(status_code)
        }
        
        self.increment_counter("api_requests_total", labels=labels)
        self.observe_histogram("api_request_duration_seconds", duration_seconds, labels=labels)
        
        if status_code >= 500:
            self.increment_counter("api_errors_total", labels={"endpoint": endpoint})
        elif status_code >= 400:
            self.increment_counter("api_client_errors_total", labels={"endpoint": endpoint})
    
    # ==================== AI Provider Metrics ====================
    
    def track_ai_request(
        self,
        provider: str,
        model: str,
        duration_seconds: float,
        tokens_used: int,
        cost: float,
        success: bool = True
    ):
        """Track AI provider request."""
        labels = {"provider": provider, "model": model}
        
        self.increment_counter("ai_requests_total", labels=labels)
        self.observe_histogram("ai_request_duration_seconds", duration_seconds, labels=labels)
        self.increment_counter("ai_tokens_used_total", value=tokens_used, labels=labels)
        self.increment_counter("ai_cost_total", value=cost, labels=labels)
        
        if not success:
            self.increment_counter("ai_errors_total", labels=labels)
    
    # ==================== Database Metrics ====================
    
    def track_db_query(self, operation: str, duration_seconds: float, success: bool = True):
        """Track database query."""
        labels = {"operation": operation}
        
        self.increment_counter("db_queries_total", labels=labels)
        self.observe_histogram("db_query_duration_seconds", duration_seconds, labels=labels)
        
        if not success:
            self.increment_counter("db_errors_total", labels=labels)
    
    def set_db_connections(self, active: int, idle: int):
        """Set database connection pool metrics."""
        self.set_gauge("db_connections_active", active)
        self.set_gauge("db_connections_idle", idle)
    
    # ==================== System Metrics ====================
    
    def set_system_metrics(self, cpu_percent: float, memory_percent: float, disk_percent: float):
        """Set system resource metrics."""
        self.set_gauge("system_cpu_percent", cpu_percent)
        self.set_gauge("system_memory_percent", memory_percent)
        self.set_gauge("system_disk_percent", disk_percent)
    
    # ==================== Business Metrics ====================
    
    def track_report_processed(self, vulnerability_type: str, severity: str):
        """Track report processing."""
        self.increment_counter("reports_processed_total", labels={
            "vulnerability_type": vulnerability_type,
            "severity": severity
        })
    
    def track_duplicate_detected(self):
        """Track duplicate detection."""
        self.increment_counter("duplicates_detected_total")
    
    def track_false_positive_detected(self):
        """Track false positive detection."""
        self.increment_counter("false_positives_detected_total")
    
    # ==================== Query Methods ====================
    
    def get_counter(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        """Get counter value."""
        key = self._make_key(name, labels)
        return self.counters.get(key, 0.0)
    
    def get_gauge(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        """Get gauge value."""
        key = self._make_key(name, labels)
        return self.gauges.get(key, 0.0)
    
    def get_histogram_summary(self, name: str, labels: Optional[Dict[str, str]] = None) -> MetricSummary:
        """Get histogram summary statistics."""
        key = self._make_key(name, labels)
        values = self.histograms.get(key, [])
        
        if not values:
            return MetricSummary()
        
        sorted_values = sorted(values)
        count = len(sorted_values)
        
        summary = MetricSummary(
            count=count,
            sum=sum(sorted_values),
            min=sorted_values[0],
            max=sorted_values[-1],
            avg=sum(sorted_values) / count,
            p50=sorted_values[int(count * 0.5)],
            p95=sorted_values[int(count * 0.95)] if count > 1 else sorted_values[0],
            p99=sorted_values[int(count * 0.99)] if count > 1 else sorted_values[0]
        )
        
        return summary
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics as a dictionary."""
        with self.lock:
            return {
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "histograms": {
                    name: self.get_histogram_summary(name.split('{')[0], 
                                                     self._parse_labels(name))
                    for name in self.histograms.keys()
                }
            }
    
    def _parse_labels(self, key: str) -> Optional[Dict[str, str]]:
        """Parse labels from metric key."""
        if '{' not in key:
            return None
        
        label_str = key.split('{')[1].rstrip('}')
        if not label_str:
            return None
        
        labels = {}
        for pair in label_str.split(','):
            k, v = pair.split('=')
            labels[k] = v
        
        return labels
    
    def cleanup_old_metrics(self):
        """Remove metrics older than retention period."""
        cutoff = datetime.utcnow() - timedelta(hours=self.retention_hours)
        
        with self.lock:
            for key, metric_list in self.metrics.items():
                # Remove old metrics
                while metric_list and metric_list[0].timestamp < cutoff:
                    metric_list.popleft()


# Global metrics collector instance
metrics_collector = MetricsCollector()


# ==================== Decorators ====================

def track_validation(func):
    """Decorator to track validation metrics."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        report_id = kwargs.get('report_id', 'unknown')
        
        metrics_collector.track_validation_start(report_id)
        
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Extract metrics from result
            verdict = getattr(result, 'verdict', 'unknown')
            confidence = getattr(result, 'confidence', 0.0)
            
            metrics_collector.track_validation_complete(
                report_id, duration, verdict, confidence, success=True
            )
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            metrics_collector.track_validation_error(type(e).__name__)
            raise
    
    return wrapper


def track_api_request(func):
    """Decorator to track API request metrics."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        
        try:
            response = await func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Extract request info
            request = kwargs.get('request')
            if request:
                metrics_collector.track_api_request(
                    method=request.method,
                    endpoint=request.url.path,
                    status_code=getattr(response, 'status_code', 200),
                    duration_seconds=duration
                )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"API request error: {e}")
            raise
    
    return wrapper


def track_ai_request(provider: str, model: str):
    """Decorator to track AI request metrics."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Extract metrics from result
                tokens = getattr(result, 'tokens_used', 0)
                cost = getattr(result, 'cost', 0.0)
                
                metrics_collector.track_ai_request(
                    provider=provider,
                    model=model,
                    duration_seconds=duration,
                    tokens_used=tokens,
                    cost=cost,
                    success=True
                )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                metrics_collector.track_ai_request(
                    provider=provider,
                    model=model,
                    duration_seconds=duration,
                    tokens_used=0,
                    cost=0.0,
                    success=False
                )
                raise
        
        return wrapper
    return decorator

