"""
Prometheus Metrics Exporter

Exports metrics in Prometheus format for monitoring and alerting.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

from .metrics import metrics_collector, MetricSummary

logger = logging.getLogger(__name__)


class PrometheusExporter:
    """
    Exports metrics in Prometheus text format.
    
    Supports:
    - Counter metrics
    - Gauge metrics
    - Histogram metrics with quantiles
    - Labels for dimensional metrics
    """
    
    def __init__(self):
        """Initialize Prometheus exporter."""
        self.namespace = "bountybot"
        logger.info("Initialized PrometheusExporter")
    
    def export_metrics(self) -> str:
        """
        Export all metrics in Prometheus text format.
        
        Returns:
            Metrics in Prometheus exposition format
        """
        lines = []
        
        # Add header
        lines.append("# BountyBot Metrics")
        lines.append(f"# Generated at {datetime.utcnow().isoformat()}")
        lines.append("")
        
        # Export counters
        lines.extend(self._export_counters())
        lines.append("")
        
        # Export gauges
        lines.extend(self._export_gauges())
        lines.append("")
        
        # Export histograms
        lines.extend(self._export_histograms())
        
        return "\n".join(lines)
    
    def _export_counters(self) -> List[str]:
        """Export counter metrics."""
        lines = []
        
        counters = metrics_collector.counters
        
        # Group by metric name
        grouped = {}
        for key, value in counters.items():
            metric_name = key.split('{')[0]
            if metric_name not in grouped:
                grouped[metric_name] = []
            grouped[metric_name].append((key, value))
        
        # Export each metric
        for metric_name, entries in grouped.items():
            full_name = f"{self.namespace}_{metric_name}"
            
            # Add HELP and TYPE
            lines.append(f"# HELP {full_name} Counter metric")
            lines.append(f"# TYPE {full_name} counter")
            
            # Add values
            for key, value in entries:
                labels = self._extract_labels(key)
                if labels:
                    label_str = self._format_labels(labels)
                    lines.append(f"{full_name}{{{label_str}}} {value}")
                else:
                    lines.append(f"{full_name} {value}")
        
        return lines
    
    def _export_gauges(self) -> List[str]:
        """Export gauge metrics."""
        lines = []
        
        gauges = metrics_collector.gauges
        
        # Group by metric name
        grouped = {}
        for key, value in gauges.items():
            metric_name = key.split('{')[0]
            if metric_name not in grouped:
                grouped[metric_name] = []
            grouped[metric_name].append((key, value))
        
        # Export each metric
        for metric_name, entries in grouped.items():
            full_name = f"{self.namespace}_{metric_name}"
            
            # Add HELP and TYPE
            lines.append(f"# HELP {full_name} Gauge metric")
            lines.append(f"# TYPE {full_name} gauge")
            
            # Add values
            for key, value in entries:
                labels = self._extract_labels(key)
                if labels:
                    label_str = self._format_labels(labels)
                    lines.append(f"{full_name}{{{label_str}}} {value}")
                else:
                    lines.append(f"{full_name} {value}")
        
        return lines
    
    def _export_histograms(self) -> List[str]:
        """Export histogram metrics."""
        lines = []
        
        histograms = metrics_collector.histograms
        
        # Group by metric name
        grouped = {}
        for key in histograms.keys():
            metric_name = key.split('{')[0]
            if metric_name not in grouped:
                grouped[metric_name] = []
            grouped[metric_name].append(key)
        
        # Export each metric
        for metric_name, keys in grouped.items():
            full_name = f"{self.namespace}_{metric_name}"
            
            # Add HELP and TYPE
            lines.append(f"# HELP {full_name} Histogram metric")
            lines.append(f"# TYPE {full_name} histogram")
            
            # Add histogram data for each label combination
            for key in keys:
                labels = self._extract_labels(key)
                summary = metrics_collector.get_histogram_summary(
                    metric_name,
                    labels
                )
                
                base_labels = self._format_labels(labels) if labels else ""
                
                # Add quantiles
                quantiles = [
                    ("0.5", summary.p50),
                    ("0.95", summary.p95),
                    ("0.99", summary.p99)
                ]
                
                for quantile, value in quantiles:
                    if base_labels:
                        label_str = f'{base_labels},quantile="{quantile}"'
                    else:
                        label_str = f'quantile="{quantile}"'
                    
                    lines.append(f"{full_name}{{{label_str}}} {value}")
                
                # Add sum and count
                if base_labels:
                    lines.append(f"{full_name}_sum{{{base_labels}}} {summary.sum}")
                    lines.append(f"{full_name}_count{{{base_labels}}} {summary.count}")
                else:
                    lines.append(f"{full_name}_sum {summary.sum}")
                    lines.append(f"{full_name}_count {summary.count}")
        
        return lines
    
    def _extract_labels(self, key: str) -> Optional[Dict[str, str]]:
        """Extract labels from metric key."""
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
    
    def _format_labels(self, labels: Dict[str, str]) -> str:
        """Format labels for Prometheus."""
        return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    
    def export_health_metrics(self) -> str:
        """Export health check metrics."""
        from .health import health_checker, HealthStatus
        
        lines = []
        
        # Get system health
        health = health_checker.check_all()
        
        # Export overall health
        lines.append("# HELP bountybot_health_status Overall system health (1=healthy, 0.5=degraded, 0=unhealthy)")
        lines.append("# TYPE bountybot_health_status gauge")
        
        status_value = {
            HealthStatus.HEALTHY: 1.0,
            HealthStatus.DEGRADED: 0.5,
            HealthStatus.UNHEALTHY: 0.0,
            HealthStatus.UNKNOWN: -1.0
        }.get(health.status, -1.0)
        
        lines.append(f"bountybot_health_status {status_value}")
        lines.append("")
        
        # Export component health
        lines.append("# HELP bountybot_component_health Component health status (1=healthy, 0.5=degraded, 0=unhealthy)")
        lines.append("# TYPE bountybot_component_health gauge")
        
        for component_name, component in health.components.items():
            status_value = {
                HealthStatus.HEALTHY: 1.0,
                HealthStatus.DEGRADED: 0.5,
                HealthStatus.UNHEALTHY: 0.0,
                HealthStatus.UNKNOWN: -1.0
            }.get(component.status, -1.0)
            
            lines.append(f'bountybot_component_health{{component="{component_name}"}} {status_value}')
        
        lines.append("")
        
        # Export uptime
        lines.append("# HELP bountybot_uptime_seconds System uptime in seconds")
        lines.append("# TYPE bountybot_uptime_seconds counter")
        lines.append(f"bountybot_uptime_seconds {health.uptime_seconds}")
        
        return "\n".join(lines)
    
    def export_alert_metrics(self) -> str:
        """Export alert metrics."""
        from .alerts import alert_manager, AlertSeverity
        
        lines = []
        
        summary = alert_manager.get_alert_summary()
        
        # Export total alerts
        lines.append("# HELP bountybot_alerts_total Total number of alerts")
        lines.append("# TYPE bountybot_alerts_total gauge")
        lines.append(f"bountybot_alerts_total {summary['total_alerts']}")
        lines.append("")
        
        # Export active alerts
        lines.append("# HELP bountybot_alerts_active Number of active alerts")
        lines.append("# TYPE bountybot_alerts_active gauge")
        lines.append(f"bountybot_alerts_active {summary['active_alerts']}")
        lines.append("")
        
        # Export alerts by severity
        lines.append("# HELP bountybot_alerts_by_severity Number of active alerts by severity")
        lines.append("# TYPE bountybot_alerts_by_severity gauge")
        
        for severity, count in summary['by_severity'].items():
            lines.append(f'bountybot_alerts_by_severity{{severity="{severity}"}} {count}')
        
        return "\n".join(lines)
    
    def export_all(self) -> str:
        """Export all metrics including health and alerts."""
        sections = [
            self.export_metrics(),
            "",
            self.export_health_metrics(),
            "",
            self.export_alert_metrics()
        ]
        
        return "\n".join(sections)


# Global Prometheus exporter instance
prometheus_exporter = PrometheusExporter()

