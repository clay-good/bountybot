"""
Monitoring System Demo

Demonstrates the monitoring and observability features of BountyBot.
"""

import time
import random
from datetime import datetime

from bountybot.monitoring import (
    metrics_collector,
    health_checker,
    alert_manager,
    prometheus_exporter,
    AlertSeverity
)


def print_section(title: str):
    """Print a section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_metrics_collection():
    """Demonstrate metrics collection."""
    print_section("1. METRICS COLLECTION")
    
    print("📊 Collecting various metrics...\n")
    
    # Simulate validation metrics
    print("Validation Metrics:")
    for i in range(5):
        metrics_collector.track_validation_start(f"report_{i}")
        time.sleep(0.1)
        
        verdict = random.choice(["valid", "invalid", "uncertain"])
        confidence = random.uniform(0.6, 0.95)
        duration = random.uniform(0.5, 3.0)
        
        metrics_collector.track_validation_complete(
            report_id=f"report_{i}",
            duration_seconds=duration,
            verdict=verdict,
            confidence=confidence,
            success=True
        )
        
        print(f"  ✓ Report {i}: {verdict} (confidence: {confidence:.2f}, duration: {duration:.2f}s)")
    
    # Simulate API metrics
    print("\nAPI Metrics:")
    endpoints = ["/api/validate", "/api/reports", "/api/health"]
    methods = ["GET", "POST"]
    
    for i in range(10):
        endpoint = random.choice(endpoints)
        method = random.choice(methods)
        status = random.choice([200, 200, 200, 400, 500])
        duration = random.uniform(0.1, 1.0)
        
        metrics_collector.track_api_request(
            method=method,
            endpoint=endpoint,
            status_code=status,
            duration_seconds=duration
        )
        
        print(f"  ✓ {method} {endpoint} - {status} ({duration:.3f}s)")
    
    # Simulate AI provider metrics
    print("\nAI Provider Metrics:")
    for i in range(3):
        metrics_collector.track_ai_request(
            provider="anthropic",
            model="claude-3-sonnet",
            duration_seconds=random.uniform(1.0, 3.0),
            tokens_used=random.randint(500, 2000),
            cost=random.uniform(0.01, 0.10),
            success=True
        )
        print(f"  ✓ AI request {i+1} completed")
    
    # Simulate business metrics
    print("\nBusiness Metrics:")
    vuln_types = ["xss", "sqli", "csrf", "rce"]
    severities = ["low", "medium", "high", "critical"]
    
    for i in range(8):
        vuln = random.choice(vuln_types)
        severity = random.choice(severities)
        metrics_collector.track_report_processed(vuln, severity)
        print(f"  ✓ Processed {vuln} report (severity: {severity})")
    
    # Add some duplicates and false positives
    metrics_collector.track_duplicate_detected()
    metrics_collector.track_duplicate_detected()
    metrics_collector.track_false_positive_detected()
    
    print("\n✅ Metrics collection complete!")


def demo_metrics_query():
    """Demonstrate metrics querying."""
    print_section("2. METRICS QUERY")
    
    print("📈 Querying collected metrics...\n")
    
    # Query counters
    print("Counters:")
    validations = metrics_collector.get_counter("validations_started_total")
    print(f"  • Total validations started: {validations}")
    
    api_requests = metrics_collector.get_counter("api_requests_total", {
        "method": "GET",
        "endpoint": "/api/validate",
        "status": "200"
    })
    print(f"  • Successful GET /api/validate requests: {api_requests}")
    
    duplicates = metrics_collector.get_counter("duplicates_detected_total")
    print(f"  • Duplicates detected: {duplicates}")
    
    false_positives = metrics_collector.get_counter("false_positives_detected_total")
    print(f"  • False positives detected: {false_positives}")
    
    # Query histograms
    print("\nHistogram Summaries:")
    
    validation_summary = metrics_collector.get_histogram_summary("validation_duration_seconds")
    if validation_summary.count > 0:
        print(f"  • Validation Duration:")
        print(f"    - Count: {validation_summary.count}")
        print(f"    - Average: {validation_summary.avg:.3f}s")
        print(f"    - Min: {validation_summary.min:.3f}s")
        print(f"    - Max: {validation_summary.max:.3f}s")
        print(f"    - P50: {validation_summary.p50:.3f}s")
        print(f"    - P95: {validation_summary.p95:.3f}s")
        print(f"    - P99: {validation_summary.p99:.3f}s")
    
    api_summary = metrics_collector.get_histogram_summary("api_request_duration_seconds")
    if api_summary.count > 0:
        print(f"\n  • API Request Duration:")
        print(f"    - Count: {api_summary.count}")
        print(f"    - Average: {api_summary.avg:.3f}s")
        print(f"    - P95: {api_summary.p95:.3f}s")
    
    print("\n✅ Metrics query complete!")


def demo_health_checks():
    """Demonstrate health checking."""
    print_section("3. HEALTH CHECKS")
    
    print("🏥 Checking system health...\n")
    
    # Check individual components
    print("Component Health:")
    
    disk_health = health_checker.check_disk_space()
    print(f"  • Disk Space: {disk_health.status.value.upper()}")
    print(f"    - {disk_health.message}")
    if disk_health.metadata:
        print(f"    - Free: {disk_health.metadata.get('free_gb', 0):.1f} GB")
    
    memory_health = health_checker.check_memory()
    print(f"\n  • Memory: {memory_health.status.value.upper()}")
    print(f"    - {memory_health.message}")
    
    db_health = health_checker.check_database()
    print(f"\n  • Database: {db_health.status.value.upper()}")
    print(f"    - {db_health.message}")
    
    ai_health = health_checker.check_ai_provider()
    print(f"\n  • AI Provider: {ai_health.status.value.upper()}")
    print(f"    - {ai_health.message}")
    
    # Check overall system health
    print("\nOverall System Health:")
    system_health = health_checker.check_all()
    
    print(f"  • Status: {system_health.status.value.upper()}")
    print(f"  • Uptime: {system_health.uptime_seconds:.1f} seconds")
    print(f"  • Components checked: {len(system_health.components)}")
    print(f"  • Timestamp: {system_health.timestamp.isoformat()}")
    
    # Health status indicator
    if system_health.is_healthy():
        print("\n  ✅ System is HEALTHY")
    elif system_health.is_degraded():
        print("\n  ⚠️  System is DEGRADED")
    else:
        print("\n  ❌ System is UNHEALTHY")
    
    print("\n✅ Health checks complete!")


def demo_alerts():
    """Demonstrate alert management."""
    print_section("4. ALERT MANAGEMENT")
    
    print("🚨 Managing alerts...\n")
    
    # Create various alerts
    print("Creating Alerts:")
    
    alert1 = alert_manager.create_alert(
        severity=AlertSeverity.INFO,
        title="System Started",
        message="BountyBot monitoring system has started"
    )
    print(f"  ✓ INFO: {alert1.title}")
    
    alert2 = alert_manager.create_alert(
        severity=AlertSeverity.WARNING,
        title="High Memory Usage",
        message="Memory usage is above 80%"
    )
    print(f"  ✓ WARNING: {alert2.title}")
    
    alert3 = alert_manager.create_alert(
        severity=AlertSeverity.ERROR,
        title="API Error Rate High",
        message="API error rate exceeded threshold"
    )
    print(f"  ✓ ERROR: {alert3.title}")
    
    alert4 = alert_manager.create_alert(
        severity=AlertSeverity.CRITICAL,
        title="Database Connection Lost",
        message="Cannot connect to database"
    )
    print(f"  ✓ CRITICAL: {alert4.title}")
    
    # Query alerts
    print("\nActive Alerts:")
    active_alerts = alert_manager.get_active_alerts()
    print(f"  • Total active: {len(active_alerts)}")
    
    for alert in active_alerts:
        print(f"    - [{alert.severity.value.upper()}] {alert.title}")
    
    # Resolve some alerts
    print("\nResolving Alerts:")
    alert_manager.resolve_alert(alert1.alert_id)
    print(f"  ✓ Resolved: {alert1.title}")
    
    alert_manager.resolve_alert(alert4.alert_id)
    print(f"  ✓ Resolved: {alert4.title}")
    
    # Get alert summary
    print("\nAlert Summary:")
    summary = alert_manager.get_alert_summary()
    print(f"  • Total alerts: {summary['total_alerts']}")
    print(f"  • Active alerts: {summary['active_alerts']}")
    print(f"  • Resolved alerts: {summary['resolved_alerts']}")
    print(f"  • By severity:")
    print(f"    - Critical: {summary['by_severity']['critical']}")
    print(f"    - Error: {summary['by_severity']['error']}")
    print(f"    - Warning: {summary['by_severity']['warning']}")
    print(f"    - Info: {summary['by_severity']['info']}")
    
    print("\n✅ Alert management complete!")


def demo_prometheus_export():
    """Demonstrate Prometheus metrics export."""
    print_section("5. PROMETHEUS EXPORT")
    
    print("📤 Exporting metrics in Prometheus format...\n")
    
    # Export metrics
    print("Exporting Metrics:")
    metrics_output = prometheus_exporter.export_metrics()
    
    # Show sample of output
    lines = metrics_output.split('\n')
    print(f"  • Total lines: {len(lines)}")
    print(f"  • Sample output (first 20 lines):\n")
    
    for line in lines[:20]:
        if line.strip():
            print(f"    {line}")
    
    # Export health metrics
    print("\n\nExporting Health Metrics:")
    health_output = prometheus_exporter.export_health_metrics()
    
    lines = health_output.split('\n')
    print(f"  • Total lines: {len(lines)}")
    print(f"  • Sample output:\n")
    
    for line in lines[:15]:
        if line.strip():
            print(f"    {line}")
    
    # Export alert metrics
    print("\n\nExporting Alert Metrics:")
    alert_output = prometheus_exporter.export_alert_metrics()
    
    lines = alert_output.split('\n')
    for line in lines:
        if line.strip():
            print(f"    {line}")
    
    print("\n✅ Prometheus export complete!")


def demo_summary():
    """Show summary of monitoring features."""
    print_section("6. MONITORING SYSTEM SUMMARY")
    
    print("🎯 BountyBot Monitoring & Observability Features:\n")
    
    features = [
        ("Metrics Collection", [
            "Counter metrics (cumulative values)",
            "Gauge metrics (point-in-time values)",
            "Histogram metrics (distributions with quantiles)",
            "Labels for dimensional metrics",
            "Validation, API, AI, database, and business metrics",
            "Thread-safe collection",
            "Automatic metric retention"
        ]),
        ("Health Checking", [
            "Component health monitoring",
            "Database connectivity checks",
            "AI provider availability checks",
            "Disk space monitoring",
            "Memory usage monitoring",
            "Integration health checks",
            "Overall system health status",
            "Response time tracking"
        ]),
        ("Alert Management", [
            "Multiple severity levels (INFO, WARNING, ERROR, CRITICAL)",
            "Alert rules with conditions",
            "Alert cooldown to prevent spam",
            "Multiple notification channels",
            "Alert resolution tracking",
            "Alert history and querying",
            "Alert summary statistics",
            "Custom alert handlers"
        ]),
        ("Prometheus Export", [
            "Standard Prometheus text format",
            "Counter, gauge, and histogram support",
            "Label support for dimensional metrics",
            "Quantile calculations (P50, P95, P99)",
            "Health metrics export",
            "Alert metrics export",
            "Ready for Prometheus scraping"
        ])
    ]
    
    for feature_name, items in features:
        print(f"✅ {feature_name}:")
        for item in items:
            print(f"   • {item}")
        print()
    
    print("📊 Integration Points:")
    print("   • Prometheus + Grafana for visualization")
    print("   • AlertManager for alert routing")
    print("   • PagerDuty for on-call notifications")
    print("   • Slack for team notifications")
    print("   • Email for alert delivery")
    print("   • Webhooks for custom integrations")
    
    print("\n🚀 Production Ready:")
    print("   • Thread-safe operations")
    print("   • Low overhead metrics collection")
    print("   • Configurable retention periods")
    print("   • Automatic cleanup of old data")
    print("   • Comprehensive test coverage")
    print("   • Enterprise-grade monitoring")


def main():
    """Run monitoring demo."""
    print("\n" + "=" * 80)
    print("  🎯 BOUNTYBOT MONITORING & OBSERVABILITY DEMO")
    print("=" * 80)
    
    try:
        # Run demos
        demo_metrics_collection()
        time.sleep(0.5)
        
        demo_metrics_query()
        time.sleep(0.5)
        
        demo_health_checks()
        time.sleep(0.5)
        
        demo_alerts()
        time.sleep(0.5)
        
        demo_prometheus_export()
        time.sleep(0.5)
        
        demo_summary()
        
        print("\n" + "=" * 80)
        print("  ✅ DEMO COMPLETE!")
        print("=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

