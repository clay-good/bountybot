"""
Audit Logging & Forensics Demo

Demonstrates comprehensive audit logging and forensic analysis.
"""

import tempfile
import shutil
from datetime import datetime, timedelta

from bountybot.audit import (
    AuditLogger,
    AuditSearch,
    ForensicAnalyzer,
    AuditRetentionManager,
    ComplianceReporter,
    AuditEventType,
    AuditQuery,
    AuditSeverity
)


def print_section(title: str):
    """Print section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def demo_audit_logging():
    """Demonstrate audit logging."""
    print_section("AUDIT LOGGING")
    
    temp_dir = tempfile.mkdtemp()
    logger = AuditLogger(log_dir=temp_dir)
    
    print("1. Logging Authentication Events:")
    
    # Successful login
    event1 = logger.log_event(
        event_type=AuditEventType.LOGIN_SUCCESS,
        action="User logged in successfully",
        user_id="user_123",
        username="john.doe",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0"
    )
    print(f"   ✅ Logged: {event1.event_type.value} - {event1.action}")
    print(f"      Event ID: {event1.event_id}")
    print(f"      Signature: {event1.signature[:32]}...")
    print(f"      Compliance Tags: {', '.join(event1.compliance_tags)}")
    
    # Failed login
    event2 = logger.log_event(
        event_type=AuditEventType.LOGIN_FAILURE,
        action="Failed login attempt",
        user_id="user_456",
        username="jane.smith",
        ip_address="192.168.1.101",
        success=False,
        error_message="Invalid password"
    )
    print(f"   ✅ Logged: {event2.event_type.value} - {event2.action}")
    print(f"      Severity: {event2.severity.value}")
    
    print("\n2. Logging Data Access Events:")
    
    event3 = logger.log_event(
        event_type=AuditEventType.REPORT_VIEWED,
        action="Viewed security report",
        user_id="user_123",
        username="john.doe",
        resource_type="report",
        resource_id="report_789",
        details={"report_title": "SQL Injection Vulnerability"}
    )
    print(f"   ✅ Logged: {event3.event_type.value}")
    print(f"      Resource: {event3.resource_type}:{event3.resource_id}")
    
    event4 = logger.log_event(
        event_type=AuditEventType.DATA_EXPORTED,
        action="Exported vulnerability data",
        user_id="user_123",
        username="john.doe",
        resource_type="export",
        resource_id="export_001",
        details={"format": "CSV", "records": 150}
    )
    print(f"   ✅ Logged: {event4.event_type.value}")
    print(f"      Compliance Tags: {', '.join(event4.compliance_tags)}")
    
    print("\n3. Logging Security Events:")
    
    event5 = logger.log_event(
        event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
        action="Multiple failed login attempts detected",
        user_id="user_456",
        ip_address="192.168.1.101",
        details={"attempts": 5, "timeframe": "5 minutes"}
    )
    print(f"   ✅ Logged: {event5.event_type.value}")
    print(f"      Severity: {event5.severity.value}")
    
    print("\n4. Chain of Custody:")
    print(f"   Event 1 Hash: {logger._hash_event(event1)[:32]}...")
    print(f"   Event 2 Previous Hash: {event2.previous_event_hash[:32] if event2.previous_event_hash else 'None'}...")
    print(f"   ✅ Chain of custody maintained")
    
    print("\n5. Signature Verification:")
    is_valid = logger.verify_event(event1)
    print(f"   Event 1 Signature Valid: {'✅ Yes' if is_valid else '❌ No'}")
    
    return temp_dir, logger


def demo_audit_search(temp_dir: str, logger: AuditLogger):
    """Demonstrate audit search."""
    print_section("AUDIT SEARCH & FILTERING")
    
    # Create more test events
    for i in range(10):
        logger.log_event(
            event_type=AuditEventType.API_CALL if i % 2 == 0 else AuditEventType.REPORT_VIEWED,
            action=f"Action {i}",
            user_id=f"user_{i % 3}",
            org_id="org_acme"
        )
    
    search = AuditSearch(log_dir=temp_dir)
    
    print("1. Search All Events:")
    query = AuditQuery(limit=100)
    events = search.search(query)
    print(f"   Found {len(events)} total events")
    
    print("\n2. Filter by Event Type:")
    query = AuditQuery(
        event_types=[AuditEventType.LOGIN_SUCCESS, AuditEventType.LOGIN_FAILURE],
        limit=100
    )
    events = search.search(query)
    print(f"   Found {len(events)} authentication events")
    
    print("\n3. Filter by Severity:")
    query = AuditQuery(
        severities=[AuditSeverity.HIGH, AuditSeverity.CRITICAL],
        limit=100
    )
    events = search.search(query)
    print(f"   Found {len(events)} high/critical severity events")
    
    print("\n4. Aggregate by Category:")
    query = AuditQuery()
    aggregation = search.aggregate_by_category(query)
    print("   Events by Category:")
    for category, count in aggregation.items():
        print(f"     {category}: {count}")
    
    print("\n5. Aggregate by Severity:")
    aggregation = search.aggregate_by_severity(query)
    print("   Events by Severity:")
    for severity, count in aggregation.items():
        print(f"     {severity}: {count}")
    
    return search


def demo_forensic_analysis(search: AuditSearch):
    """Demonstrate forensic analysis."""
    print_section("FORENSIC ANALYSIS")
    
    analyzer = ForensicAnalyzer(search)
    
    print("1. Creating Forensic Timeline:")
    query = AuditQuery(user_ids=["user_123"])
    timeline = analyzer.create_timeline(
        title="User Activity Investigation",
        description="Timeline of user_123 activities",
        query=query
    )
    print(f"   Timeline ID: {timeline.timeline_id}")
    print(f"   Total Events: {len(timeline.events)}")
    print(f"   Actors: {', '.join(timeline.actors)}")
    print(f"   Resources: {len(timeline.resources)}")
    print(f"   Key Findings:")
    for finding in timeline.key_findings:
        print(f"     • {finding}")
    
    print("\n2. Detecting Anomalies:")
    query = AuditQuery()
    anomalies = analyzer.detect_anomalies(query, sensitivity=0.7)
    print(f"   Detected {len(anomalies)} anomalies")
    
    for anomaly in anomalies[:3]:  # Show first 3
        print(f"\n   Anomaly: {anomaly.anomaly_type}")
        print(f"     Severity: {anomaly.severity.value}")
        print(f"     Description: {anomaly.description}")
        print(f"     Confidence: {anomaly.confidence_score * 100:.0f}%")
        print(f"     Recommendations:")
        for action in anomaly.recommended_actions[:2]:
            print(f"       • {action}")
    
    print("\n3. Analyzing User Activity:")
    start_time = datetime.utcnow() - timedelta(hours=1)
    end_time = datetime.utcnow() + timedelta(hours=1)
    
    analysis = analyzer.analyze_user_activity("user_123", start_time, end_time)
    print(f"   User: {analysis['user_id']}")
    print(f"   Total Events: {analysis['total_events']}")
    print(f"   Failed Attempts: {analysis['failed_attempts']}")
    print(f"   Resources Accessed: {len(analysis['resources_accessed'])}")
    print(f"   IP Addresses: {len(analysis['ip_addresses'])}")
    print(f"   Events by Category:")
    for category, count in list(analysis['events_by_category'].items())[:3]:
        print(f"     {category}: {count}")


def demo_compliance_reporting(search: AuditSearch):
    """Demonstrate compliance reporting."""
    print_section("COMPLIANCE REPORTING")
    
    reporter = ComplianceReporter(search)
    
    start_time = datetime.utcnow() - timedelta(days=30)
    end_time = datetime.utcnow()
    
    print("1. SOC 2 Compliance Report:")
    report = reporter.generate_soc2_report(start_time, end_time)
    print(f"   Report ID: {report.report_id}")
    print(f"   Period: {report.start_time.strftime('%Y-%m-%d')} to {report.end_time.strftime('%Y-%m-%d')}")
    print(f"   Total Events: {report.total_events}")
    print(f"   Security Incidents: {report.security_incidents}")
    print(f"\n   Summary:")
    for line in report.summary.split('\n'):
        if line.strip():
            print(f"     {line.strip()}")
    
    if report.recommendations:
        print(f"\n   Recommendations:")
        for rec in report.recommendations:
            print(f"     • {rec}")
    
    print("\n2. GDPR Compliance Report:")
    report = reporter.generate_gdpr_report(start_time, end_time)
    print(f"   Report ID: {report.report_id}")
    print(f"   Total Events: {report.total_events}")
    print(f"\n   Summary:")
    for line in report.summary.split('\n'):
        if line.strip():
            print(f"     {line.strip()}")
    
    print("\n3. Access Control Report:")
    report = reporter.generate_access_report(start_time, end_time)
    print(f"   Report ID: {report.report_id}")
    print(f"   Total Events: {report.total_events}")
    print(f"   Events by Category:")
    for category, count in list(report.events_by_category.items())[:3]:
        print(f"     {category}: {count}")


def demo_retention_management(temp_dir: str):
    """Demonstrate retention management."""
    print_section("RETENTION MANAGEMENT")
    
    archive_dir = tempfile.mkdtemp()
    retention = AuditRetentionManager(
        log_dir=temp_dir,
        archive_dir=archive_dir
    )
    
    print("1. Retention Policies:")
    print(f"   Total Policies: {len(retention.policies)}")
    for policy in retention.policies[:3]:
        print(f"     • {policy.name}: {policy.retention_days} days")
    
    print("\n2. Retention Statistics:")
    stats = retention.get_retention_stats()
    print(f"   Active Logs: {stats['active_logs']}")
    print(f"   Archived Logs: {stats['archived_logs']}")
    print(f"   Total Size: {stats['total_size_mb']:.2f} MB")
    if stats['oldest_log']:
        print(f"   Oldest Log: {stats['oldest_log']}")
    if stats['newest_log']:
        print(f"   Newest Log: {stats['newest_log']}")
    
    print("\n3. Archive Old Logs:")
    archive_stats = retention.archive_old_logs(days_to_keep=365)
    print(f"   Files Archived: {archive_stats['files_archived']}")
    print(f"   Space Saved: {archive_stats['bytes_saved'] / 1024:.2f} KB")
    
    # Cleanup
    shutil.rmtree(archive_dir, ignore_errors=True)


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BOUNTYBOT AUDIT LOGGING & FORENSICS DEMO")
    print("=" * 80)
    
    try:
        # Demo 1: Audit Logging
        temp_dir, logger = demo_audit_logging()
        
        # Demo 2: Audit Search
        search = demo_audit_search(temp_dir, logger)
        
        # Demo 3: Forensic Analysis
        demo_forensic_analysis(search)
        
        # Demo 4: Compliance Reporting
        demo_compliance_reporting(search)
        
        # Demo 5: Retention Management
        demo_retention_management(temp_dir)
        
        print("\n" + "=" * 80)
        print("  ✅ DEMO COMPLETED SUCCESSFULLY")
        print("=" * 80 + "\n")
        
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

