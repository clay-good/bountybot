#!/usr/bin/env python3

import tempfile
import os
from datetime import datetime, timedelta

from bountybot.database import (
    init_database,
    session_scope,
    ReportRepository,
    ValidationResultRepository,
    ResearcherRepository,
    MetricsRepository,
    AuditLogRepository,
    health_check,
    get_database_stats
)
from bountybot.database.models import (
    VerdictEnum,
    SeverityEnum,
    PriorityEnum,
    StatusEnum
)


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_database_initialization():
    """Demonstrate database initialization."""
    print_section("DATABASE INITIALIZATION")
    
    # Create temporary SQLite database for demo
    db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
    db_file.close()
    db_url = f"sqlite:///{db_file.name}"
    
    print(f"Initializing database: {db_url}")
    db = init_database(db_url, echo=False, create_tables=True)
    
    print(f"✓ Database initialized successfully")
    print(f"✓ Health check: {health_check()}")
    
    stats = get_database_stats()
    print(f"✓ Database type: {stats['database_type']}")
    
    return db_file.name


def demo_report_operations():
    """Demonstrate report CRUD operations."""
    print_section("REPORT OPERATIONS")
    
    with session_scope() as session:
        repo = ReportRepository(session)
        
        # Create reports
        print("Creating reports...")
        report1 = repo.create({
            'external_id': 'DEMO-001',
            'title': 'SQL Injection in Login Form',
            'vulnerability_type': 'sql_injection',
            'severity': SeverityEnum.CRITICAL,
            'affected_components': ['login.php', 'auth/database.php'],
            'reproduction_steps': [
                'Navigate to login page',
                'Enter SQL payload in username field',
                'Observe database error'
            ],
            'proof_of_concept': "username: admin' OR '1'='1",
            'impact_description': 'Complete database compromise possible',
            'status': StatusEnum.PENDING
        })
        print(f"✓ Created report: {report1.id} - {report1.title}")
        
        report2 = repo.create({
            'external_id': 'DEMO-002',
            'title': 'Stored XSS in Comment Section',
            'vulnerability_type': 'xss',
            'severity': SeverityEnum.HIGH,
            'affected_components': ['comments.php'],
            'status': StatusEnum.PENDING
        })
        print(f"✓ Created report: {report2.id} - {report2.title}")
        
        report3 = repo.create({
            'external_id': 'DEMO-003',
            'title': 'CSRF in Profile Update',
            'vulnerability_type': 'csrf',
            'severity': SeverityEnum.MEDIUM,
            'status': StatusEnum.PENDING
        })
        print(f"✓ Created report: {report3.id} - {report3.title}")

        # Store IDs for later use
        report1_id = report1.id

    # Retrieve reports
    print("\nRetrieving reports...")
    with session_scope() as session:
        repo = ReportRepository(session)

        report = repo.get_by_external_id('DEMO-001')
        print(f"✓ Retrieved by external ID: {report.title}")

        pending = repo.get_by_status(StatusEnum.PENDING)
        print(f"✓ Found {len(pending)} pending reports")

        critical = repo.get_by_severity(SeverityEnum.CRITICAL)
        print(f"✓ Found {len(critical)} critical reports")

    # Update report status
    print("\nUpdating report status...")
    with session_scope() as session:
        repo = ReportRepository(session)
        repo.update_status(report1_id, StatusEnum.IN_PROGRESS, assigned_to='security@example.com')
        print(f"✓ Updated report {report1_id} to IN_PROGRESS")
    
    # Get statistics
    print("\nReport statistics:")
    with session_scope() as session:
        repo = ReportRepository(session)
        stats = repo.get_statistics()
        print(f"  Total reports: {stats['total_reports']}")
        print(f"  By status: {stats['by_status']}")
        print(f"  By severity: {stats['by_severity']}")


def demo_validation_operations():
    """Demonstrate validation result operations."""
    print_section("VALIDATION OPERATIONS")
    
    with session_scope() as session:
        report_repo = ReportRepository(session)
        validation_repo = ValidationResultRepository(session)
        
        # Get a report
        report = report_repo.get_by_external_id('DEMO-001')
        
        # Create validation result
        print(f"Creating validation result for report: {report.title}")
        result = validation_repo.create({
            'report_id': report.id,
            'verdict': VerdictEnum.VALID,
            'confidence': 95,
            'cvss_base_score': 9.8,
            'cvss_temporal_score': 9.5,
            'cvss_vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'cvss_severity_rating': 'CRITICAL',
            'exploit_complexity_score': 85.0,
            'exploit_skill_level': 'Intermediate',
            'exploit_time_estimate': 'Minutes',
            'false_positive_confidence': 5.0,
            'is_attack_chain': False,
            'priority_level': PriorityEnum.CRITICAL,
            'priority_score': 88.5,
            'priority_sla': '24 hours',
            'escalation_required': True,
            'is_duplicate': False,
            'processing_time_seconds': 45.2,
            'ai_cost': 0.15,
            'key_findings': ['SQL injection confirmed', 'No authentication required'],
            'recommendations_security': ['Patch immediately', 'Deploy WAF rules'],
            'reasoning': 'Critical vulnerability with easy exploitation'
        })
        print(f"✓ Created validation result: {result.id}")
        print(f"  Verdict: {result.verdict.value}")
        print(f"  Confidence: {result.confidence}%")
        print(f"  CVSS Score: {result.cvss_base_score}")
        print(f"  Priority: {result.priority_level.value.upper()} ({result.priority_score}/100)")
        print(f"  Escalation Required: {result.escalation_required}")
    
    # Retrieve validation results
    print("\nRetrieving validation results...")
    with session_scope() as session:
        validation_repo = ValidationResultRepository(session)
        
        high_priority = validation_repo.get_high_priority(min_score=80.0)
        print(f"✓ Found {len(high_priority)} high-priority validations")
        
        critical = validation_repo.get_by_priority(PriorityEnum.CRITICAL)
        print(f"✓ Found {len(critical)} critical priority validations")
    
    # Get statistics
    print("\nValidation statistics:")
    with session_scope() as session:
        validation_repo = ValidationResultRepository(session)
        stats = validation_repo.get_statistics()
        print(f"  Total validations: {stats['total_validations']}")
        print(f"  By verdict: {stats['by_verdict']}")
        print(f"  By priority: {stats['by_priority']}")
        print(f"  Average confidence: {stats['average_confidence']}%")
        print(f"  Average priority score: {stats['average_priority_score']}/100")


def demo_researcher_operations():
    """Demonstrate researcher operations."""
    print_section("RESEARCHER OPERATIONS")
    
    with session_scope() as session:
        researcher_repo = ResearcherRepository(session)
        report_repo = ReportRepository(session)
        validation_repo = ValidationResultRepository(session)
        
        # Create researchers
        print("Creating researchers...")
        researcher1 = researcher_repo.create({
            'external_id': 'RES-001',
            'username': 'security_expert',
            'email': 'expert@example.com'
        })
        print(f"✓ Created researcher: {researcher1.username}")
        
        researcher2 = researcher_repo.get_or_create('bug_hunter', 'RES-002')
        print(f"✓ Created researcher: {researcher2.username}")
        
        # Associate reports with researcher
        print("\nAssociating reports with researcher...")
        report = report_repo.get_by_external_id('DEMO-001')
        report.researcher_id = researcher1.id
        
        # Update researcher statistics
        validation = validation_repo.get_by_report_id(report.id)
        researcher_repo.update_statistics(researcher1.id, validation)
        print(f"✓ Updated researcher statistics")
        
        # Retrieve updated researcher
        updated = researcher_repo.get_by_id(researcher1.id)
        print(f"\nResearcher statistics:")
        print(f"  Username: {updated.username}")
        print(f"  Total reports: {updated.total_reports}")
        print(f"  Valid reports: {updated.valid_reports}")
        print(f"  Quality score: {updated.quality_score:.1f}/100")


def demo_metrics_operations():
    """Demonstrate metrics operations."""
    print_section("METRICS OPERATIONS")
    
    with session_scope() as session:
        repo = MetricsRepository(session)
        
        # Record metrics
        print("Recording metrics...")
        repo.record('reports_validated', 1.0, {'severity': 'critical', 'verdict': 'valid'}, 'count')
        repo.record('validation_time', 45.2, {'report_id': 'DEMO-001'}, 'seconds')
        repo.record('ai_cost', 0.15, {'model': 'claude-sonnet-4'}, 'dollars')
        print("✓ Recorded 3 metrics")
        
        # Retrieve metrics
        print("\nRetrieving recent metrics...")
        recent = repo.get_recent_metrics(hours=24, limit=10)
        for metric in recent:
            print(f"  {metric.metric_name}: {metric.metric_value} {metric.unit}")
        
        # Get aggregates
        print("\nMetric aggregates:")
        start = datetime.utcnow() - timedelta(hours=1)
        end = datetime.utcnow()
        
        total_validated = repo.get_aggregate('reports_validated', start, end, 'sum')
        avg_time = repo.get_aggregate('validation_time', start, end, 'avg')
        total_cost = repo.get_aggregate('ai_cost', start, end, 'sum')
        
        print(f"  Total reports validated: {total_validated}")
        print(f"  Average validation time: {avg_time:.1f} seconds")
        print(f"  Total AI cost: ${total_cost:.2f}")


def demo_audit_log():
    """Demonstrate audit logging."""
    print_section("AUDIT LOGGING")
    
    with session_scope() as session:
        repo = AuditLogRepository(session)
        
        # Log actions
        print("Logging audit events...")
        repo.log(
            action='report_created',
            resource_type='report',
            resource_id=1,
            user='admin@example.com',
            details={'title': 'SQL Injection in Login Form'},
            result='success'
        )
        
        repo.log(
            action='validation_completed',
            resource_type='validation',
            resource_id=1,
            user='system',
            details={'verdict': 'VALID', 'confidence': 95},
            result='success'
        )
        
        repo.log(
            action='status_updated',
            resource_type='report',
            resource_id=1,
            user='security@example.com',
            details={'old_status': 'PENDING', 'new_status': 'IN_PROGRESS'},
            result='success'
        )
        print("✓ Logged 3 audit events")
        
        # Retrieve logs
        print("\nRetrieving audit logs...")
        recent = repo.get_recent(hours=24, limit=10)
        for log in recent:
            print(f"  [{log.timestamp.strftime('%H:%M:%S')}] {log.action} by {log.user} - {log.result}")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BountyBot Database Backend Demo")
    print("=" * 80)
    
    db_file = demo_database_initialization()
    demo_report_operations()
    demo_validation_operations()
    demo_researcher_operations()
    demo_metrics_operations()
    demo_audit_log()
    
    print("\n" + "=" * 80)
    print("  Demo Complete!")
    print("=" * 80)
    print("\nThe Database Backend provides:")
    print("  ✓ Persistent storage for reports, validations, researchers")
    print("  ✓ Time-series metrics for analytics")
    print("  ✓ Audit logging for compliance")
    print("  ✓ Repository pattern for clean data access")
    print("  ✓ Support for PostgreSQL (production) and SQLite (dev/test)")
    print("  ✓ Connection pooling and health checks")
    print("\nClean up:")
    print(f"  rm {db_file}")
    print("=" * 80 + "\n")


if __name__ == '__main__':
    main()

