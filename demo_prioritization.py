#!/usr/bin/env python3

from datetime import datetime, timedelta
from bountybot.models import Report, Severity, ValidationResult, Verdict
from bountybot.prioritization import PriorityEngine, RemediationQueue, QueueItem, PriorityLevel


class MockCVSSScore:
    """Mock CVSS score object."""
    def __init__(self, base_score):
        self.base_score = base_score


class MockAttackChain:
    """Mock attack chain object."""
    def __init__(self, is_chain, impact_multiplier=1.0):
        self.is_chain = is_chain
        self.impact_multiplier = impact_multiplier


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def print_priority_score(priority, report_title):
    """Print formatted priority score."""
    print(f"Report: {report_title}")
    print(f"Priority Level: {priority.priority_level.value.upper()}")
    print(f"Overall Score: {priority.overall_score:.1f}/100")
    print(f"Recommended SLA: {priority.recommended_sla}")
    print(f"Escalation Required: {'YES' if priority.escalation_required else 'NO'}")
    print(f"\nComponent Scores:")
    print(f"  - CVSS: {priority.cvss_score:.1f}/100")
    print(f"  - Exploitability: {priority.exploitability_score:.1f}/100")
    print(f"  - Confidence: {priority.confidence_score:.1f}/100")
    print(f"  - Chain Amplification: {priority.chain_amplification_score:.1f}/100")
    print(f"  - Business Impact: {priority.business_impact_score:.1f}/100")
    if priority.risk_factors:
        print(f"\nRisk Factors:")
        for factor in priority.risk_factors:
            print(f"  - {factor}")
    if priority.mitigating_factors:
        print(f"\nMitigating Factors:")
        for factor in priority.mitigating_factors:
            print(f"  - {factor}")
    print(f"\nReasoning: {priority.reasoning}")


def demo_critical_priority():
    """Demonstrate critical priority calculation."""
    print_section("CRITICAL PRIORITY: Unauthenticated RCE")
    
    engine = PriorityEngine()
    
    report = Report(
        title="Unauthenticated Remote Code Execution in API",
        vulnerability_type="rce",
        severity=Severity.CRITICAL,
        affected_components=["api/execute", "admin/commands"],
        impact_description="Unauthenticated remote code execution allows full system compromise",
        reproduction_steps=[
            "Send GET request to /api/execute?cmd=whoami",
            "Observe command output in response"
        ],
        proof_of_concept="curl 'https://example.com/api/execute?cmd=whoami'"
    )
    
    result = ValidationResult(
        report=report,
        verdict=Verdict.VALID,
        confidence=95
    )
    result.cvss_score = MockCVSSScore(9.8)
    result.exploit_complexity_score = 85.0  # Very easy to exploit
    result.false_positive_indicators = []
    
    priority = engine.calculate_priority(result)
    print_priority_score(priority, report.title)


def demo_high_priority_with_chain():
    """Demonstrate high priority with attack chain."""
    print_section("HIGH PRIORITY: Attack Chain (IDOR → Privilege Escalation)")
    
    engine = PriorityEngine()
    
    report = Report(
        title="IDOR to Admin Privilege Escalation",
        vulnerability_type="idor",
        severity=Severity.HIGH,
        affected_components=["api/users", "admin/promote"],
        impact_description="IDOR allows viewing admin user ID, then CSRF allows privilege escalation",
        reproduction_steps=[
            "Use IDOR to enumerate user IDs",
            "Identify admin user ID",
            "Craft CSRF payload to promote user to admin",
            "Send CSRF to victim admin",
            "Gain admin privileges"
        ],
        proof_of_concept="IDOR: /api/users/1, CSRF: <form action='/admin/promote'>"
    )
    
    result = ValidationResult(
        report=report,
        verdict=Verdict.VALID,
        confidence=85
    )
    result.cvss_score = MockCVSSScore(7.5)
    result.exploit_complexity_score = 65.0
    result.attack_chain = MockAttackChain(is_chain=True, impact_multiplier=1.8)
    
    priority = engine.calculate_priority(result)
    print_priority_score(priority, report.title)


def demo_medium_priority():
    """Demonstrate medium priority calculation."""
    print_section("MEDIUM PRIORITY: Stored XSS")
    
    engine = PriorityEngine()
    
    report = Report(
        title="Stored XSS in Comment Field",
        vulnerability_type="xss",
        severity=Severity.MEDIUM,
        affected_components=["comments.php"],
        impact_description="Stored XSS allows JavaScript execution in other users' browsers",
        reproduction_steps=[
            "Navigate to comment section",
            "Enter XSS payload: <script>alert(1)</script>",
            "Submit comment",
            "Observe XSS execution when other users view the page"
        ],
        proof_of_concept="<script>alert(document.cookie)</script>"
    )
    
    result = ValidationResult(
        report=report,
        verdict=Verdict.VALID,
        confidence=75
    )
    result.cvss_score = MockCVSSScore(6.1)
    result.exploit_complexity_score = 55.0
    
    priority = engine.calculate_priority(result)
    print_priority_score(priority, report.title)


def demo_low_priority_with_fp():
    """Demonstrate low priority with false positive indicators."""
    print_section("LOW PRIORITY: Possible SQL Injection (FP Indicators)")
    
    engine = PriorityEngine()
    
    report = Report(
        title="Possible SQL Injection in Search",
        vulnerability_type="sql injection",
        severity=Severity.MEDIUM,
        affected_components=["search.php"],
        impact_description="Might be vulnerable to SQL injection",
        reproduction_steps=["Try SQL injection"],
        proof_of_concept=""
    )
    
    result = ValidationResult(
        report=report,
        verdict=Verdict.UNCERTAIN,
        confidence=45
    )
    result.cvss_score = MockCVSSScore(5.0)
    result.exploit_complexity_score = 40.0
    result.false_positive_indicators = [
        "Missing evidence",
        "Insufficient reproduction steps",
        "Theoretical only"
    ]
    
    priority = engine.calculate_priority(result)
    print_priority_score(priority, report.title)


def demo_remediation_queue():
    """Demonstrate remediation queue management."""
    print_section("REMEDIATION QUEUE MANAGEMENT")
    
    engine = PriorityEngine()
    queue = RemediationQueue()
    
    # Create sample reports with different priorities
    reports_data = [
        ("Unauthenticated RCE", Severity.CRITICAL, 9.8, 85, 95, None, 5),
        ("SQL Injection in Auth", Severity.CRITICAL, 9.0, 70, 90, None, 3),
        ("IDOR to Privilege Escalation", Severity.HIGH, 7.5, 65, 85, 1.8, 7),
        ("Stored XSS", Severity.MEDIUM, 6.1, 55, 75, None, 10),
        ("CSRF in Profile Update", Severity.MEDIUM, 5.5, 50, 70, None, 2),
        ("Information Disclosure", Severity.LOW, 3.5, 30, 60, None, 15),
        ("Missing Security Headers", Severity.LOW, 2.0, 20, 40, None, 20),
    ]
    
    print("Adding reports to queue...\n")
    
    for title, severity, cvss, exploit, confidence, chain_mult, age in reports_data:
        report = Report(
            title=title,
            vulnerability_type="various",
            severity=severity,
            affected_components=["various"],
            impact_description=f"Impact of {title}"
        )
        
        result = ValidationResult(
            report=report,
            verdict=Verdict.VALID,
            confidence=confidence
        )
        result.cvss_score = MockCVSSScore(cvss)
        result.exploit_complexity_score = exploit
        if chain_mult:
            result.attack_chain = MockAttackChain(is_chain=True, impact_multiplier=chain_mult)
        
        priority = engine.calculate_priority(result)
        
        item = QueueItem(
            report_id=f"report_{len(queue.items) + 1}",
            report_title=title,
            priority_score=priority,
            submission_date=datetime.now() - timedelta(days=age),
            age_days=age
        )
        queue.add(item)
    
    # Display queue statistics
    stats = queue.get_statistics()
    print("Queue Statistics:")
    print(f"  Total Reports: {stats['total_items']}")
    print(f"  Average Priority Score: {stats['avg_score']:.1f}/100")
    print(f"\n  By Priority Level:")
    for level, count in sorted(stats['by_priority'].items(), 
                               key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x[0])):
        print(f"    - {level.upper()}: {count}")
    
    # Display top 5 priorities
    print(f"\n  Top 5 Priorities:")
    top_5 = queue.get_top_n(5)
    for i, item in enumerate(top_5, 1):
        print(f"    {i}. [{item.priority_score.priority_level.value.upper()}] "
              f"{item.report_title} "
              f"(Score: {item.priority_score.overall_score:.1f}, "
              f"Age: {item.age_days} days, "
              f"SLA: {item.priority_score.recommended_sla})")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BountyBot Remediation Prioritization Engine Demo")
    print("=" * 80)
    
    demo_critical_priority()
    demo_high_priority_with_chain()
    demo_medium_priority()
    demo_low_priority_with_fp()
    demo_remediation_queue()
    
    print("\n" + "=" * 80)
    print("  Demo Complete!")
    print("=" * 80)
    print("\nThe Prioritization Engine provides:")
    print("  ✓ Intelligent multi-signal priority scoring (5 factors)")
    print("  ✓ Automatic P0-P4 classification")
    print("  ✓ SLA recommendations (24 hours to 3 months)")
    print("  ✓ Escalation logic for critical issues")
    print("  ✓ Queue management with sorting and statistics")
    print("\nThis feature is now integrated into the main validation pipeline.")
    print("Run: python3 -m bountybot.cli report.json --verbose")
    print("=" * 80 + "\n")


if __name__ == '__main__':
    main()

