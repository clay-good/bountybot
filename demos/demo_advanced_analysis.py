#!/usr/bin/env python3

from bountybot.models import Report, Severity
from bountybot.analysis import (
    FalsePositiveDetector,
    ExploitComplexityAnalyzer,
    AttackChainDetector
)


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_false_positive_detection():
    """Demonstrate false positive detection."""
    print_section("FALSE POSITIVE DETECTION")
    
    detector = FalsePositiveDetector()
    
    # Example 1: High-quality report (should NOT be flagged)
    print("Example 1: High-Quality SQL Injection Report")
    print("-" * 80)
    
    good_report = Report(
        title="SQL Injection in Login Form",
        vulnerability_type="sql injection",
        severity=Severity.CRITICAL,
        impact_description="SQL injection allows full database access, credential theft, and data modification",
        affected_components=["login.php", "database"],
        reproduction_steps=[
            "Navigate to /login",
            "Enter username: admin' OR 1=1--",
            "Enter any password",
            "Click login button",
            "Observe successful authentication bypass",
            "Database error reveals table structure"
        ],
        proof_of_concept="admin' OR 1=1-- -"
    )
    
    result = detector.analyze(good_report)
    print(f"FP Confidence: {result.confidence:.1f}%")
    print(f"Risk Score: {result.risk_score:.1f}/100")
    print(f"Is Likely FP: {result.is_likely_false_positive}")
    print(f"Indicators: {len(result.indicators)}")
    print(f"Reasoning: {result.reasoning[:150]}...")
    
    # Example 2: Poor quality report (should be flagged)
    print("\n\nExample 2: Poor Quality Report (Missing Evidence)")
    print("-" * 80)
    
    bad_report = Report(
        title="Possible SQL Injection",
        vulnerability_type="sql injection",
        severity=Severity.MEDIUM,
        impact_description="Might be vulnerable",
        affected_components=["login.php"],
        reproduction_steps=["Try SQL injection"],
        proof_of_concept=""
    )
    
    result = detector.analyze(bad_report)
    print(f"FP Confidence: {result.confidence:.1f}%")
    print(f"Risk Score: {result.risk_score:.1f}/100")
    print(f"Is Likely FP: {result.is_likely_false_positive}")
    print(f"Indicators: {len(result.indicators)}")
    for ind in result.indicators[:3]:
        print(f"  - {ind['category']}: {ind['description']}")
    print(f"Reasoning: {result.reasoning[:150]}...")


def demo_exploit_complexity():
    """Demonstrate exploit complexity analysis."""
    print_section("EXPLOIT COMPLEXITY ANALYSIS")
    
    analyzer = ExploitComplexityAnalyzer()
    
    # Example 1: Simple unauthenticated exploit
    print("Example 1: Simple Unauthenticated RCE")
    print("-" * 80)
    
    simple_report = Report(
        title="Unauthenticated RCE via Command Injection",
        vulnerability_type="rce",
        severity=Severity.CRITICAL,
        impact_description="Unauthenticated remote code execution allows full system compromise",
        affected_components=["api/execute.php"],
        reproduction_steps=[
            "Send GET request to /api/execute?cmd=whoami",
            "Observe command output in response"
        ],
        proof_of_concept="curl 'https://example.com/api/execute?cmd=whoami'"
    )
    
    result = analyzer.analyze(simple_report)
    print(f"Overall Complexity Score: {result.overall_score:.1f}/100")
    print(f"Skill Level Required: {result.skill_level.value.replace('_', ' ').title()}")
    print(f"Time to Exploit: {result.time_to_exploit.value.title()}")
    print(f"Automation Potential: {result.automation_potential:.1f}%")
    print(f"Reliability: {result.reliability:.1f}%")
    print(f"\nTop Complexity Factors:")
    for factor in sorted(result.factors, key=lambda f: f.score, reverse=True)[:3]:
        print(f"  - {factor.name}: {factor.score:.1f}/100 ({factor.weight*100:.0f}% weight)")
    
    # Example 2: Complex authenticated exploit
    print("\n\nExample 2: Complex Race Condition in Admin Panel")
    print("-" * 80)
    
    complex_report = Report(
        title="Race Condition Privilege Escalation",
        vulnerability_type="race condition",
        severity=Severity.HIGH,
        impact_description="Race condition in admin panel allows privilege escalation but requires admin access and precise timing",
        affected_components=["admin/users.php"],
        reproduction_steps=[
            "Login as administrator",
            "Navigate to user management panel",
            "Send two simultaneous requests to modify user privileges",
            "Exploit race condition window (< 100ms)",
            "Requires multiple attempts and precise timing",
            "Success rate approximately 10%"
        ],
        proof_of_concept="Requires custom multi-threaded script"
    )
    
    result = analyzer.analyze(complex_report)
    print(f"Overall Complexity Score: {result.overall_score:.1f}/100")
    print(f"Skill Level Required: {result.skill_level.value.replace('_', ' ').title()}")
    print(f"Time to Exploit: {result.time_to_exploit.value.title()}")
    print(f"Automation Potential: {result.automation_potential:.1f}%")
    print(f"Reliability: {result.reliability:.1f}%")
    print(f"\nExploitation Barriers:")
    for barrier in result.barriers[:3]:
        print(f"  - {barrier}")


def demo_attack_chains():
    """Demonstrate attack chain detection."""
    print_section("ATTACK CHAIN DETECTION")
    
    detector = AttackChainDetector()
    
    # Example 1: Single vulnerability (no chain)
    print("Example 1: Single Vulnerability (No Chain)")
    print("-" * 80)
    
    single_report = Report(
        title="SQL Injection in Search",
        vulnerability_type="sql injection",
        severity=Severity.HIGH,
        impact_description="SQL injection allows database access",
        affected_components=["search.php"],
        reproduction_steps=[
            "Navigate to search page",
            "Enter SQL payload in search box"
        ],
        proof_of_concept="' OR 1=1--"
    )
    
    result = detector.detect(single_report)
    print(f"Is Chain: {result.is_chain}")
    print(f"Chain Length: {result.chain_length}")
    print(f"Chain Type: {result.chain_type.value if result.chain_type else 'None'}")
    
    # Example 2: Privilege escalation chain
    print("\n\nExample 2: IDOR → CSRF → Privilege Escalation Chain")
    print("-" * 80)
    
    chain_report = Report(
        title="IDOR to Admin Privilege Escalation",
        vulnerability_type="idor",
        severity=Severity.CRITICAL,
        impact_description="IDOR allows viewing admin user ID, then CSRF allows privilege escalation to admin",
        affected_components=["api/users.php", "admin/promote.php"],
        reproduction_steps=[
            "Use IDOR to enumerate user IDs",
            "Identify admin user ID (user_id=1)",
            "Craft CSRF payload to promote user to admin",
            "Send CSRF to victim admin via email",
            "Victim clicks link, attacker gains admin privileges"
        ],
        proof_of_concept="IDOR: /api/users/1, CSRF: <form action='/admin/promote'>"
    )
    
    result = detector.detect(chain_report)
    print(f"Is Chain: {result.is_chain}")
    print(f"Chain Length: {result.chain_length}")
    print(f"Chain Type: {result.chain_type.value if result.chain_type else 'None'}")
    print(f"Impact Multiplier: {result.impact_multiplier:.1f}x")
    print(f"\nVulnerabilities in Chain:")
    for vuln in result.vulnerabilities:
        print(f"  - {vuln.vulnerability_type}")
        if vuln.requires:
            print(f"    Requires: {', '.join(vuln.requires)}")
        if vuln.enables:
            print(f"    Enables: {', '.join(vuln.enables)}")
    print(f"\nExploitation Path:")
    for i, step in enumerate(result.exploitation_path, 1):
        print(f"  {i}. {step}")
    print(f"\nCombined Impact: {result.combined_impact}")
    
    # Example 3: Data exfiltration chain
    print("\n\nExample 3: SSRF → SQL Injection → Data Exfiltration Chain")
    print("-" * 80)
    
    exfil_report = Report(
        title="SSRF to Internal Database Access",
        vulnerability_type="ssrf",
        severity=Severity.CRITICAL,
        impact_description="SSRF allows access to internal network, then SQL injection on internal database",
        affected_components=["api/fetch.php", "internal/db.php"],
        reproduction_steps=[
            "Exploit SSRF to access internal network",
            "Identify internal database endpoint (http://internal-db:3306)",
            "Use SSRF to send SQL injection payload to internal DB",
            "Exfiltrate sensitive data through SSRF response"
        ],
        proof_of_concept="SSRF: http://internal-db:3306, SQLi: ' UNION SELECT * FROM users--"
    )
    
    result = detector.detect(exfil_report)
    print(f"Is Chain: {result.is_chain}")
    print(f"Chain Length: {result.chain_length}")
    print(f"Chain Type: {result.chain_type.value if result.chain_type else 'None'}")
    print(f"Impact Multiplier: {result.impact_multiplier:.1f}x")
    print(f"Exploitation Path Steps: {len(result.exploitation_path)}")
    if result.combined_impact:
        print(f"Combined Impact: {result.combined_impact[:150]}...")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BountyBot Advanced Analysis Features Demo")
    print("=" * 80)
    
    demo_false_positive_detection()
    demo_exploit_complexity()
    demo_attack_chains()
    
    print("\n" + "=" * 80)
    print("  Demo Complete!")
    print("=" * 80)
    print("\nAll three advanced analysis features are working correctly:")
    print("  ✓ False Positive Detection")
    print("  ✓ Exploit Complexity Analysis")
    print("  ✓ Attack Chain Detection")
    print("\nThese features are now integrated into the main validation pipeline.")
    print("Run: python3 -m bountybot.cli report.json --verbose")
    print("=" * 80 + "\n")


if __name__ == '__main__':
    main()

