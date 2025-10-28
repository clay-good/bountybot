"""
Demo: Continuous Security Validation & Regression Testing System

Demonstrates the complete continuous validation workflow including:
- Vulnerability lifecycle management
- Automated regression testing
- Security posture tracking
- Continuous validation scheduling
"""

import asyncio
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from bountybot.continuous_validation import (
    VulnerabilityLifecycleManager,
    RegressionTestingEngine,
    SecurityPostureTracker,
    ContinuousValidationScheduler,
    VulnerabilityLifecycleState,
    ScheduleFrequency
)

console = Console()


def print_header(title: str):
    """Print section header."""
    console.print(f"\n[bold cyan]{'='*80}[/bold cyan]")
    console.print(f"[bold cyan]{title.center(80)}[/bold cyan]")
    console.print(f"[bold cyan]{'='*80}[/bold cyan]\n")


async def demo_vulnerability_lifecycle():
    """Demonstrate vulnerability lifecycle management."""
    print_header("1. Vulnerability Lifecycle Management")
    
    manager = VulnerabilityLifecycleManager()
    
    # Create vulnerability lifecycle
    console.print("[bold]Creating vulnerability lifecycle...[/bold]")
    lifecycle = manager.create_lifecycle(
        vulnerability_id="vuln-2024-001",
        report_id="report-12345",
        vulnerability_type="SQL Injection",
        severity="critical",
        discovered_by="researcher@bugbounty.com",
        discovery_source="bug_bounty"
    )
    
    console.print(f"✓ Created lifecycle for [cyan]{lifecycle.vulnerability_id}[/cyan]")
    console.print(f"  State: [yellow]{lifecycle.current_state.value}[/yellow]")
    console.print(f"  Severity: [red]{lifecycle.severity}[/red]")
    console.print(f"  Type: {lifecycle.vulnerability_type}\n")
    
    # Mark as validated
    console.print("[bold]Marking as validated...[/bold]")
    manager.mark_validated(
        "vuln-2024-001",
        validation_result={"verdict": "valid", "confidence": 0.95},
        confidence_score=0.95
    )
    
    updated = manager.get_lifecycle("vuln-2024-001")
    console.print(f"✓ Validated with confidence: [green]{updated.confidence_score:.1%}[/green]")
    console.print(f"  State: [yellow]{updated.current_state.value}[/yellow] (auto-triaged)")
    console.print(f"  Priority Score: [cyan]{updated.priority_score:.2f}[/cyan]\n")
    
    # Mark fix in progress
    console.print("[bold]Starting fix...[/bold]")
    manager.mark_fix_in_progress("vuln-2024-001")
    console.print(f"✓ Fix started at {updated.fix_started_at}\n")
    
    # Mark fix ready
    console.print("[bold]Marking fix as ready...[/bold]")
    manager.mark_fix_ready(
        "vuln-2024-001",
        fix_commit_hash="abc123def456",
        fix_pull_request="https://github.com/org/repo/pull/789",
        fix_description="Added parameterized queries to prevent SQL injection"
    )
    
    updated = manager.get_lifecycle("vuln-2024-001")
    console.print(f"✓ Fix ready for verification")
    console.print(f"  Commit: [cyan]{updated.fix_commit_hash}[/cyan]")
    console.print(f"  PR: {updated.fix_pull_request}\n")
    
    # Display lifecycle history
    table = Table(title="Lifecycle State History")
    table.add_column("From State", style="yellow")
    table.add_column("To State", style="green")
    table.add_column("Reason", style="cyan")
    table.add_column("Timestamp", style="dim")
    
    for entry in updated.state_history:
        table.add_row(
            entry['from_state'] or "N/A",
            entry['to_state'],
            entry['reason'],
            entry['timestamp'][:19]
        )
    
    console.print(table)
    
    return manager


async def demo_regression_testing(manager: VulnerabilityLifecycleManager):
    """Demonstrate automated regression testing."""
    print_header("2. Automated Regression Testing")
    
    engine = RegressionTestingEngine()
    
    # Verify fix
    console.print("[bold]Verifying fix with automated testing...[/bold]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running fix verification...", total=None)
        
        verification = await engine.verify_fix(
            vulnerability_id="vuln-2024-001",
            test_method="automated_scan",
            test_config={
                "scan_type": "full",
                "vulnerability_type": "SQL Injection"
            }
        )
        
        progress.update(task, completed=True)
    
    # Display verification results
    console.print(f"\n✓ Fix verification completed")
    console.print(f"  Status: [{'green' if verification.status.value == 'passed' else 'red'}]{verification.status.value}[/]")
    console.print(f"  Confidence: [cyan]{verification.confidence_score:.1%}[/cyan]")
    console.print(f"  Fix Effectiveness: [green]{verification.fix_effectiveness:.1%}[/green]\n")
    
    console.print("[bold]Findings:[/bold]")
    for finding in verification.findings:
        console.print(f"  • {finding}")
    
    # Add verification to lifecycle
    manager.add_verification_result("vuln-2024-001", verification)
    
    lifecycle = manager.get_lifecycle("vuln-2024-001")
    console.print(f"\n✓ Lifecycle updated")
    console.print(f"  State: [green]{lifecycle.current_state.value}[/green]")
    console.print(f"  Verification Count: {lifecycle.verification_count}\n")
    
    # Create regression tests
    console.print("[bold]Creating regression tests...[/bold]\n")
    
    test_types = ["poc_replay", "automated_scan", "security_check"]
    tests = []
    
    for test_type in test_types:
        test = await engine.create_regression_test(
            vulnerability_id="vuln-2024-001",
            test_type=test_type,
            test_config={"test_type": test_type}
        )
        tests.append(test)
        console.print(f"✓ Created {test_type} test: [cyan]{test.test_id[:8]}...[/cyan]")
    
    # Execute regression tests in batch
    console.print(f"\n[bold]Executing {len(tests)} regression tests in parallel...[/bold]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running regression tests...", total=None)
        
        results = await engine.execute_batch_regression_tests([t.test_id for t in tests])
        
        progress.update(task, completed=True)
    
    # Display results
    table = Table(title="Regression Test Results")
    table.add_column("Test Type", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Regression", style="bold")
    table.add_column("Confidence", style="green")
    table.add_column("Duration", style="dim")
    
    for result in results:
        status_color = "green" if result.status.value == "passed" else "red"
        regression_text = "❌ Yes" if result.regression_detected else "✓ No"
        duration = (result.completed_at - result.started_at).total_seconds() if result.completed_at else 0
        
        table.add_row(
            result.test_type,
            f"[{status_color}]{result.status.value}[/]",
            regression_text,
            f"{result.confidence_score:.1%}",
            f"{duration:.2f}s"
        )
    
    console.print(table)
    
    # Calculate regression rate
    regression_rate = engine.get_regression_rate()
    console.print(f"\n[bold]Regression Rate:[/bold] [{'red' if regression_rate > 0 else 'green'}]{regression_rate:.1%}[/]\n")
    
    return engine


async def demo_security_posture(manager: VulnerabilityLifecycleManager):
    """Demonstrate security posture tracking."""
    print_header("3. Security Posture Tracking")
    
    tracker = SecurityPostureTracker()
    
    # Create additional vulnerabilities for demo
    console.print("[bold]Creating additional vulnerabilities for posture analysis...[/bold]\n")
    
    vuln_data = [
        ("vuln-2024-002", "XSS", "high"),
        ("vuln-2024-003", "CSRF", "medium"),
        ("vuln-2024-004", "RCE", "critical"),
        ("vuln-2024-005", "Path Traversal", "medium"),
    ]
    
    for vuln_id, vuln_type, severity in vuln_data:
        manager.create_lifecycle(
            vulnerability_id=vuln_id,
            report_id=f"report-{vuln_id}",
            vulnerability_type=vuln_type,
            severity=severity
        )
        console.print(f"✓ Created {vuln_id}: {vuln_type} ({severity})")
    
    # Create posture snapshot
    console.print(f"\n[bold]Creating security posture snapshot...[/bold]\n")
    
    posture = tracker.create_posture_snapshot(list(manager.lifecycles.values()))
    
    # Display posture overview
    table = Table(title="Security Posture Overview")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="bold", justify="right")
    
    table.add_row("Total Vulnerabilities", str(len(manager.lifecycles)))
    table.add_row("Discovered", str(posture.discovered_count), style="yellow")
    table.add_row("Validated", str(posture.validated_count), style="blue")
    table.add_row("Triaged", str(posture.triaged_count), style="cyan")
    table.add_row("Fix In Progress", str(posture.fix_in_progress_count), style="magenta")
    table.add_row("Fix Verified", str(posture.fix_verified_count), style="green")
    table.add_row("Monitoring", str(posture.monitoring_count), style="green")
    table.add_row("Closed", str(posture.closed_count), style="dim")
    
    console.print(table)
    
    # Display severity distribution
    table = Table(title="Severity Distribution")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")
    
    total = len(manager.lifecycles)
    severities = [
        ("Critical", posture.critical_count, "red"),
        ("High", posture.high_count, "orange1"),
        ("Medium", posture.medium_count, "yellow"),
        ("Low", posture.low_count, "green"),
        ("Info", posture.info_count, "dim")
    ]
    
    for severity, count, color in severities:
        pct = (count / total * 100) if total > 0 else 0
        table.add_row(
            f"[{color}]{severity}[/]",
            str(count),
            f"{pct:.1f}%"
        )
    
    console.print(table)
    
    # Display metrics
    metrics = posture.metrics
    
    table = Table(title="Performance Metrics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold", justify="right")
    
    if metrics.avg_time_to_validate:
        table.add_row("Avg Time to Validate", f"{metrics.avg_time_to_validate:.2f} hours")
    if metrics.avg_time_to_triage:
        table.add_row("Avg Time to Triage", f"{metrics.avg_time_to_triage:.2f} hours")
    if metrics.avg_time_to_fix:
        table.add_row("Avg Time to Fix", f"{metrics.avg_time_to_fix:.2f} hours")
    if metrics.avg_confidence_score:
        table.add_row("Avg Confidence Score", f"{metrics.avg_confidence_score:.1%}")
    if metrics.avg_priority_score:
        table.add_row("Avg Priority Score", f"{metrics.avg_priority_score:.2f}")
    
    console.print(table)
    
    return tracker


async def demo_continuous_scheduling(engine: RegressionTestingEngine):
    """Demonstrate continuous validation scheduling."""
    print_header("4. Continuous Validation Scheduling")
    
    scheduler = ContinuousValidationScheduler(engine)
    
    # Create schedules
    console.print("[bold]Creating validation schedules...[/bold]\n")
    
    schedules_config = [
        ("vuln-2024-001", ScheduleFrequency.DAILY, "Daily regression check"),
        ("vuln-2024-002", ScheduleFrequency.WEEKLY, "Weekly security scan"),
        ("vuln-2024-003", ScheduleFrequency.MONTHLY, "Monthly comprehensive test"),
    ]
    
    for vuln_id, frequency, description in schedules_config:
        schedule = scheduler.create_schedule(
            vulnerability_id=vuln_id,
            frequency=frequency,
            test_config={"test_type": "automated_scan"},
            created_by="security_team"
        )
        console.print(f"✓ Created {frequency.value} schedule for {vuln_id}")
        console.print(f"  Next run: [cyan]{schedule.next_run}[/cyan]")
        console.print(f"  Description: {description}\n")
    
    # Display schedule statistics
    stats = scheduler.get_schedule_statistics()
    
    table = Table(title="Scheduler Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold", justify="right")
    
    table.add_row("Total Schedules", str(stats['total_schedules']))
    table.add_row("Enabled Schedules", str(stats['enabled_schedules']))
    table.add_row("Total Runs", str(stats['total_runs']))
    table.add_row("Successful Runs", str(stats['successful_runs']))
    table.add_row("Failed Runs", str(stats['failed_runs']))
    table.add_row("Success Rate", f"{stats['success_rate']:.1%}")
    
    console.print(table)
    
    # Display frequency distribution
    table = Table(title="Schedule Frequency Distribution")
    table.add_column("Frequency", style="cyan")
    table.add_column("Count", style="bold", justify="right")
    
    for freq, count in stats['frequency_distribution'].items():
        table.add_row(freq.capitalize(), str(count))
    
    console.print(table)
    
    console.print(f"\n[bold green]✓ Continuous validation scheduler configured successfully![/bold green]\n")


async def main():
    """Run complete demo."""
    console.print(Panel.fit(
        "[bold cyan]BountyBot v2.11.0[/bold cyan]\n"
        "[bold]Continuous Security Validation & Regression Testing System[/bold]\n\n"
        "Demonstrating enterprise-grade continuous validation capabilities",
        border_style="cyan"
    ))
    
    try:
        # Demo 1: Vulnerability Lifecycle
        manager = await demo_vulnerability_lifecycle()
        
        # Demo 2: Regression Testing
        engine = await demo_regression_testing(manager)
        
        # Demo 3: Security Posture
        tracker = await demo_security_posture(manager)
        
        # Demo 4: Continuous Scheduling
        await demo_continuous_scheduling(engine)
        
        # Final summary
        print_header("Summary")
        
        console.print("[bold green]✓ Continuous Validation System Demo Complete![/bold green]\n")
        
        console.print("[bold]Key Features Demonstrated:[/bold]")
        console.print("  ✓ Vulnerability lifecycle management (discovery → fix → verification → monitoring)")
        console.print("  ✓ Automated regression testing with parallel execution")
        console.print("  ✓ Security posture tracking with metrics and trends")
        console.print("  ✓ Continuous validation scheduling with multiple frequencies\n")
        
        console.print("[bold cyan]BountyBot v2.11.0 provides enterprise-grade continuous security validation![/bold cyan]\n")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise


if __name__ == "__main__":
    asyncio.run(main())

