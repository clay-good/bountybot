#!/usr/bin/env python3
"""
Demo script for BountyBot Integration Hub.

Demonstrates how to use integrations with JIRA, Slack, GitHub, PagerDuty, and Email.
"""

import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich import box

# Add bountybot to path
sys.path.insert(0, str(Path(__file__).parent))

from bountybot.integrations import (
    IntegrationManager,
    IntegrationConfig,
    IntegrationType,
    IntegrationStatus,
)
from bountybot.models import Report, ValidationResult, Verdict
from bountybot.scoring import CVSSCalculator, CVSSv31Score
from bountybot.prioritization import PriorityEngine, PriorityScore, PriorityLevel

console = Console()


def print_header():
    """Print demo header."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]BountyBot Integration Hub Demo[/bold cyan]\n"
        "[dim]Connect with JIRA, Slack, GitHub, PagerDuty, and Email[/dim]",
        border_style="cyan"
    ))
    console.print()


def create_sample_validation_result() -> ValidationResult:
    """Create a sample validation result for demo."""
    # Create sample report
    report = Report(
        title="SQL Injection in User Authentication",
        vulnerability_type="SQL Injection",
        severity="HIGH",
        researcher="security_researcher_123",
        impact_description="An attacker can bypass authentication by injecting SQL code into the login form.",
        affected_components=["auth/login.php", "database/users.php"],
        reproduction_steps=[
            "Navigate to /login",
            "Enter username: admin' OR '1'='1",
            "Enter any password",
            "Click login button",
            "Observe successful authentication bypass"
        ],
        proof_of_concept="POST /login HTTP/1.1\nusername=admin' OR '1'='1&password=test"
    )
    
    # Create validation result
    result = ValidationResult(
        report=report,
        verdict=Verdict.VALID,
        confidence=92,
        key_findings=[
            "SQL injection confirmed in login endpoint",
            "No input sanitization detected",
            "Direct database query execution",
            "Authentication bypass possible"
        ],
        recommendations_security_team=[
            "Implement parameterized queries immediately",
            "Add input validation and sanitization",
            "Review all database queries for similar issues",
            "Enable SQL injection detection in WAF"
        ],
        recommendations_researcher=[
            "Excellent report with clear reproduction steps",
            "Consider testing other endpoints for similar issues"
        ]
    )
    
    # Add CVSS score (calculate from report)
    cvss_calculator = CVSSCalculator()
    result.cvss_score = cvss_calculator.calculate_from_report(report, result)
    
    # Add priority score
    result.priority_score = PriorityScore(
        overall_score=85.0,
        priority_level=PriorityLevel.HIGH,
        recommended_sla="Fix within 7 days",
        escalation_required=True,
        risk_factors=["High CVSS score", "Authentication bypass", "Network accessible"],
        reasoning="Critical authentication vulnerability with high exploitability"
    )
    
    result.processing_time_seconds = 12.5
    result.ai_provider = "anthropic"
    
    return result


def demo_integration_config():
    """Demonstrate integration configuration."""
    console.print("[bold]1. Integration Configuration[/bold]")
    console.print()
    
    config_example = """
# config/default.yaml
integrations:
  enabled: true
  
  jira:
    enabled: true
    config:
      url: "https://company.atlassian.net"
      username: "${JIRA_USERNAME}"
      api_token: "${JIRA_API_TOKEN}"
      project_key: "SEC"
    trigger_on_valid: true
    min_severity: "MEDIUM"
    min_confidence: 70
  
  slack:
    enabled: true
    config:
      webhook_url: "${SLACK_WEBHOOK_URL}"
      channel: "#security-alerts"
    trigger_on_valid: true
    min_severity: "HIGH"
"""
    
    syntax = Syntax(config_example, "yaml", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title="Configuration Example", border_style="green"))
    console.print()


def demo_integration_manager():
    """Demonstrate Integration Manager."""
    console.print("[bold]2. Integration Manager[/bold]")
    console.print()
    
    # Create sample config
    config = {
        'integrations': {
            'enabled': True,
            'slack': {
                'enabled': True,
                'type': 'slack',
                'config': {
                    'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
                    'channel': '#security-alerts'
                },
                'trigger_on_valid': True,
                'trigger_on_invalid': False,
                'min_severity': 'HIGH',
                'min_confidence': 70
            },
            'jira': {
                'enabled': False,  # Disabled for demo
                'type': 'jira',
                'config': {
                    'url': 'https://company.atlassian.net',
                    'username': 'user@example.com',
                    'api_token': 'your_token'
                }
            }
        }
    }
    
    # Initialize manager
    manager = IntegrationManager(config)
    
    # Display loaded integrations
    table = Table(title="Loaded Integrations", box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Enabled", style="green")
    table.add_column("Triggers", style="yellow")
    
    for integration_info in manager.list_integrations():
        triggers = []
        if integration_info['trigger_on_valid']:
            triggers.append("VALID")
        if integration_info['trigger_on_invalid']:
            triggers.append("INVALID")
        if integration_info['trigger_on_uncertain']:
            triggers.append("UNCERTAIN")
        
        table.add_row(
            integration_info['name'],
            integration_info['type'],
            "✓" if integration_info['enabled'] else "✗",
            ", ".join(triggers)
        )
    
    console.print(table)
    console.print()


def demo_trigger_conditions():
    """Demonstrate trigger conditions."""
    console.print("[bold]3. Trigger Conditions[/bold]")
    console.print()
    
    console.print("Integrations can be configured to trigger based on:")
    console.print("  • [cyan]Verdict[/cyan]: VALID, INVALID, UNCERTAIN")
    console.print("  • [cyan]Severity[/cyan]: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    console.print("  • [cyan]Confidence[/cyan]: 0-100%")
    console.print()
    
    # Create sample validation result
    result = create_sample_validation_result()
    
    # Show trigger evaluation
    table = Table(title="Trigger Evaluation Example", box=box.ROUNDED)
    table.add_column("Integration", style="cyan")
    table.add_column("Condition", style="yellow")
    table.add_column("Result", style="green")
    
    table.add_row(
        "Slack",
        "trigger_on_valid=True, min_severity=HIGH",
        "✓ TRIGGERED (Verdict=VALID, Severity=HIGH)"
    )
    table.add_row(
        "JIRA",
        "trigger_on_valid=True, min_confidence=70",
        "✓ TRIGGERED (Confidence=92%)"
    )
    table.add_row(
        "PagerDuty",
        "trigger_on_valid=True, min_severity=CRITICAL",
        "✗ SKIPPED (Severity=HIGH < CRITICAL)"
    )
    table.add_row(
        "Email",
        "trigger_on_invalid=True",
        "✗ SKIPPED (Verdict=VALID)"
    )
    
    console.print(table)
    console.print()


def demo_integration_results():
    """Demonstrate integration results."""
    console.print("[bold]4. Integration Results[/bold]")
    console.print()
    
    # Create sample results
    results = [
        {
            'name': 'JIRA',
            'status': IntegrationStatus.SUCCESS,
            'message': 'Created JIRA issue SEC-1234',
            'url': 'https://company.atlassian.net/browse/SEC-1234'
        },
        {
            'name': 'Slack',
            'status': IntegrationStatus.SUCCESS,
            'message': 'Slack notification sent successfully',
            'url': None
        },
        {
            'name': 'GitHub',
            'status': IntegrationStatus.SUCCESS,
            'message': 'Created GitHub issue #42',
            'url': 'https://github.com/company/security/issues/42'
        },
        {
            'name': 'PagerDuty',
            'status': IntegrationStatus.SKIPPED,
            'message': 'Severity threshold not met',
            'url': None
        }
    ]
    
    table = Table(title="Integration Execution Results", box=box.ROUNDED)
    table.add_column("Integration", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Message", style="yellow")
    table.add_column("URL", style="blue")
    
    for result in results:
        status_icon = {
            IntegrationStatus.SUCCESS: "✓",
            IntegrationStatus.FAILED: "✗",
            IntegrationStatus.SKIPPED: "⊘",
            IntegrationStatus.PARTIAL: "⚠"
        }.get(result['status'], "?")
        
        table.add_row(
            result['name'],
            f"{status_icon} {result['status'].value}",
            result['message'],
            result['url'] or "-"
        )
    
    console.print(table)
    console.print()


def demo_code_example():
    """Demonstrate code usage."""
    console.print("[bold]5. Code Example[/bold]")
    console.print()
    
    code_example = """
from bountybot.orchestrator import Orchestrator
from bountybot.config_loader import ConfigLoader

# Load configuration
config = ConfigLoader.load_config('config/default.yaml')

# Initialize orchestrator (includes IntegrationManager)
orchestrator = Orchestrator(config)

# Validate report
result = orchestrator.validate_report('report.json')

# Integrations are automatically executed if enabled
if result.integration_results:
    for int_result in result.integration_results:
        if int_result.status == IntegrationStatus.SUCCESS:
            print(f"✓ {int_result.integration_name}: {int_result.message}")
            if int_result.external_url:
                print(f"  URL: {int_result.external_url}")
"""
    
    syntax = Syntax(code_example, "python", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title="Usage Example", border_style="green"))
    console.print()


def demo_supported_integrations():
    """Show supported integrations."""
    console.print("[bold]6. Supported Integrations[/bold]")
    console.print()
    
    table = Table(title="Integration Hub - Supported Platforms", box=box.ROUNDED)
    table.add_column("Platform", style="cyan", width=15)
    table.add_column("Type", style="magenta", width=20)
    table.add_column("Features", style="yellow")
    
    table.add_row(
        "JIRA",
        "Issue Tracker",
        "Create issues, update issues, add comments, priority mapping"
    )
    table.add_row(
        "Slack",
        "Notification",
        "Rich messages, mentions, color coding, detailed findings"
    )
    table.add_row(
        "GitHub",
        "Version Control",
        "Create issues, labels, assignees, markdown formatting"
    )
    table.add_row(
        "PagerDuty",
        "Incident Management",
        "Create incidents, auto-resolve, severity mapping, deduplication"
    )
    table.add_row(
        "Email",
        "Email",
        "HTML/text emails, multiple recipients, SMTP/TLS support"
    )
    
    console.print(table)
    console.print()


def main():
    """Run the demo."""
    print_header()
    
    demo_integration_config()
    demo_integration_manager()
    demo_trigger_conditions()
    demo_integration_results()
    demo_code_example()
    demo_supported_integrations()
    
    console.print(Panel.fit(
        "[bold green]Integration Hub Demo Complete![/bold green]\n"
        "[dim]Configure integrations in config/default.yaml to get started[/dim]",
        border_style="green"
    ))
    console.print()


if __name__ == '__main__':
    main()

