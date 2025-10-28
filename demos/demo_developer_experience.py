#!/usr/bin/env python3
"""
BountyBot v2.8.0 - Developer Experience Demo

Demonstrates the new developer experience features:
- Interactive debugging
- Validation replay
- Enhanced error handling
- Mock data generation
- Test helpers
"""

import sys
import json
import tempfile
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich import box

# Import BountyBot dev tools
from bountybot.dev_tools.mock_data import MockDataGenerator
from bountybot.dev_tools.test_helpers import TestHelpers
from bountybot.debug.validation_replay import ValidationReplay
from bountybot.debug.error_handler import EnhancedErrorHandler

console = Console()


def print_header(title: str):
    """Print section header."""
    console.print("\n")
    console.print(Panel.fit(
        f"[bold cyan]{title}[/bold cyan]",
        border_style="cyan"
    ))


def demo_mock_data_generation():
    """Demo 1: Mock Data Generation."""
    print_header("Demo 1: Mock Data Generation")
    
    console.print("\n[bold]Generating mock bug bounty report...[/bold]")
    
    # Generate report
    report = MockDataGenerator.generate_report(
        vulnerability_type='SQL Injection',
        severity='High',
        include_http_requests=True
    )
    
    # Display report
    table = Table(title="Generated Report", box=box.ROUNDED)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    
    table.add_row("ID", report['id'])
    table.add_row("Title", report['title'][:60] + "...")
    table.add_row("Vulnerability Type", report['vulnerability_type'])
    table.add_row("Severity", report['severity'])
    table.add_row("Platform", report['platform'])
    table.add_row("Researcher", report['researcher_name'])
    
    console.print(table)
    
    # Show description preview
    console.print("\n[bold]Description Preview:[/bold]")
    preview = report['description'][:200] + "..."
    console.print(Panel(preview, border_style="dim"))
    
    console.print("\n[green]✓ Mock report generated successfully![/green]")


def demo_batch_generation():
    """Demo 2: Batch Report Generation."""
    print_header("Demo 2: Batch Report Generation")
    
    console.print("\n[bold]Generating batch of 5 reports...[/bold]")
    
    reports = MockDataGenerator.generate_batch_reports(count=5)
    
    # Display batch
    table = Table(title="Generated Batch", box=box.ROUNDED)
    table.add_column("#", style="cyan", no_wrap=True)
    table.add_column("ID", style="white")
    table.add_column("Vulnerability Type", style="yellow")
    table.add_column("Severity", style="red")
    
    for idx, report in enumerate(reports, 1):
        table.add_row(
            str(idx),
            report['id'],
            report['vulnerability_type'],
            report['severity']
        )
    
    console.print(table)
    console.print("\n[green]✓ Batch generated successfully![/green]")


def demo_test_suite_generation():
    """Demo 3: Test Suite Generation."""
    print_header("Demo 3: Test Suite Generation")
    
    console.print("\n[bold]Generating complete test suite...[/bold]")
    
    suite = MockDataGenerator.generate_test_suite()
    
    # Display suite
    table = Table(title="Test Suite", box=box.ROUNDED)
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="white")
    table.add_column("Description", style="dim")
    
    table.add_row(
        "Valid Reports",
        str(len(suite['valid_reports'])),
        "Reports with genuine vulnerabilities"
    )
    table.add_row(
        "Invalid Reports",
        str(len(suite['invalid_reports'])),
        "Reports without valid vulnerabilities"
    )
    table.add_row(
        "Edge Cases",
        str(len(suite['edge_cases'])),
        "Reports with missing or unusual data"
    )
    
    console.print(table)
    console.print("\n[green]✓ Test suite generated successfully![/green]")


def demo_test_helpers():
    """Demo 4: Test Helpers."""
    print_header("Demo 4: Test Helpers")
    
    console.print("\n[bold]Creating temporary test files...[/bold]")
    
    # Create JSON report
    json_path = TestHelpers.create_temp_report(format='json')
    console.print(f"  ✓ JSON report: {json_path}")
    
    # Create Markdown report
    md_path = TestHelpers.create_temp_report(format='md')
    console.print(f"  ✓ Markdown report: {md_path}")
    
    # Create HTML report
    html_path = TestHelpers.create_temp_report(format='html')
    console.print(f"  ✓ HTML report: {html_path}")
    
    console.print("\n[bold]Creating temporary codebase...[/bold]")
    
    # Create codebase
    codebase_path = TestHelpers.create_temp_codebase({
        'main.py': 'print("Hello, World!")',
        'lib/utils.py': 'def helper():\n    pass',
        'tests/test_main.py': 'def test_main():\n    assert True'
    })
    console.print(f"  ✓ Codebase: {codebase_path}")
    
    # List files
    console.print("\n[bold]Codebase structure:[/bold]")
    for file_path in Path(codebase_path).rglob('*.py'):
        rel_path = file_path.relative_to(codebase_path)
        console.print(f"  - {rel_path}")
    
    console.print("\n[green]✓ Test files created successfully![/green]")
    
    # Cleanup
    Path(json_path).unlink()
    Path(md_path).unlink()
    Path(html_path).unlink()


def demo_mock_ai_provider():
    """Demo 5: Mock AI Provider."""
    print_header("Demo 5: Mock AI Provider")
    
    console.print("\n[bold]Creating mock AI provider...[/bold]")
    
    # Create mock provider
    provider = TestHelpers.mock_ai_provider(
        response="This is a valid SQL injection vulnerability.",
        cost=0.05,
        input_tokens=150,
        output_tokens=75
    )
    
    console.print("  ✓ Mock provider created")
    
    # Use provider
    console.print("\n[bold]Calling mock provider...[/bold]")
    result = provider.complete("Analyze this vulnerability")
    
    # Display result
    table = Table(title="Mock Provider Response", box=box.ROUNDED)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Response", result['response'][:60] + "...")
    table.add_row("Cost", f"${result['cost']:.4f}")
    table.add_row("Input Tokens", str(result['input_tokens']))
    table.add_row("Output Tokens", str(result['output_tokens']))
    
    console.print(table)
    console.print("\n[green]✓ Mock provider works perfectly![/green]")


def demo_validation_replay():
    """Demo 6: Validation Replay."""
    print_header("Demo 6: Validation Replay")
    
    console.print("\n[bold]Creating validation snapshot...[/bold]")
    
    # Create replay manager
    with tempfile.TemporaryDirectory() as tmpdir:
        replay = ValidationReplay(tmpdir)
        
        # Save snapshot
        snapshot_id = replay.save_snapshot(
            report_path='demo_report.json',
            config={'api': {'default_provider': 'anthropic'}},
            report_data={'id': 'DEMO-123', 'title': 'SQL Injection Demo'},
            http_requests=[{'method': 'POST', 'url': 'https://example.com/api'}],
            quality_assessment={'score': 0.95},
            plausibility_analysis={'score': 0.90},
            validation_result={
                'verdict': 'VALID',
                'confidence': 0.95,
                'severity': 'High',
                'reasoning': 'This is a genuine SQL injection vulnerability.'
            },
            performance_metrics={
                'parsing': 0.5,
                'extraction': 0.3,
                'validation': 2.5,
                'total': 3.3
            }
        )
        
        console.print(f"  ✓ Snapshot saved: {snapshot_id}")
        
        # List snapshots
        console.print("\n[bold]Listing snapshots...[/bold]")
        snapshots = replay.list_snapshots()
        console.print(f"  Found {len(snapshots)} snapshot(s)")
        
        # Display snapshot
        console.print("\n[bold]Snapshot details:[/bold]")
        replay.display_snapshot(snapshot_id)
    
    console.print("\n[green]✓ Validation replay demonstrated![/green]")


def demo_enhanced_error_handling():
    """Demo 7: Enhanced Error Handling."""
    print_header("Demo 7: Enhanced Error Handling")
    
    console.print("\n[bold]Demonstrating enhanced error handling...[/bold]")
    
    handler = EnhancedErrorHandler(debug_mode=False)
    
    # Demo 1: File not found error
    console.print("\n[bold]Example 1: File Not Found Error[/bold]")
    try:
        with open('nonexistent_file.json', 'r') as f:
            pass
    except FileNotFoundError as e:
        handler.handle_error(
            e,
            context={'file_path': 'nonexistent_file.json', 'operation': 'read'},
            show_traceback=False
        )
    
    # Demo 2: Connection error
    console.print("\n[bold]Example 2: API Connection Error[/bold]")
    error = ConnectionError("Failed to connect to API endpoint")
    handler.handle_api_error(
        error,
        provider='anthropic',
        operation='complete',
        context={'model': 'claude-sonnet-4', 'endpoint': 'https://api.anthropic.com'}
    )
    
    console.print("\n[green]✓ Enhanced error handling demonstrated![/green]")


def demo_performance_measurement():
    """Demo 8: Performance Measurement."""
    print_header("Demo 8: Performance Measurement")
    
    console.print("\n[bold]Measuring function performance...[/bold]")
    
    # Define test function
    def slow_function(n):
        import time
        time.sleep(0.1)
        return sum(range(n))
    
    # Measure performance
    metrics = TestHelpers.measure_performance(slow_function, 1000)
    
    # Display metrics
    table = Table(title="Performance Metrics", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Result", str(metrics['result']))
    table.add_row("Duration", f"{metrics['duration']:.4f}s")
    table.add_row("Start Time", f"{metrics['start_time']:.2f}")
    table.add_row("End Time", f"{metrics['end_time']:.2f}")
    
    console.print(table)
    console.print("\n[green]✓ Performance measured successfully![/green]")


def main():
    """Run all demos."""
    console.print(Panel.fit(
        "[bold cyan]BountyBot v2.8.0 - Developer Experience Demo[/bold cyan]\n"
        "Showcasing new developer tools and utilities",
        title="🛠️  Developer Experience",
        border_style="cyan"
    ))
    
    demos = [
        ("Mock Data Generation", demo_mock_data_generation),
        ("Batch Generation", demo_batch_generation),
        ("Test Suite Generation", demo_test_suite_generation),
        ("Test Helpers", demo_test_helpers),
        ("Mock AI Provider", demo_mock_ai_provider),
        ("Validation Replay", demo_validation_replay),
        ("Enhanced Error Handling", demo_enhanced_error_handling),
        ("Performance Measurement", demo_performance_measurement),
    ]
    
    for idx, (name, demo_func) in enumerate(demos, 1):
        try:
            demo_func()
        except Exception as e:
            console.print(f"\n[red]Error in {name}: {e}[/red]")
    
    # Final summary
    console.print("\n")
    console.print(Panel.fit(
        "[bold green]All Demos Complete! ✨[/bold green]\n\n"
        "BountyBot v2.8.0 delivers world-class developer experience:\n"
        "  ✓ Interactive debugging\n"
        "  ✓ Validation replay\n"
        "  ✓ Enhanced error handling\n"
        "  ✓ Mock data generation\n"
        "  ✓ Comprehensive test helpers\n"
        "  ✓ Performance measurement\n\n"
        "Try it yourself:\n"
        "  bountybot-debug validate report.json --step\n"
        "  bountybot-debug doctor",
        title="🎉 Demo Complete",
        border_style="green"
    ))


if __name__ == '__main__':
    main()

