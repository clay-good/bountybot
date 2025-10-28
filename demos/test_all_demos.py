#!/usr/bin/env python3
"""
Test all demo scripts to ensure they run without errors.
"""

import subprocess
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

# List of all demo scripts
DEMO_SCRIPTS = [
    "demo_advanced_analysis.py",
    "demo_advanced_features.py",
    "demo_advanced_scanners.py",
    "demo_ai_providers.py",
    "demo_api.py",
    "demo_async_performance.py",
    "demo_audit.py",
    "demo_auth.py",
    "demo_autoscaling.py",
    "demo_backup.py",
    "demo_cache.py",
    "demo_collaboration.py",
    "demo_compliance.py",
    "demo_continuous_validation.py",
    "demo_dashboard.py",
    "demo_database.py",
    "demo_developer_experience.py",
    "demo_distributed_tracing.py",
    "demo_dynamic_scanner.py",
    "demo_graphql.py",
    "demo_html_validation.py",
    "demo_integrations.py",
    "demo_ml.py",
    "demo_monitoring.py",
    "demo_prioritization.py",
    "demo_prompt_caching.py",
    "demo_reporting.py",
    "demo_secrets.py",
    "demo_security_intelligence.py",
    "demo_tasks.py",
    "demo_tenancy.py",
    "demo_threat_intel.py",
    "demo_webhooks.py",
]


def run_demo(script_path: str) -> tuple[bool, str, float]:
    """Run a demo script and return success status, output, and execution time."""
    import time

    # Demos that intentionally show errors as part of their demonstration
    DEMOS_WITH_INTENTIONAL_ERRORS = [
        "demo_developer_experience.py",  # Shows error handling examples
    ]

    start_time = time.time()
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=30,  # 30 second timeout per demo
            cwd=Path.cwd()
        )
        execution_time = time.time() - start_time

        # Check for errors
        if result.returncode != 0:
            return False, result.stderr or result.stdout, execution_time

        # For demos that intentionally show errors, check if they completed successfully
        script_name = Path(script_path).name
        if script_name in DEMOS_WITH_INTENTIONAL_ERRORS:
            # Check if demo completed (look for completion message)
            if "Demo Complete" in result.stdout or "All Demos Complete" in result.stdout:
                return True, result.stdout, execution_time

        # Check for Python exceptions in output (but not in demos that intentionally show them)
        if "Traceback" in result.stderr or "Error:" in result.stderr:
            if script_name not in DEMOS_WITH_INTENTIONAL_ERRORS:
                return False, result.stderr, execution_time

        return True, result.stdout, execution_time

    except subprocess.TimeoutExpired:
        execution_time = time.time() - start_time
        return False, "TIMEOUT (>30s)", execution_time
    except Exception as e:
        execution_time = time.time() - start_time
        return False, str(e), execution_time


def main():
    """Test all demo scripts."""
    console.print("\n[bold cyan]Testing All Demo Scripts[/bold cyan]\n")
    
    results = []
    total_time = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("Testing demos...", total=len(DEMO_SCRIPTS))
        
        for script in DEMO_SCRIPTS:
            progress.update(task, description=f"Testing {script}...")
            
            success, output, exec_time = run_demo(script)
            total_time += exec_time
            
            results.append({
                'script': script,
                'success': success,
                'output': output,
                'time': exec_time
            })
            
            progress.advance(task)
    
    # Display results
    table = Table(title="Demo Test Results", box=box.ROUNDED)
    table.add_column("Demo Script", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Time", style="yellow", justify="right")
    
    passed = 0
    failed = 0
    
    for result in results:
        status = "[green]✓ PASS[/green]" if result['success'] else "[red]✗ FAIL[/red]"
        time_str = f"{result['time']:.2f}s"
        
        table.add_row(result['script'], status, time_str)
        
        if result['success']:
            passed += 1
        else:
            failed += 1
    
    console.print(table)
    console.print()
    
    # Summary
    console.print(f"[bold]Summary:[/bold]")
    console.print(f"  Total demos: {len(DEMO_SCRIPTS)}")
    console.print(f"  [green]Passed: {passed}[/green]")
    console.print(f"  [red]Failed: {failed}[/red]")
    console.print(f"  Total time: {total_time:.2f}s")
    console.print()
    
    # Show failures
    if failed > 0:
        console.print("[bold red]Failed Demos:[/bold red]\n")
        for result in results:
            if not result['success']:
                console.print(f"[red]✗ {result['script']}[/red]")
                console.print(f"  Error: {result['output'][:200]}...")
                console.print()
    
    # Exit with appropriate code
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()

