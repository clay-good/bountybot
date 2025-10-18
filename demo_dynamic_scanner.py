#!/usr/bin/env python3

import sys
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Add parent directory to path
sys.path.insert(0, '.')

from bountybot.scanners import DynamicScanner

console = Console()


def print_header():
    """Print demo header."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]BountyBot Dynamic Security Scanner Demo[/bold cyan]\n"
        "[dim]Safe, controlled vulnerability testing[/dim]",
        border_style="cyan"
    ))
    console.print()


def demo_scanner_initialization():
    """Demo 1: Scanner initialization."""
    console.print("[bold yellow]Demo 1: Scanner Initialization[/bold yellow]")
    console.print()
    
    config = {
        'timeout': 10,
        'max_requests': 100,
        'delay': 0.5,
        'verify_ssl': True,
    }
    
    scanner = DynamicScanner(config)
    
    console.print("[green]✓[/green] Scanner initialized with configuration:")
    console.print(f"  • Timeout: {scanner.timeout}s")
    console.print(f"  • Max requests: {scanner.max_requests}")
    console.print(f"  • Delay between requests: {scanner.delay_between_requests}s")
    console.print(f"  • SSL verification: {scanner.verify_ssl}")
    console.print()
    
    scanner.close()
    return scanner


def demo_sql_injection_scan():
    """Demo 2: SQL injection scanning."""
    console.print("[bold yellow]Demo 2: SQL Injection Scanning[/bold yellow]")
    console.print()
    
    # Note: This is a demo with a mock vulnerable URL
    # In production, only scan systems you have permission to test
    
    console.print("[dim]Scanning for SQL injection vulnerabilities...[/dim]")
    console.print()
    
    # Show what payloads would be tested
    console.print("[cyan]SQL Injection Payloads:[/cyan]")
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
    ]
    
    for payload in payloads:
        console.print(f"  • {payload}")
    console.print()
    
    console.print("[cyan]Detection Methods:[/cyan]")
    console.print("  • SQL error pattern matching")
    console.print("  • Database-specific error messages")
    console.print("  • Response time analysis")
    console.print()


def demo_xss_scan():
    """Demo 3: XSS scanning."""
    console.print("[bold yellow]Demo 3: Cross-Site Scripting (XSS) Scanning[/bold yellow]")
    console.print()
    
    console.print("[dim]Scanning for XSS vulnerabilities...[/dim]")
    console.print()
    
    console.print("[cyan]XSS Payloads:[/cyan]")
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
    ]
    
    for payload in payloads:
        console.print(f"  • {payload}")
    console.print()
    
    console.print("[cyan]Detection Methods:[/cyan]")
    console.print("  • Payload reflection in response")
    console.print("  • Context-aware detection")
    console.print("  • DOM-based XSS indicators")
    console.print()


def demo_command_injection_scan():
    """Demo 4: Command injection scanning."""
    console.print("[bold yellow]Demo 4: Command Injection Scanning[/bold yellow]")
    console.print()
    
    console.print("[dim]Scanning for command injection vulnerabilities...[/dim]")
    console.print()
    
    console.print("[cyan]Command Injection Payloads:[/cyan]")
    payloads = [
        "; echo 'vulnerable'",
        "| echo 'vulnerable'",
        "& echo 'vulnerable'",
        "`echo 'vulnerable'`",
        "$(echo 'vulnerable')",
    ]
    
    for payload in payloads:
        console.print(f"  • {payload}")
    console.print()
    
    console.print("[cyan]Detection Methods:[/cyan]")
    console.print("  • Command output in response")
    console.print("  • Time-based detection")
    console.print("  • Error message analysis")
    console.print()


def demo_scan_results():
    """Demo 5: Scan results and reporting."""
    console.print("[bold yellow]Demo 5: Scan Results and Reporting[/bold yellow]")
    console.print()
    
    # Create mock scan results
    console.print("[cyan]Example Scan Results:[/cyan]")
    console.print()
    
    # Create results table
    table = Table(title="Security Findings", box=box.ROUNDED)
    table.add_column("Vulnerability", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Parameter", style="yellow")
    table.add_column("Confidence", style="green")
    
    table.add_row("SQL Injection", "CRITICAL", "id", "85%")
    table.add_row("XSS", "HIGH", "search", "80%")
    table.add_row("Open Redirect", "MEDIUM", "redirect", "90%")
    
    console.print(table)
    console.print()
    
    # Severity breakdown
    console.print("[cyan]Severity Breakdown:[/cyan]")
    console.print("  • CRITICAL: 1")
    console.print("  • HIGH: 1")
    console.print("  • MEDIUM: 1")
    console.print("  • LOW: 0")
    console.print()
    
    # Scan statistics
    console.print("[cyan]Scan Statistics:[/cyan]")
    console.print("  • Target: http://example.com")
    console.print("  • Duration: 45.3 seconds")
    console.print("  • Requests sent: 87")
    console.print("  • Findings: 3")
    console.print()


def demo_safety_features():
    """Demo 6: Safety features."""
    console.print("[bold yellow]Demo 6: Safety Features[/bold yellow]")
    console.print()
    
    console.print("[cyan]Built-in Safety Controls:[/cyan]")
    console.print()
    
    console.print("[green]✓[/green] Rate limiting:")
    console.print("  • Configurable delay between requests")
    console.print("  • Maximum request limit")
    console.print("  • Prevents overwhelming target systems")
    console.print()
    
    console.print("[green]✓[/green] Safe payloads:")
    console.print("  • Detection-only payloads")
    console.print("  • No destructive operations")
    console.print("  • No data exfiltration")
    console.print()
    
    console.print("[green]✓[/green] Timeout controls:")
    console.print("  • Configurable request timeout")
    console.print("  • Prevents hanging connections")
    console.print("  • Graceful error handling")
    console.print()
    
    console.print("[green]✓[/green] SSL verification:")
    console.print("  • Optional SSL certificate validation")
    console.print("  • Secure communication")
    console.print()


def demo_integration():
    """Demo 7: Integration with BountyBot."""
    console.print("[bold yellow]Demo 7: Integration with BountyBot[/bold yellow]")
    console.print()
    
    console.print("[cyan]Dynamic scanning is integrated into the validation pipeline:[/cyan]")
    console.print()
    
    console.print("1. [dim]Parse report[/dim]")
    console.print("2. [dim]Pre-validate quality[/dim]")
    console.print("3. [dim]Extract HTTP requests[/dim]")
    console.print("4. [dim]AI quality assessment[/dim]")
    console.print("5. [dim]AI plausibility analysis[/dim]")
    console.print("6. [dim]Code analysis (optional)[/dim]")
    console.print("7. [bold green]→ Dynamic scanning (NEW!)[/bold green]")
    console.print("8. [dim]AI final verdict[/dim]")
    console.print("9. [dim]CVSS scoring[/dim]")
    console.print("10. [dim]Duplicate detection[/dim]")
    console.print()
    
    console.print("[cyan]Usage:[/cyan]")
    console.print()
    console.print("[dim]$ python3 -m bountybot.cli report.json --target http://example.com[/dim]")
    console.print()
    
    console.print("[cyan]Configuration:[/cyan]")
    console.print()
    console.print("[dim]# config/default.yaml[/dim]")
    console.print("[dim]dynamic_scanning:[/dim]")
    console.print("[dim]  enabled: true[/dim]")
    console.print("[dim]  timeout: 10[/dim]")
    console.print("[dim]  max_requests: 100[/dim]")
    console.print("[dim]  delay: 0.5[/dim]")
    console.print()


def main():
    """Run all demos."""
    print_header()
    
    try:
        demo_scanner_initialization()
        console.print("─" * 80)
        console.print()
        
        demo_sql_injection_scan()
        console.print("─" * 80)
        console.print()
        
        demo_xss_scan()
        console.print("─" * 80)
        console.print()
        
        demo_command_injection_scan()
        console.print("─" * 80)
        console.print()
        
        demo_scan_results()
        console.print("─" * 80)
        console.print()
        
        demo_safety_features()
        console.print("─" * 80)
        console.print()
        
        demo_integration()
        
        # Summary
        console.print()
        console.print(Panel.fit(
            "[bold green]✓ Dynamic Scanner Demo Complete![/bold green]\n\n"
            "[cyan]Key Features:[/cyan]\n"
            "• SQL Injection detection\n"
            "• XSS detection\n"
            "• Command Injection detection\n"
            "• Path Traversal detection\n"
            "• SSRF detection\n"
            "• Open Redirect detection\n"
            "• Safe, controlled testing\n"
            "• Integrated with validation pipeline\n\n"
            "[yellow]⚠ Important:[/yellow] Only scan systems you have permission to test!",
            border_style="green"
        ))
        console.print()
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

