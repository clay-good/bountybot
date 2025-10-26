#!/usr/bin/env python3
"""
BountyBot - Advanced Vulnerability Scanners Demo

Demonstrates the new SSTI, XXE, and JWT vulnerability detection capabilities.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax

console = Console()


def print_header():
    """Print demo header."""
    console.print()
    console.print("=" * 80, style="bold blue")
    console.print("  BountyBot - Advanced Vulnerability Scanners", style="bold blue")
    console.print("=" * 80, style="bold blue")
    console.print()


def demo_overview():
    """Show overview of new scanners."""
    console.print("\n[bold cyan]═══ 1. New Vulnerability Scanners ═══[/bold cyan]\n")
    
    table = Table(title="Advanced Security Scanners", show_header=True, header_style="bold magenta")
    table.add_column("Scanner", style="cyan", width=15)
    table.add_column("Vulnerability Type", style="green", width=25)
    table.add_column("Severity", style="yellow", width=12)
    table.add_column("Detection Method", style="white", width=28)
    
    table.add_row(
        "SSTI",
        "Server-Side Template Injection",
        "CRITICAL",
        "Mathematical expression evaluation"
    )
    table.add_row(
        "XXE",
        "XML External Entity",
        "HIGH",
        "Entity resolution & file access"
    )
    table.add_row(
        "JWT",
        "JSON Web Token Vulnerabilities",
        "CRITICAL",
        "Algorithm & claims analysis"
    )
    
    console.print(table)
    console.print()


def demo_ssti_scanner():
    """Demonstrate SSTI scanner."""
    console.print("\n[bold cyan]═══ 2. SSTI (Server-Side Template Injection) Scanner ═══[/bold cyan]\n")
    
    console.print("[bold yellow]What is SSTI?[/bold yellow]")
    console.print("Server-Side Template Injection occurs when user input is embedded into template")
    console.print("engines without proper sanitization, potentially leading to Remote Code Execution.\n")
    
    console.print("[bold yellow]Supported Template Engines:[/bold yellow]")
    engines = [
        "• Jinja2 (Python) - {{7*7}}",
        "• Twig (PHP) - {{7*7}}",
        "• Freemarker (Java) - ${7*7}",
        "• ERB (Ruby) - <%= 7*7 %>",
        "• Smarty (PHP) - {7*7}",
        "• Velocity (Java) - ${7*7}",
    ]
    for engine in engines:
        console.print(f"  {engine}")
    console.print()
    
    console.print("[bold yellow]Detection Payloads:[/bold yellow]")
    
    payloads_code = """# Safe mathematical expressions to detect SSTI
payloads = [
    '{{7*7}}',      # Should output: 49
    '${7*7}',       # Should output: 49
    '<%= 7*7 %>',   # Should output: 49
    '${{7*7}}',     # Should output: 49
    '#{7*7}',       # Should output: 49
]

# If the expression is evaluated, SSTI is present
if '49' in response.text:
    print("SSTI DETECTED!")"""
    
    syntax = Syntax(payloads_code, "python", theme="monokai", line_numbers=True)
    console.print(syntax)
    console.print()
    
    console.print("[bold green]✅ Scanner Features:[/bold green]")
    console.print("  • Tests multiple template engine syntaxes")
    console.print("  • Safe, non-destructive payloads only")
    console.print("  • Automatic parameter discovery")
    console.print("  • 95% confidence scoring")
    console.print()


def demo_xxe_scanner():
    """Demonstrate XXE scanner."""
    console.print("\n[bold cyan]═══ 3. XXE (XML External Entity) Scanner ═══[/bold cyan]\n")
    
    console.print("[bold yellow]What is XXE?[/bold yellow]")
    console.print("XXE allows attackers to interfere with XML processing, potentially leading to")
    console.print("file disclosure, SSRF, or denial of service.\n")
    
    console.print("[bold yellow]Detection Payload Example:[/bold yellow]")
    
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>
    <data>&xxe;</data>
</root>"""
    
    syntax = Syntax(xxe_payload, "xml", theme="monokai", line_numbers=True)
    console.print(syntax)
    console.print()
    
    console.print("[bold yellow]Detection Indicators:[/bold yellow]")
    indicators = [
        "• File content in response (e.g., hostname)",
        "• XML parsing errors mentioning entities",
        "• External entity resolution errors",
        "• SSRF to attacker-controlled server",
    ]
    for indicator in indicators:
        console.print(f"  {indicator}")
    console.print()
    
    console.print("[bold green]✅ Scanner Features:[/bold green]")
    console.print("  • Tests multiple XXE payload types")
    console.print("  • Detects both in-band and error-based XXE")
    console.print("  • Safe file read attempts only")
    console.print("  • 85% confidence scoring")
    console.print()


def demo_jwt_scanner():
    """Demonstrate JWT scanner."""
    console.print("\n[bold cyan]═══ 4. JWT (JSON Web Token) Scanner ═══[/bold cyan]\n")
    
    console.print("[bold yellow]What are JWT Vulnerabilities?[/bold yellow]")
    console.print("JWT vulnerabilities allow attackers to forge tokens, bypass authentication,")
    console.print("or escalate privileges through improper implementation.\n")
    
    console.print("[bold yellow]Vulnerabilities Detected:[/bold yellow]")
    
    vuln_table = Table(show_header=True, header_style="bold magenta")
    vuln_table.add_column("Vulnerability", style="cyan", width=25)
    vuln_table.add_column("Severity", style="yellow", width=12)
    vuln_table.add_column("Description", style="white", width=40)
    
    vuln_table.add_row(
        "Algorithm 'none'",
        "CRITICAL",
        "Signature verification completely bypassed"
    )
    vuln_table.add_row(
        "Weak Algorithm (HS256)",
        "MEDIUM",
        "Vulnerable to brute force attacks"
    )
    vuln_table.add_row(
        "Missing Expiration",
        "MEDIUM",
        "Token never expires, unlimited validity"
    )
    vuln_table.add_row(
        "Long Token Lifetime",
        "LOW",
        "Token valid for more than 1 hour"
    )
    vuln_table.add_row(
        "Sensitive Data Exposure",
        "HIGH",
        "Password/secrets in JWT payload"
    )
    
    console.print(vuln_table)
    console.print()
    
    console.print("[bold yellow]JWT Analysis Example:[/bold yellow]")
    
    jwt_code = """import base64
import json

# Decode JWT header and payload
header = json.loads(base64.urlsafe_b64decode(jwt_parts[0]))
payload = json.loads(base64.urlsafe_b64decode(jwt_parts[1]))

# Check for vulnerabilities
if header.get('alg') == 'none':
    print("CRITICAL: Algorithm 'none' detected!")

if 'exp' not in payload:
    print("MEDIUM: Missing expiration claim!")

if 'password' in payload:
    print("HIGH: Sensitive data in payload!")"""
    
    syntax = Syntax(jwt_code, "python", theme="monokai", line_numbers=True)
    console.print(syntax)
    console.print()
    
    console.print("[bold green]✅ Scanner Features:[/bold green]")
    console.print("  • Extracts JWT from headers, cookies, or body")
    console.print("  • Analyzes header and payload structure")
    console.print("  • Detects 5+ vulnerability types")
    console.print("  • Confidence scoring per vulnerability")
    console.print()


def demo_usage():
    """Show usage examples."""
    console.print("\n[bold cyan]═══ 5. Usage Examples ═══[/bold cyan]\n")
    
    console.print("[bold yellow]Configuration (config/default.yaml):[/bold yellow]")
    
    config_yaml = """dynamic_scanning:
  enabled: true
  timeout: 10
  max_requests: 100
  scan_types:
    - sqli
    - xss
    - cmdi
    - path_traversal
    - ssrf
    - open_redirect
    - ssti  # NEW: Server-Side Template Injection
    - xxe   # NEW: XML External Entity
    - jwt   # NEW: JWT vulnerabilities"""
    
    syntax = Syntax(config_yaml, "yaml", theme="monokai", line_numbers=True)
    console.print(syntax)
    console.print()
    
    console.print("[bold yellow]Command Line Usage:[/bold yellow]")
    
    cli_examples = """# Scan with all vulnerability types
python3 -m bountybot.cli report.json --target-url https://example.com/api

# Scan specific vulnerability types
python3 -m bountybot.cli report.json --target-url https://example.com \\
    --scan-types ssti,xxe,jwt

# Full validation with dynamic scanning
python3 -m bountybot.cli report.json \\
    --codebase /path/to/src \\
    --target-url https://example.com/api \\
    --output result.json"""
    
    syntax = Syntax(cli_examples, "bash", theme="monokai", line_numbers=True)
    console.print(syntax)
    console.print()
    
    console.print("[bold yellow]Python API Usage:[/bold yellow]")
    
    python_code = """from bountybot.scanners import DynamicScanner

# Initialize scanner
config = {
    'timeout': 10,
    'max_requests': 100,
    'scan_types': ['ssti', 'xxe', 'jwt']
}
scanner = DynamicScanner(config)

# Run scan
result = scanner.scan(
    target_url='https://example.com/api',
    scan_types=['ssti', 'xxe', 'jwt']
)

# Check findings
for finding in result.findings:
    print(f"{finding.vulnerability_type}: {finding.severity.value}")
    print(f"  {finding.description}")
    print(f"  Confidence: {finding.confidence}%")"""
    
    syntax = Syntax(python_code, "python", theme="monokai", line_numbers=True)
    console.print(syntax)
    console.print()


def demo_results():
    """Show example results."""
    console.print("\n[bold cyan]═══ 6. Example Scan Results ═══[/bold cyan]\n")
    
    console.print("[bold yellow]Sample Output:[/bold yellow]\n")
    
    results_table = Table(show_header=True, header_style="bold magenta")
    results_table.add_column("Vulnerability", style="cyan", width=20)
    results_table.add_column("Severity", style="red", width=12)
    results_table.add_column("Parameter", style="green", width=15)
    results_table.add_column("Confidence", style="yellow", width=12)
    results_table.add_column("Evidence", style="white", width=30)
    
    results_table.add_row(
        "SSTI",
        "CRITICAL",
        "template",
        "95%",
        "Expression evaluated: {{7*7}} = 49"
    )
    results_table.add_row(
        "XXE",
        "HIGH",
        "xml_data",
        "85%",
        "File content disclosed: hostname"
    )
    results_table.add_row(
        "JWT - Algorithm None",
        "CRITICAL",
        "Authorization",
        "100%",
        "alg: none in JWT header"
    )
    results_table.add_row(
        "JWT - Sensitive Data",
        "HIGH",
        "Authorization",
        "90%",
        "Password field in JWT payload"
    )
    
    console.print(results_table)
    console.print()


def main():
    """Run the demo."""
    print_header()
    
    demo_overview()
    demo_ssti_scanner()
    demo_xxe_scanner()
    demo_jwt_scanner()
    demo_usage()
    demo_results()
    
    console.print("\n" + "=" * 80, style="bold blue")
    console.print("  Demo Complete!", style="bold green")
    console.print("=" * 80, style="bold blue")
    console.print()
    
    console.print("[bold cyan]✅ Key Takeaways:[/bold cyan]")
    console.print("  • 3 new critical vulnerability scanners added")
    console.print("  • SSTI: Detects template injection in 6+ engines")
    console.print("  • XXE: Identifies XML entity vulnerabilities")
    console.print("  • JWT: Analyzes 5+ token security issues")
    console.print("  • All scanners use safe, non-destructive payloads")
    console.print("  • 506 tests passing (15 new tests added)")
    console.print()
    
    console.print("[bold yellow]📚 Next Steps:[/bold yellow]")
    console.print("  1. Enable dynamic scanning in config/default.yaml")
    console.print("  2. Add ssti, xxe, jwt to scan_types list")
    console.print("  3. Run: python3 -m bountybot.cli report.json --target-url <URL>")
    console.print("  4. Review findings in the validation result")
    console.print()


if __name__ == "__main__":
    main()

