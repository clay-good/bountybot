import logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from bountybot.models import ValidationResult, Verdict

logger = logging.getLogger(__name__)


class TerminalOutput:
    """
    Formats validation results for terminal display with colors.
    """
    
    def __init__(self):
        self.console = Console()
    
    def display(self, result: ValidationResult):
        """
        Display validation result in terminal.
        
        Args:
            result: Validation result
        """
        # Header
        self.console.print()
        self.console.rule("[bold]Vulnerability Validation Report[/bold]")
        self.console.print()
        
        # Verdict panel
        verdict_color = {
            Verdict.VALID: "red",
            Verdict.INVALID: "green",
            Verdict.UNCERTAIN: "yellow",
        }
        
        verdict_text = f"[bold {verdict_color[result.verdict]}]{result.verdict.value}[/bold {verdict_color[result.verdict]}]"
        confidence_text = f"Confidence: {result.confidence}%"
        
        self.console.print(Panel(
            f"{verdict_text}\n{confidence_text}",
            title="Verdict",
            border_style=verdict_color[result.verdict]
        ))
        self.console.print()
        
        # Report details
        details_table = Table(title="Report Details", box=box.ROUNDED)
        details_table.add_column("Field", style="cyan")
        details_table.add_column("Value", style="white")
        
        details_table.add_row("Title", result.report.title)
        if result.report.researcher:
            details_table.add_row("Researcher", result.report.researcher)
        if result.report.vulnerability_type:
            details_table.add_row("Type", result.report.vulnerability_type)
        if result.report.severity:
            details_table.add_row("Severity", result.report.severity.value)
        
        self.console.print(details_table)
        self.console.print()
        
        # Quality assessment
        if result.quality_assessment:
            qa = result.quality_assessment
            qa_table = Table(title="Quality Assessment", box=box.ROUNDED)
            qa_table.add_column("Metric", style="cyan")
            qa_table.add_column("Score", style="white")
            
            qa_table.add_row("Quality", f"{qa.quality_score}/10")
            qa_table.add_row("Completeness", f"{qa.completeness_score}/10")
            qa_table.add_row("Technical Accuracy", f"{qa.technical_accuracy}/10")
            
            self.console.print(qa_table)
            self.console.print()
            
            if qa.strengths:
                self.console.print("[bold green]Strengths:[/bold green]")
                for strength in qa.strengths:
                    self.console.print(f"  + {strength}")
                self.console.print()
            
            if qa.concerns:
                self.console.print("[bold yellow]Concerns:[/bold yellow]")
                for concern in qa.concerns:
                    self.console.print(f"  - {concern}")
                self.console.print()
        
        # Plausibility analysis
        if result.plausibility_analysis:
            pa = result.plausibility_analysis
            self.console.print(f"[bold]Plausibility Score:[/bold] {pa.plausibility_score}/100")
            
            if pa.reasoning:
                self.console.print(Panel(pa.reasoning, title="Analysis", border_style="blue"))
            self.console.print()
        
        # Code analysis
        if result.code_analysis:
            ca = result.code_analysis
            status = "[red]Yes[/red]" if ca.vulnerable_code_found else "[green]No[/green]"
            self.console.print(f"[bold]Vulnerable Code Found:[/bold] {status}")
            self.console.print(f"[bold]Code Analysis Confidence:[/bold] {ca.confidence}/100")

            if ca.vulnerable_files:
                self.console.print(f"\n[yellow]Vulnerable Files ({len(ca.vulnerable_files)}):[/yellow]")
                for file in ca.vulnerable_files[:5]:
                    self.console.print(f"  - {file}")
            self.console.print()

        # HTTP Requests
        if result.extracted_http_requests:
            self.console.print(f"[bold]Extracted HTTP Requests:[/bold] {len(result.extracted_http_requests)}")
            for i, req in enumerate(result.extracted_http_requests[:3], 1):
                self.console.print(f"\n[cyan]Request {i}:[/cyan]")
                self.console.print(f"  Method: {req.method}")
                self.console.print(f"  URL: {req.url}")
                if req.payload_locations:
                    self.console.print(f"  Payload Locations: {', '.join(req.payload_locations)}")
                self.console.print(f"  Confidence: {req.extraction_confidence:.0%}")

            if len(result.extracted_http_requests) > 3:
                self.console.print(f"\n[dim]... and {len(result.extracted_http_requests) - 3} more request(s)[/dim]")
            self.console.print()

            if result.http_validation_issues:
                self.console.print("[yellow]HTTP Validation Issues:[/yellow]")
                for issue in result.http_validation_issues[:5]:
                    self.console.print(f"  - {issue}")
                self.console.print()

        # Generated PoC
        if result.generated_poc:
            poc = result.generated_poc
            self.console.print(Panel(
                f"[bold]Title:[/bold] {poc.title}\n\n{poc.description[:200]}...",
                title="Generated Proof-of-Concept",
                border_style="magenta"
            ))

            if poc.curl_command:
                self.console.print("\n[bold]cURL Command:[/bold]")
                self.console.print(f"[dim]{poc.curl_command[:150]}...[/dim]")

            if poc.safety_notes:
                self.console.print("\n[yellow]Safety Notes:[/yellow]")
                for note in poc.safety_notes[:3]:
                    self.console.print(f"  ⚠ {note}")

            self.console.print()

        # Key findings
        if result.key_findings:
            self.console.print("[bold]Key Findings:[/bold]")
            for finding in result.key_findings:
                self.console.print(f"  - {finding}")
            self.console.print()
        
        # Recommendations
        if result.recommendations_security_team:
            self.console.print("[bold cyan]Recommendations for Security Team:[/bold cyan]")
            for rec in result.recommendations_security_team:
                self.console.print(f"  - {rec}")
            self.console.print()
        
        # Metadata
        self.console.print(f"[dim]AI Provider: {result.ai_provider} ({result.ai_model})[/dim]")
        self.console.print(f"[dim]Cost: ${result.total_cost:.4f} | Time: {result.processing_time_seconds:.2f}s[/dim]")
        self.console.print()
    
    def display_progress(self, message: str):
        """Display progress message."""
        self.console.print(f"[cyan]...[/cyan] {message}")
    
    def display_success(self, message: str):
        """Display success message."""
        self.console.print(f"[green]✓[/green] {message}")
    
    def display_error(self, message: str):
        """Display error message."""
        self.console.print(f"[red]✗[/red] {message}")
    
    def display_warning(self, message: str):
        """Display warning message."""
        self.console.print(f"[yellow]![/yellow] {message}")

