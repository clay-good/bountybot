"""
Interactive debugger for BountyBot validation pipeline.

Provides step-by-step debugging, inspection, and interactive exploration.
"""

import logging
import json
from typing import Dict, Any, Optional, List
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.tree import Tree
from rich.prompt import Prompt, Confirm
from rich import box

logger = logging.getLogger(__name__)
console = Console()


class InteractiveDebugger:
    """
    Interactive debugger for validation pipeline.
    
    Features:
    - Step-by-step validation execution
    - Inspect intermediate results
    - Modify configuration on-the-fly
    - Breakpoints at validation stages
    - Rich visualization of data structures
    """
    
    def __init__(self, orchestrator, config: Dict[str, Any]):
        """
        Initialize interactive debugger.
        
        Args:
            orchestrator: Orchestrator instance
            config: Configuration dictionary
        """
        self.orchestrator = orchestrator
        self.config = config
        self.breakpoints = set()
        self.step_mode = False
        self.inspection_data = {}
        
    def enable_step_mode(self):
        """Enable step-by-step execution."""
        self.step_mode = True
        console.print("[yellow]Step mode enabled - press Enter to continue at each stage[/yellow]")
    
    def add_breakpoint(self, stage: str):
        """
        Add breakpoint at validation stage.
        
        Args:
            stage: Stage name (parsing, extraction, analysis, validation, scoring)
        """
        self.breakpoints.add(stage)
        console.print(f"[green]Breakpoint added at: {stage}[/green]")
    
    def remove_breakpoint(self, stage: str):
        """Remove breakpoint."""
        self.breakpoints.discard(stage)
        console.print(f"[yellow]Breakpoint removed: {stage}[/yellow]")
    
    def should_break(self, stage: str) -> bool:
        """Check if should break at stage."""
        return self.step_mode or stage in self.breakpoints
    
    def inspect_report(self, report):
        """
        Inspect parsed report interactively.
        
        Args:
            report: Report object
        """
        console.print(Panel.fit(
            "[bold cyan]Report Inspection[/bold cyan]",
            border_style="cyan"
        ))
        
        # Create report table
        table = Table(title="Report Details", box=box.ROUNDED)
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        table.add_row("ID", report.id)
        table.add_row("Title", report.title[:80] + "..." if len(report.title) > 80 else report.title)
        table.add_row("Vulnerability Type", report.vulnerability_type)
        table.add_row("Severity", report.severity)
        table.add_row("Platform", report.platform)
        table.add_row("Researcher", report.researcher_name or "Unknown")
        
        console.print(table)
        
        # Show description preview
        if report.description:
            console.print("\n[bold]Description Preview:[/bold]")
            preview = report.description[:500] + "..." if len(report.description) > 500 else report.description
            console.print(Panel(preview, border_style="dim"))
        
        # Interactive menu
        while True:
            console.print("\n[bold]Options:[/bold]")
            console.print("  [1] View full description")
            console.print("  [2] View steps to reproduce")
            console.print("  [3] View impact")
            console.print("  [4] View metadata")
            console.print("  [5] Export report as JSON")
            console.print("  [c] Continue")
            
            choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "c"], default="c")
            
            if choice == "1":
                console.print(Panel(report.description, title="Full Description", border_style="cyan"))
            elif choice == "2":
                console.print(Panel(report.steps_to_reproduce or "Not provided", title="Steps to Reproduce", border_style="cyan"))
            elif choice == "3":
                console.print(Panel(report.impact or "Not provided", title="Impact", border_style="cyan"))
            elif choice == "4":
                metadata_json = json.dumps(report.metadata, indent=2)
                syntax = Syntax(metadata_json, "json", theme="monokai", line_numbers=True)
                console.print(Panel(syntax, title="Metadata", border_style="cyan"))
            elif choice == "5":
                output_path = Prompt.ask("Output path", default="report_debug.json")
                with open(output_path, 'w') as f:
                    json.dump(report.__dict__, f, indent=2, default=str)
                console.print(f"[green]Report exported to {output_path}[/green]")
            elif choice == "c":
                break
    
    def inspect_http_requests(self, http_requests: List[Dict[str, Any]]):
        """
        Inspect extracted HTTP requests.
        
        Args:
            http_requests: List of HTTP request dictionaries
        """
        console.print(Panel.fit(
            f"[bold cyan]HTTP Requests Inspection ({len(http_requests)} found)[/bold cyan]",
            border_style="cyan"
        ))
        
        if not http_requests:
            console.print("[yellow]No HTTP requests found[/yellow]")
            return
        
        for idx, req in enumerate(http_requests, 1):
            console.print(f"\n[bold]Request #{idx}:[/bold]")
            
            # Create request table
            table = Table(box=box.SIMPLE)
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            
            table.add_row("Method", req.get('method', 'Unknown'))
            table.add_row("URL", req.get('url', 'Unknown'))
            table.add_row("Headers", str(len(req.get('headers', {}))) + " headers")
            table.add_row("Body", "Present" if req.get('body') else "None")
            
            console.print(table)
            
            # Show details option
            if Confirm.ask(f"View full request #{idx}?", default=False):
                req_json = json.dumps(req, indent=2)
                syntax = Syntax(req_json, "json", theme="monokai", line_numbers=True)
                console.print(Panel(syntax, title=f"Request #{idx}", border_style="cyan"))
    
    def inspect_validation_result(self, result):
        """
        Inspect validation result.
        
        Args:
            result: ValidationResult object
        """
        console.print(Panel.fit(
            "[bold cyan]Validation Result Inspection[/bold cyan]",
            border_style="cyan"
        ))
        
        # Verdict panel
        verdict_color = {
            'VALID': 'red',
            'INVALID': 'green',
            'UNCERTAIN': 'yellow'
        }
        
        verdict_panel = Panel(
            f"[bold {verdict_color.get(result.verdict.value, 'white')}]{result.verdict.value}[/bold {verdict_color.get(result.verdict.value, 'white')}]\n"
            f"Confidence: {result.confidence:.1%}\n"
            f"Severity: {result.severity}",
            title="Verdict",
            border_style=verdict_color.get(result.verdict.value, 'white')
        )
        console.print(verdict_panel)
        
        # Reasoning
        console.print("\n[bold]Reasoning:[/bold]")
        console.print(Panel(result.reasoning, border_style="dim"))
        
        # Recommendations
        if result.recommendations:
            console.print("\n[bold]Recommendations:[/bold]")
            for idx, rec in enumerate(result.recommendations, 1):
                console.print(f"  {idx}. {rec}")
        
        # Interactive menu
        while True:
            console.print("\n[bold]Options:[/bold]")
            console.print("  [1] View quality assessment")
            console.print("  [2] View plausibility analysis")
            console.print("  [3] View code analysis")
            console.print("  [4] View dynamic scan results")
            console.print("  [5] View metadata")
            console.print("  [6] Export result as JSON")
            console.print("  [c] Continue")
            
            choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "c"], default="c")
            
            if choice == "1":
                quality = result.metadata.get('quality_assessment', {})
                quality_json = json.dumps(quality, indent=2)
                syntax = Syntax(quality_json, "json", theme="monokai", line_numbers=True)
                console.print(Panel(syntax, title="Quality Assessment", border_style="cyan"))
            elif choice == "2":
                plausibility = result.metadata.get('plausibility_analysis', {})
                plausibility_json = json.dumps(plausibility, indent=2)
                syntax = Syntax(plausibility_json, "json", theme="monokai", line_numbers=True)
                console.print(Panel(syntax, title="Plausibility Analysis", border_style="cyan"))
            elif choice == "3":
                code_analysis = result.metadata.get('code_analysis', {})
                code_json = json.dumps(code_analysis, indent=2)
                syntax = Syntax(code_json, "json", theme="monokai", line_numbers=True)
                console.print(Panel(syntax, title="Code Analysis", border_style="cyan"))
            elif choice == "4":
                scan_results = result.metadata.get('dynamic_scan', {})
                scan_json = json.dumps(scan_results, indent=2)
                syntax = Syntax(scan_json, "json", theme="monokai", line_numbers=True)
                console.print(Panel(syntax, title="Dynamic Scan Results", border_style="cyan"))
            elif choice == "5":
                metadata_json = json.dumps(result.metadata, indent=2)
                syntax = Syntax(metadata_json, "json", theme="monokai", line_numbers=True)
                console.print(Panel(syntax, title="Full Metadata", border_style="cyan"))
            elif choice == "6":
                output_path = Prompt.ask("Output path", default="validation_result_debug.json")
                with open(output_path, 'w') as f:
                    json.dump({
                        'verdict': result.verdict.value,
                        'confidence': result.confidence,
                        'severity': result.severity,
                        'reasoning': result.reasoning,
                        'recommendations': result.recommendations,
                        'metadata': result.metadata
                    }, f, indent=2, default=str)
                console.print(f"[green]Result exported to {output_path}[/green]")
            elif choice == "c":
                break
    
    def wait_for_continue(self, stage: str):
        """
        Wait for user to continue at stage.
        
        Args:
            stage: Current stage name
        """
        if self.should_break(stage):
            console.print(f"\n[yellow]⏸  Paused at stage: {stage}[/yellow]")
            console.print("[dim]Press Enter to continue, or type 'help' for options[/dim]")
            
            user_input = Prompt.ask("", default="")
            
            if user_input.lower() == 'help':
                self.show_help()
                self.wait_for_continue(stage)
            elif user_input.lower().startswith('inspect'):
                console.print("[yellow]Inspection data available in self.inspection_data[/yellow]")
                self.wait_for_continue(stage)
    
    def show_help(self):
        """Show help menu."""
        help_table = Table(title="Interactive Debugger Help", box=box.ROUNDED)
        help_table.add_column("Command", style="cyan")
        help_table.add_column("Description", style="white")
        
        help_table.add_row("Enter", "Continue to next stage")
        help_table.add_row("help", "Show this help menu")
        help_table.add_row("inspect", "Inspect current data")
        
        console.print(help_table)

