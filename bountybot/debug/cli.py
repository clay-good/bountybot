"""
Debug CLI for BountyBot.

Provides interactive debugging, validation replay, and development tools.
"""

import sys
import logging
from pathlib import Path

try:
    import click
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    
    CLICK_AVAILABLE = True
except ImportError:
    CLICK_AVAILABLE = False
    click = None

from bountybot.config_loader import ConfigLoader
from bountybot.orchestrator import Orchestrator
from bountybot.debug.interactive_debugger import InteractiveDebugger
from bountybot.debug.validation_replay import ValidationReplay
from bountybot.debug.error_handler import EnhancedErrorHandler

logger = logging.getLogger(__name__)
console = Console()


if CLICK_AVAILABLE:
    @click.group()
    @click.option('--debug', is_flag=True, help='Enable debug mode')
    @click.pass_context
    def cli(ctx, debug):
        """BountyBot Debug CLI - Interactive debugging and development tools."""
        ctx.ensure_object(dict)
        ctx.obj['debug'] = debug
        
        # Configure logging
        log_level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler('bountybot_debug.log')]
        )
    
    
    @cli.command()
    @click.argument('report_path', type=click.Path(exists=True))
    @click.option('--config', type=click.Path(exists=True), help='Configuration file')
    @click.option('--codebase', type=click.Path(exists=True), help='Codebase path for analysis')
    @click.option('--target', help='Target URL for dynamic scanning')
    @click.option('--step', is_flag=True, help='Enable step-by-step mode')
    @click.option('--breakpoint', multiple=True, help='Add breakpoint at stage')
    @click.option('--save-snapshot', is_flag=True, help='Save validation snapshot')
    @click.pass_context
    def validate(ctx, report_path, config, codebase, target, step, breakpoint, save_snapshot):
        """
        Validate report with interactive debugging.
        
        Example:
            bountybot-debug validate report.json --step
            bountybot-debug validate report.json --breakpoint parsing --breakpoint validation
        """
        debug_mode = ctx.obj['debug']
        error_handler = EnhancedErrorHandler(debug_mode=debug_mode)
        
        try:
            # Load configuration
            config_loader = ConfigLoader()
            full_config = config_loader.load(config)
            
            # Create orchestrator
            orchestrator = Orchestrator(full_config)
            
            # Create interactive debugger
            debugger = InteractiveDebugger(orchestrator, full_config)
            
            # Configure debugger
            if step:
                debugger.enable_step_mode()
            
            for bp in breakpoint:
                debugger.add_breakpoint(bp)
            
            console.print(Panel.fit(
                "[bold cyan]Interactive Validation Debug Mode[/bold cyan]\n"
                f"Report: {report_path}\n"
                f"Step Mode: {'Enabled' if step else 'Disabled'}\n"
                f"Breakpoints: {', '.join(breakpoint) if breakpoint else 'None'}",
                title="🐛 Debug Mode",
                border_style="cyan"
            ))
            
            # Parse report
            console.print("\n[bold]Stage: Parsing[/bold]")
            debugger.wait_for_continue('parsing')
            
            report = orchestrator._parse_report(report_path)
            debugger.inspect_report(report)
            
            # Extract HTTP requests
            console.print("\n[bold]Stage: HTTP Extraction[/bold]")
            debugger.wait_for_continue('extraction')
            
            http_requests = orchestrator.http_extractor.extract_from_report(report)
            debugger.inspect_http_requests(http_requests)
            
            # Validate
            console.print("\n[bold]Stage: Validation[/bold]")
            debugger.wait_for_continue('validation')
            
            result = orchestrator.validate_report(report_path, codebase, target)
            debugger.inspect_validation_result(result)
            
            # Save snapshot if requested
            if save_snapshot:
                replay = ValidationReplay()
                snapshot_id = replay.save_snapshot(
                    report_path=report_path,
                    config=full_config,
                    report_data=report.__dict__,
                    http_requests=http_requests,
                    quality_assessment={},
                    plausibility_analysis={},
                    validation_result={
                        'verdict': result.verdict.value,
                        'confidence': result.confidence,
                        'severity': result.severity,
                        'reasoning': result.reasoning
                    }
                )
                console.print(f"\n[green]✓ Snapshot saved: {snapshot_id}[/green]")
            
            console.print("\n[bold green]✓ Validation complete[/bold green]")
            
        except Exception as e:
            error_handler.handle_validation_error(
                e,
                report_path=report_path,
                stage='unknown',
                context={'config': config, 'codebase': codebase, 'target': target}
            )
            sys.exit(1)
    
    
    @cli.command()
    @click.option('--snapshot-dir', default='./validation_snapshots', help='Snapshot directory')
    def list_snapshots(snapshot_dir):
        """List all validation snapshots."""
        replay = ValidationReplay(snapshot_dir)
        snapshots = replay.list_snapshots()
        
        if not snapshots:
            console.print("[yellow]No snapshots found[/yellow]")
            return
        
        console.print(Panel.fit(
            f"[bold cyan]Validation Snapshots ({len(snapshots)})[/bold cyan]",
            border_style="cyan"
        ))
        
        table = Table(box=box.ROUNDED)
        table.add_column("#", style="cyan", no_wrap=True)
        table.add_column("Snapshot ID", style="white")
        
        for idx, snapshot_id in enumerate(snapshots, 1):
            table.add_row(str(idx), snapshot_id)
        
        console.print(table)
    
    
    @cli.command()
    @click.argument('snapshot_id')
    @click.option('--snapshot-dir', default='./validation_snapshots', help='Snapshot directory')
    def show_snapshot(snapshot_id, snapshot_dir):
        """Show snapshot details."""
        replay = ValidationReplay(snapshot_dir)
        
        try:
            replay.display_snapshot(snapshot_id)
        except FileNotFoundError:
            console.print(f"[red]Snapshot not found: {snapshot_id}[/red]")
            sys.exit(1)
    
    
    @cli.command()
    @click.argument('snapshot_id1')
    @click.argument('snapshot_id2')
    @click.option('--snapshot-dir', default='./validation_snapshots', help='Snapshot directory')
    def compare(snapshot_id1, snapshot_id2, snapshot_dir):
        """Compare two snapshots."""
        replay = ValidationReplay(snapshot_dir)
        
        try:
            replay.compare_snapshots(snapshot_id1, snapshot_id2)
        except FileNotFoundError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)
    
    
    @cli.command()
    @click.argument('snapshot_id')
    @click.argument('output_path')
    @click.option('--snapshot-dir', default='./validation_snapshots', help='Snapshot directory')
    def export(snapshot_id, output_path, snapshot_dir):
        """Export snapshot to file."""
        replay = ValidationReplay(snapshot_dir)
        
        try:
            replay.export_snapshot(snapshot_id, output_path)
        except FileNotFoundError:
            console.print(f"[red]Snapshot not found: {snapshot_id}[/red]")
            sys.exit(1)
    
    
    @cli.command()
    @click.argument('input_path', type=click.Path(exists=True))
    @click.option('--snapshot-dir', default='./validation_snapshots', help='Snapshot directory')
    def import_snapshot(input_path, snapshot_dir):
        """Import snapshot from file."""
        replay = ValidationReplay(snapshot_dir)
        
        try:
            snapshot_id = replay.import_snapshot(input_path)
            console.print(f"[green]✓ Imported as: {snapshot_id}[/green]")
        except Exception as e:
            console.print(f"[red]Import failed: {e}[/red]")
            sys.exit(1)
    
    
    @cli.command()
    def doctor():
        """Run system diagnostics."""
        console.print(Panel.fit(
            "[bold cyan]BountyBot System Diagnostics[/bold cyan]",
            border_style="cyan"
        ))
        
        # Check Python version
        console.print("\n[bold]Python Version:[/bold]")
        console.print(f"  {sys.version}")
        
        # Check dependencies
        console.print("\n[bold]Dependencies:[/bold]")
        dependencies = [
            ('anthropic', 'Anthropic API'),
            ('openai', 'OpenAI API'),
            ('google.generativeai', 'Google Gemini'),
            ('click', 'CLI framework'),
            ('rich', 'Rich terminal output'),
            ('fastapi', 'REST API'),
            ('strawberry', 'GraphQL'),
            ('sqlalchemy', 'Database ORM'),
            ('redis', 'Redis cache'),
        ]
        
        for module, name in dependencies:
            try:
                __import__(module)
                console.print(f"  ✓ {name}")
            except ImportError:
                console.print(f"  ✗ {name} [dim](not installed)[/dim]")
        
        # Check environment variables
        console.print("\n[bold]Environment Variables:[/bold]")
        import os
        env_vars = [
            'ANTHROPIC_API_KEY',
            'OPENAI_API_KEY',
            'GEMINI_API_KEY',
            'DATABASE_URL',
            'REDIS_URL'
        ]
        
        for var in env_vars:
            if os.getenv(var):
                console.print(f"  ✓ {var} [dim](set)[/dim]")
            else:
                console.print(f"  ✗ {var} [dim](not set)[/dim]")
        
        # Check configuration
        console.print("\n[bold]Configuration:[/bold]")
        try:
            config_loader = ConfigLoader()
            config = config_loader.load()
            console.print(f"  ✓ Configuration loaded")
            console.print(f"  Provider: {config['api']['default_provider']}")
        except Exception as e:
            console.print(f"  ✗ Configuration error: {e}")
        
        console.print("\n[bold green]✓ Diagnostics complete[/bold green]")


if __name__ == '__main__':
    if not CLICK_AVAILABLE:
        print("Error: click package not installed")
        print("Install with: pip install click rich")
        sys.exit(1)
    
    cli()

