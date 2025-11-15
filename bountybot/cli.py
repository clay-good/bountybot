import sys
import logging
import click
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich import box

from bountybot.config_loader import ConfigLoader
from bountybot.orchestrator import Orchestrator
from bountybot import __version__


# Configure logging - file only, no console output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bountybot.log')
    ]
)

logger = logging.getLogger(__name__)
console = Console()


@click.command()
@click.argument('report', type=click.Path(exists=True))
@click.option('--codebase', type=click.Path(exists=True),
              help='Path to application source code for static analysis')
@click.option('--target', type=str,
              help='Base URL for safe dynamic testing')
@click.option('--provider', type=click.Choice(['anthropic', 'openai', 'gemini']),
              default='anthropic', help='AI provider to use')
@click.option('--model', type=str,
              help='Specific model to use (overrides default)')
@click.option('--output', type=str, default='json,markdown',
              help='Output formats (comma-separated: json,markdown,html)')
@click.option('--output-dir', type=click.Path(), default='./validation_results',
              help='Directory for saving results')
@click.option('--config', type=click.Path(exists=True),
              help='Custom configuration file')
@click.option('--parallel', type=int, default=4,
              help='Number of parallel validation tasks')
@click.option('--no-cache', is_flag=True,
              help='Disable response caching')
@click.option('--cost-limit', type=float, default=10.0,
              help='Maximum API cost in USD')
@click.option('--verbose', is_flag=True,
              help='Enable detailed logging')
@click.option('--dry-run', is_flag=True,
              help='Validate configuration without processing')
@click.option('--batch', is_flag=True,
              help='Process all reports in directory (report argument becomes directory path)')
@click.option('--batch-workers', type=int, default=3,
              help='Number of parallel workers for batch processing')
def main(report, codebase, target, provider, model, output, output_dir,
         config, parallel, no_cache, cost_limit, verbose, dry_run, batch, batch_workers):
    """
    bountybot - Enterprise bug bounty validation framework

    Validates bug bounty reports using AI analysis, static code analysis,
    and optional dynamic testing. All output is written to files.

    Example:
        bountybot report.json --codebase ./src --output json,markdown,html
    """
    try:
        # Set logging level
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        # Load configuration
        config_loader = ConfigLoader()

        # Build CLI overrides
        cli_overrides = {
            'api': {
                'default_provider': provider,
            },
            'validation': {
                'parallel_tasks': parallel,
            },
            'output': {
                'formats': output.split(','),
                'directory': output_dir,
            },
            'cost_management': {
                'max_cost_per_validation': cost_limit,
            },
        }

        if model:
            cli_overrides['api']['providers'] = {
                provider: {
                    'model': model,
                }
            }

        # Load and merge configuration
        full_config = config_loader.load(config, cli_overrides)

        # Validate configuration
        if not config_loader.validate_config():
            console.print("[red]Configuration validation failed. Please check your API keys.[/red]")
            sys.exit(1)

        # Dry run - just validate config
        if dry_run:
            console.print(Panel.fit(
                f"[green]Configuration validated successfully[/green]\n\n"
                f"Provider: {full_config['api']['default_provider']}\n"
                f"Model: {full_config['api']['providers'][provider]['model']}\n"
                f"Output formats: {', '.join(full_config['output']['formats'])}",
                title="Dry Run",
                border_style="green"
            ))
            return

        # Initialize orchestrator
        orchestrator = Orchestrator(full_config)

        # Disable cache if requested
        if no_cache:
            orchestrator.ai_provider.cache_enabled = False

        # Display header
        console.print()
        console.print(Panel.fit(
            f"[bold cyan]bountybot v{__version__}[/bold cyan]\n"
            "Enterprise Bug Bounty Validation Framework",
            border_style="cyan"
        ))
        console.print()

        # Batch processing mode
        if batch:
            from bountybot.batch_processor import BatchProcessor

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"[cyan]Processing directory: {report}", total=None)

                batch_processor = BatchProcessor(orchestrator, max_workers=batch_workers)
                summary = batch_processor.process_directory(
                    input_dir=report,
                    output_dir=output_dir,
                    codebase_path=codebase,
                    output_formats=full_config['output']['formats'],
                    parallel=(batch_workers > 1)
                )

                progress.update(task, completed=True)

            # Generate batch report
            batch_report_path = Path(output_dir) / "batch_report.md"
            batch_processor.generate_batch_report(summary, str(batch_report_path))

            # Display summary table
            summary_table = Table(title="Batch Processing Summary", box=box.ROUNDED, border_style="cyan")
            summary_table.add_column("Metric", style="cyan", no_wrap=True)
            summary_table.add_column("Value", style="white")

            summary_table.add_row("Total Reports", str(summary['total']))
            summary_table.add_row("Processed", f"[green]{summary['processed']}[/green]")
            summary_table.add_row("Failed", f"[red]{summary['failed']}[/red]")

            if 'statistics' in summary and summary['statistics']:
                stats = summary['statistics']
                summary_table.add_row("Total Cost", f"${stats.get('total_cost', 0):.4f}")
                summary_table.add_row("Total Time", f"{stats.get('total_time', 0):.2f}s")

                if 'verdicts' in stats:
                    verdict_str = ", ".join([f"{v}: {c}" for v, c in stats['verdicts'].items()])
                    summary_table.add_row("Verdicts", verdict_str)

            summary_table.add_row("Report Location", str(batch_report_path))

            console.print()
            console.print(summary_table)
            console.print()
            sys.exit(0)

        # Single report mode
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            # Parse report
            task1 = progress.add_task("[cyan]Parsing report...", total=None)
            progress.update(task1, completed=True)

            # Code analysis
            if codebase:
                task2 = progress.add_task("[cyan]Analyzing codebase...", total=None)

            # AI validation
            task3 = progress.add_task("[cyan]Running AI validation...", total=None)

            # Validate report
            result = orchestrator.validate_report(report, codebase, target)

            progress.update(task3, completed=True)

            # Save results
            task4 = progress.add_task("[cyan]Generating reports...", total=None)
            output_formats = full_config['output']['formats']
            orchestrator.save_results(result, output_formats, output_dir)
            progress.update(task4, completed=True)

        # Display summary table
        stats = orchestrator.get_stats()

        verdict_color = {
            'VALID': 'red',
            'INVALID': 'green',
            'UNCERTAIN': 'yellow'
        }

        result_table = Table(title="Validation Results", box=box.ROUNDED, border_style="cyan")
        result_table.add_column("Metric", style="cyan", no_wrap=True)
        result_table.add_column("Value", style="white")

        verdict_style = verdict_color.get(result.verdict.value, 'white')
        result_table.add_row("Verdict", f"[{verdict_style}]{result.verdict.value}[/{verdict_style}]")
        result_table.add_row("Confidence", f"{result.confidence}%")
        result_table.add_row("Processing Time", f"{result.processing_time_seconds:.2f}s")
        result_table.add_row("AI Cost", f"${stats['ai_provider']['total_cost']:.4f}")
        result_table.add_row("Output Directory", output_dir)
        result_table.add_row("Output Formats", ", ".join(output_formats))

        console.print()
        console.print(result_table)
        console.print()

        # Exit with appropriate code
        if result.verdict.value == 'VALID':
            sys.exit(0)
        elif result.verdict.value == 'INVALID':
            sys.exit(1)
        else:  # UNCERTAIN
            sys.exit(2)

    except Exception as e:
        logger.exception("Fatal error")
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    main()

