"""
Dashboard CLI

Command-line interface for starting the BountyBot dashboard.
"""

import click
import uvicorn
import logging
import os
from pathlib import Path


@click.command()
@click.option(
    '--host',
    default='0.0.0.0',
    help='Host to bind to (default: 0.0.0.0)'
)
@click.option(
    '--port',
    default=8080,
    type=int,
    help='Port to bind to (default: 8080)'
)
@click.option(
    '--reload',
    is_flag=True,
    help='Enable auto-reload for development'
)
@click.option(
    '--workers',
    default=1,
    type=int,
    help='Number of worker processes (default: 1)'
)
@click.option(
    '--log-level',
    default='info',
    type=click.Choice(['debug', 'info', 'warning', 'error', 'critical']),
    help='Log level (default: info)'
)
@click.option(
    '--config',
    type=click.Path(exists=True),
    help='Path to configuration file'
)
@click.option(
    '--theme',
    default='dark',
    type=click.Choice(['dark', 'light']),
    help='Dashboard theme (default: dark)'
)
@click.option(
    '--refresh-interval',
    default=30,
    type=int,
    help='Auto-refresh interval in seconds (default: 30)'
)
def main(host, port, reload, workers, log_level, config, theme, refresh_interval):
    """
    Start the BountyBot Dashboard web interface.
    
    The dashboard provides:
    - Real-time report tracking and management
    - Interactive analytics and visualizations
    - Integration status monitoring
    - Webhook management
    - Batch processing interface
    - System health monitoring
    
    Example:
        bountybot-dashboard --host 0.0.0.0 --port 8080
    """
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    # Load configuration
    dashboard_config = {
        'theme': theme,
        'refresh_interval': refresh_interval
    }
    
    if config:
        try:
            from bountybot.config_loader import ConfigLoader
            full_config = ConfigLoader.load_config(config)
            if 'dashboard' in full_config:
                dashboard_config.update(full_config['dashboard'])
        except Exception as e:
            logger.warning(f"Could not load config file: {e}")
    
    # Display startup message
    click.echo("=" * 70)
    click.echo("🎨 BountyBot Dashboard")
    click.echo("=" * 70)
    click.echo(f"Host: {host}")
    click.echo(f"Port: {port}")
    click.echo(f"Workers: {workers}")
    click.echo(f"Log Level: {log_level}")
    click.echo(f"Reload: {reload}")
    click.echo(f"Theme: {theme}")
    click.echo(f"Refresh Interval: {refresh_interval}s")
    click.echo("=" * 70)
    click.echo()
    click.echo("📊 Dashboard Features:")
    click.echo("  - Real-time report tracking")
    click.echo("  - Interactive analytics")
    click.echo("  - Integration monitoring")
    click.echo("  - Webhook management")
    click.echo("  - Batch processing")
    click.echo("  - System health monitoring")
    click.echo()
    click.echo("🌐 Access Dashboard:")
    click.echo(f"  - Main Dashboard: http://{host}:{port}/")
    click.echo(f"  - Reports: http://{host}:{port}/reports")
    click.echo(f"  - Analytics: http://{host}:{port}/analytics")
    click.echo(f"  - Integrations: http://{host}:{port}/integrations")
    click.echo(f"  - API Docs: http://{host}:{port}/api/docs")
    click.echo()
    click.echo("⚙️  Configuration:")
    if config:
        click.echo(f"  ✓ Config file: {config}")
    else:
        click.echo("  ⚠️  Using default configuration")
    click.echo()
    click.echo("Press CTRL+C to stop the server")
    click.echo("=" * 70)
    click.echo()
    
    # Start the server
    try:
        uvicorn.run(
            "bountybot.dashboard.app:create_dashboard_app",
            host=host,
            port=port,
            reload=reload,
            workers=workers if not reload else 1,
            log_level=log_level,
            factory=True
        )
    except KeyboardInterrupt:
        click.echo("\n\n👋 Dashboard stopped")
    except Exception as e:
        click.echo(f"\n❌ Error starting dashboard: {e}", err=True)
        raise


if __name__ == '__main__':
    main()

