import click
import uvicorn
import logging
import os


@click.command()
@click.option(
    '--host',
    default='0.0.0.0',
    help='Host to bind to (default: 0.0.0.0)'
)
@click.option(
    '--port',
    default=8000,
    type=int,
    help='Port to bind to (default: 8000)'
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
    '--api-key',
    envvar='BOUNTYBOT_API_KEY',
    help='Default API key (can also use BOUNTYBOT_API_KEY env var)'
)
def main(host, port, reload, workers, log_level, api_key):
    """
    Start the BountyBot API server.
    
    Example:
        bountybot-api --host 0.0.0.0 --port 8000
        
        bountybot-api --reload  # Development mode with auto-reload
        
        bountybot-api --workers 4  # Production with 4 workers
    """
    # Set API key in environment if provided
    if api_key:
        os.environ['BOUNTYBOT_API_KEY'] = api_key
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    # Display startup message
    click.echo("=" * 60)
    click.echo("🤖 BountyBot API Server")
    click.echo("=" * 60)
    click.echo(f"Host: {host}")
    click.echo(f"Port: {port}")
    click.echo(f"Workers: {workers}")
    click.echo(f"Log Level: {log_level}")
    click.echo(f"Reload: {reload}")
    click.echo("=" * 60)
    click.echo()
    click.echo("📚 API Documentation:")
    click.echo(f"  - Swagger UI: http://{host}:{port}/docs")
    click.echo(f"  - ReDoc: http://{host}:{port}/redoc")
    click.echo(f"  - OpenAPI JSON: http://{host}:{port}/openapi.json")
    click.echo()
    click.echo("🔑 Authentication:")
    if api_key:
        click.echo("  ✓ Default API key configured")
    else:
        click.echo("  ⚠️  No default API key set")
        click.echo("  Set BOUNTYBOT_API_KEY environment variable or use --api-key")
    click.echo()
    click.echo("=" * 60)
    click.echo()
    
    # Start server
    try:
        uvicorn.run(
            "bountybot.api.server:app",
            host=host,
            port=port,
            reload=reload,
            workers=workers if not reload else 1,  # reload doesn't work with multiple workers
            log_level=log_level,
            access_log=True
        )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        raise


if __name__ == '__main__':
    main()

