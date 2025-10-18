"""
CLI for GraphQL server.

Provides command-line interface for running the GraphQL server.
"""

import logging
import sys

logger = logging.getLogger(__name__)

# Try to import click
try:
    import click
    CLICK_AVAILABLE = True
except ImportError:
    logger.warning("click package not installed")
    CLICK_AVAILABLE = False
    click = None


if CLICK_AVAILABLE:
    @click.command()
    @click.option('--host', default='0.0.0.0', help='Host to bind to')
    @click.option('--port', default=8001, help='Port to bind to')
    @click.option('--reload', is_flag=True, help='Enable auto-reload')
    @click.option('--log-level', default='info', help='Log level')
    def serve(host: str, port: int, reload: bool, log_level: str):
        """
        Start GraphQL server.
        
        Args:
            host: Host to bind to
            port: Port to bind to
            reload: Enable auto-reload
            log_level: Log level
        """
        # Check if dependencies available
        try:
            import uvicorn
            from .app import graphql_app
        except ImportError as e:
            click.echo(f"❌ Error: Required packages not installed: {e}", err=True)
            click.echo("Install with: pip install 'strawberry-graphql[fastapi]' uvicorn", err=True)
            sys.exit(1)
        
        if not graphql_app:
            click.echo("❌ Error: GraphQL app not available", err=True)
            sys.exit(1)
        
        # Display startup message
        click.echo("=" * 60)
        click.echo("🚀 BountyBot GraphQL Server")
        click.echo("=" * 60)
        click.echo(f"Host: {host}")
        click.echo(f"Port: {port}")
        click.echo(f"Reload: {reload}")
        click.echo(f"Log Level: {log_level}")
        click.echo("=" * 60)
        click.echo()
        click.echo("📚 GraphQL Endpoints:")
        click.echo(f"  - GraphQL API: http://{host}:{port}/graphql")
        click.echo(f"  - GraphiQL IDE: http://{host}:{port}/graphql (in browser)")
        click.echo(f"  - WebSocket: ws://{host}:{port}/graphql")
        click.echo()
        click.echo("🔑 Authentication:")
        click.echo("  Add 'Authorization: Bearer <api_key>' header to requests")
        click.echo()
        click.echo("📖 Example Queries:")
        click.echo("  - Query: { hello }")
        click.echo("  - Query: { version }")
        click.echo("  - Query: { metrics { totalReports validReports } }")
        click.echo()
        click.echo("📡 Example Subscriptions:")
        click.echo("  - subscription { heartbeat(interval: 5) }")
        click.echo("  - subscription { validationStatusUpdates { reportId status } }")
        click.echo("  - subscription { metricsUpdates { totalReports } }")
        click.echo()
        click.echo("Starting server...")
        click.echo()
        
        # Start server
        uvicorn.run(
            "bountybot.graphql.app:graphql_app",
            host=host,
            port=port,
            reload=reload,
            log_level=log_level
        )
    
    
    @click.group()
    def graphql_cli():
        """GraphQL server commands."""
        pass
    
    
    graphql_cli.add_command(serve)

else:
    def serve():
        """Stub function when click not available."""
        print("Error: click package not installed")
        print("Install with: pip install click")
        sys.exit(1)
    
    def graphql_cli():
        """Stub function when click not available."""
        print("Error: click package not installed")
        sys.exit(1)


if __name__ == '__main__':
    if CLICK_AVAILABLE:
        graphql_cli()
    else:
        print("Error: click package not installed")
        print("Install with: pip install click")
        sys.exit(1)


__all__ = ['serve', 'graphql_cli']

