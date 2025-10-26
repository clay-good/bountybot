"""
Development server with hot-reload and debugging features.

Provides a development-friendly server with auto-reload and enhanced debugging.
"""

import logging
import sys
import os
from pathlib import Path
from typing import Optional

try:
    import uvicorn
    from watchfiles import watch
    UVICORN_AVAILABLE = True
except ImportError:
    UVICORN_AVAILABLE = False
    uvicorn = None
    watch = None

from rich.console import Console
from rich.panel import Panel

logger = logging.getLogger(__name__)
console = Console()


class DevServer:
    """
    Development server with hot-reload.
    
    Features:
    - Auto-reload on file changes
    - Enhanced error messages
    - Debug mode enabled
    - Request logging
    - Performance monitoring
    """
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8000,
        reload: bool = True,
        debug: bool = True,
        log_level: str = "debug"
    ):
        """
        Initialize development server.
        
        Args:
            host: Server host
            port: Server port
            reload: Enable auto-reload
            debug: Enable debug mode
            log_level: Logging level
        """
        self.host = host
        self.port = port
        self.reload = reload
        self.debug = debug
        self.log_level = log_level
        
        if not UVICORN_AVAILABLE:
            console.print("[red]Error: uvicorn not installed[/red]")
            console.print("Install with: pip install uvicorn watchfiles")
            sys.exit(1)
    
    def run_api_server(self):
        """Run FastAPI development server."""
        console.print(Panel.fit(
            f"[bold cyan]BountyBot Development Server[/bold cyan]\n"
            f"Host: {self.host}\n"
            f"Port: {self.port}\n"
            f"Reload: {'Enabled' if self.reload else 'Disabled'}\n"
            f"Debug: {'Enabled' if self.debug else 'Disabled'}",
            title="🚀 Dev Server",
            border_style="cyan"
        ))
        
        console.print("\n[bold]Server URLs:[/bold]")
        console.print(f"  API: http://{self.host}:{self.port}")
        console.print(f"  Docs: http://{self.host}:{self.port}/docs")
        console.print(f"  Health: http://{self.host}:{self.port}/health")
        console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")
        
        # Configure uvicorn
        config = uvicorn.Config(
            "bountybot.api.server:app",
            host=self.host,
            port=self.port,
            reload=self.reload,
            log_level=self.log_level,
            access_log=True,
            reload_dirs=["bountybot"] if self.reload else None
        )
        
        server = uvicorn.Server(config)
        server.run()
    
    def run_graphql_server(self):
        """Run GraphQL development server."""
        console.print(Panel.fit(
            f"[bold cyan]BountyBot GraphQL Development Server[/bold cyan]\n"
            f"Host: {self.host}\n"
            f"Port: {self.port}\n"
            f"Reload: {'Enabled' if self.reload else 'Disabled'}\n"
            f"Debug: {'Enabled' if self.debug else 'Disabled'}",
            title="🚀 GraphQL Dev Server",
            border_style="cyan"
        ))
        
        console.print("\n[bold]Server URLs:[/bold]")
        console.print(f"  GraphQL: http://{self.host}:{self.port}/graphql")
        console.print(f"  GraphiQL: http://{self.host}:{self.port}/graphql (browser)")
        console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")
        
        # Configure uvicorn
        config = uvicorn.Config(
            "bountybot.graphql.server:app",
            host=self.host,
            port=self.port,
            reload=self.reload,
            log_level=self.log_level,
            access_log=True,
            reload_dirs=["bountybot"] if self.reload else None
        )
        
        server = uvicorn.Server(config)
        server.run()
    
    def run_with_custom_app(self, app_path: str):
        """
        Run custom ASGI application.
        
        Args:
            app_path: Path to ASGI application (e.g., "myapp:app")
        """
        console.print(Panel.fit(
            f"[bold cyan]Custom Development Server[/bold cyan]\n"
            f"App: {app_path}\n"
            f"Host: {self.host}\n"
            f"Port: {self.port}\n"
            f"Reload: {'Enabled' if self.reload else 'Disabled'}",
            title="🚀 Dev Server",
            border_style="cyan"
        ))
        
        console.print(f"\n[bold]Server URL:[/bold] http://{self.host}:{self.port}")
        console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")
        
        # Configure uvicorn
        config = uvicorn.Config(
            app_path,
            host=self.host,
            port=self.port,
            reload=self.reload,
            log_level=self.log_level,
            access_log=True
        )
        
        server = uvicorn.Server(config)
        server.run()


def run_dev_server(
    server_type: str = "api",
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = True,
    debug: bool = True
):
    """
    Run development server.
    
    Args:
        server_type: Server type (api, graphql, custom)
        host: Server host
        port: Server port
        reload: Enable auto-reload
        debug: Enable debug mode
    """
    dev_server = DevServer(
        host=host,
        port=port,
        reload=reload,
        debug=debug
    )
    
    if server_type == "api":
        dev_server.run_api_server()
    elif server_type == "graphql":
        dev_server.run_graphql_server()
    else:
        console.print(f"[red]Unknown server type: {server_type}[/red]")
        console.print("Available types: api, graphql")
        sys.exit(1)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="BountyBot Development Server")
    parser.add_argument(
        "--type",
        choices=["api", "graphql"],
        default="api",
        help="Server type"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Server host"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Server port"
    )
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="Disable auto-reload"
    )
    parser.add_argument(
        "--no-debug",
        action="store_true",
        help="Disable debug mode"
    )
    
    args = parser.parse_args()
    
    run_dev_server(
        server_type=args.type,
        host=args.host,
        port=args.port,
        reload=not args.no_reload,
        debug=not args.no_debug
    )

