"""
GraphQL FastAPI integration for BountyBot.

Integrates Strawberry GraphQL with FastAPI.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import required packages
try:
    from fastapi import FastAPI, Request, WebSocket, Depends
    from fastapi.responses import HTMLResponse
    import strawberry
    from strawberry.fastapi import GraphQLRouter
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    logger.warning("Required packages not available. Install with: pip install 'strawberry-graphql[fastapi]'")
    DEPENDENCIES_AVAILABLE = False
    FastAPI = None
    Request = None
    WebSocket = None
    Depends = None
    HTMLResponse = None
    strawberry = None
    GraphQLRouter = None


if DEPENDENCIES_AVAILABLE:
    from .schema import schema
    from .context import get_context, GraphQLContext
    
    
    async def get_graphql_context(
        request: Optional[Request] = None,
        websocket: Optional[WebSocket] = None
    ) -> GraphQLContext:
        """
        Get GraphQL context from request or websocket.
        
        Args:
            request: HTTP request
            websocket: WebSocket connection
            
        Returns:
            GraphQL context
        """
        authorization = None
        
        if request:
            authorization = request.headers.get("Authorization")
        elif websocket:
            # Get authorization from query params or headers
            authorization = websocket.query_params.get("authorization")
            if not authorization:
                authorization = websocket.headers.get("Authorization")
        
        return await get_context(authorization=authorization)
    
    
    def create_graphql_app() -> Optional[FastAPI]:
        """
        Create FastAPI app with GraphQL endpoint.
        
        Returns:
            FastAPI app or None if dependencies not available
        """
        if not schema:
            logger.warning("GraphQL schema not available")
            return None
        
        # Create GraphQL router
        graphql_router = GraphQLRouter(
            schema,
            context_getter=get_graphql_context,
            graphiql=True  # Enable GraphiQL IDE
        )
        
        # Create FastAPI app
        app = FastAPI(
            title="BountyBot GraphQL API",
            description="Modern GraphQL API with real-time subscriptions",
            version="1.0.0"
        )
        
        # Add GraphQL routes
        app.include_router(graphql_router, prefix="/graphql")
        
        @app.get("/")
        async def root():
            """Root endpoint."""
            return {
                "service": "BountyBot GraphQL API",
                "version": "1.0.0",
                "graphql_endpoint": "/graphql",
                "graphiql": "/graphql (in browser)",
                "websocket": "ws://localhost:8000/graphql"
            }
        
        @app.get("/health")
        async def health():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "graphql": "available",
                "websocket": "available"
            }
        
        logger.info("GraphQL FastAPI app created successfully")
        return app
    
    
    # Create app instance
    graphql_app = create_graphql_app()

else:
    graphql_app = None
    
    def create_graphql_app():
        """Stub function when dependencies not available."""
        logger.warning("Cannot create GraphQL app - dependencies not available")
        return None


__all__ = [
    'graphql_app',
    'create_graphql_app'
]

