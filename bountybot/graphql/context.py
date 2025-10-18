"""
GraphQL context for BountyBot.

Provides context for GraphQL resolvers including authentication and database access.
"""

import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class GraphQLContext:
    """
    GraphQL context containing request-scoped data.
    """
    user_id: Optional[str] = None
    organization_id: Optional[str] = None
    api_key: Optional[str] = None
    is_authenticated: bool = False
    
    def __post_init__(self):
        """Post-initialization."""
        if self.user_id or self.api_key:
            self.is_authenticated = True


async def get_context(
    authorization: Optional[str] = None,
    **kwargs
) -> GraphQLContext:
    """
    Get GraphQL context from request.
    
    Args:
        authorization: Authorization header value
        **kwargs: Additional context data
        
    Returns:
        GraphQLContext instance
    """
    context = GraphQLContext()
    
    # Extract API key from authorization header
    if authorization and authorization.startswith("Bearer "):
        api_key = authorization.split(" ")[1]
        
        # Verify API key
        try:
            from bountybot.auth import APIKeyManager
            
            api_key_manager = APIKeyManager()
            key_info = api_key_manager.verify_key(api_key)
            
            if key_info:
                context.api_key = api_key
                context.user_id = key_info.user_id
                context.organization_id = key_info.organization_id
                context.is_authenticated = True
                
                logger.debug(f"Authenticated GraphQL request: user_id={context.user_id}")
        except Exception as e:
            logger.error(f"Failed to verify API key: {e}")
    
    return context


def require_authentication(context: GraphQLContext) -> None:
    """
    Require authentication for resolver.
    
    Args:
        context: GraphQL context
        
    Raises:
        PermissionError: If not authenticated
    """
    if not context.is_authenticated:
        raise PermissionError("Authentication required")


def require_permission(context: GraphQLContext, permission: str) -> None:
    """
    Require specific permission for resolver.
    
    Args:
        context: GraphQL context
        permission: Required permission
        
    Raises:
        PermissionError: If permission not granted
    """
    require_authentication(context)
    
    # Check permission
    try:
        from bountybot.auth import RBACManager
        
        rbac_manager = RBACManager()
        
        # Get user role (simplified - would normally query database)
        user_role = "user"  # Default role
        
        if not rbac_manager.has_permission(user_role, permission):
            raise PermissionError(f"Permission denied: {permission}")
    except Exception as e:
        logger.error(f"Failed to check permission: {e}")
        raise PermissionError(f"Permission check failed: {e}")


__all__ = [
    'GraphQLContext',
    'get_context',
    'require_authentication',
    'require_permission'
]

