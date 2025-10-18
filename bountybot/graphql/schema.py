"""
GraphQL schema for BountyBot.

Combines queries, mutations, and subscriptions into a single schema.
"""

import logging

logger = logging.getLogger(__name__)

# Try to import Strawberry
try:
    import strawberry
    STRAWBERRY_AVAILABLE = True
except ImportError:
    logger.warning("strawberry-graphql not available")
    STRAWBERRY_AVAILABLE = False
    strawberry = None


if STRAWBERRY_AVAILABLE:
    from .queries import Query
    from .mutations import Mutation
    from .subscriptions import Subscription
    
    # Create GraphQL schema
    schema = strawberry.Schema(
        query=Query,
        mutation=Mutation,
        subscription=Subscription
    )
    
    logger.info("GraphQL schema created successfully")

else:
    # Stub schema when Strawberry not available
    schema = None
    logger.warning("GraphQL schema not available - install strawberry-graphql")


__all__ = ['schema']

