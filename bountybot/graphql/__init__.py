"""
GraphQL API module for BountyBot.

Provides modern GraphQL API with real-time subscriptions:
- Type-safe GraphQL schema
- Queries for data retrieval
- Mutations for data modification
- Subscriptions for real-time updates
- WebSocket support
- Field-level authorization
- DataLoader optimization
"""

from .schema import schema
from .types import (
    ValidationReportType,
    ValidationResultType,
    UserType,
    OrganizationType,
    MetricsType
)
from .context import GraphQLContext, get_context

__all__ = [
    'schema',
    'ValidationReportType',
    'ValidationResultType',
    'UserType',
    'OrganizationType',
    'MetricsType',
    'GraphQLContext',
    'get_context'
]

__version__ = '1.0.0'

