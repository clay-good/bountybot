"""
Cache module for BountyBot.

Provides distributed caching capabilities using Redis with support for:
- Distributed cache layer
- Distributed rate limiting
- Session storage
- Cache warming and invalidation
- High availability (Sentinel)
- Horizontal scaling (Cluster)
"""

from .redis_client import RedisClient, RedisConfig, RedisMode
from .cache_manager import CacheManager, CacheStrategy
from .distributed_rate_limiter import DistributedRateLimiter
from .cache_warmer import CacheWarmer
from .serializers import (
    Serializer,
    JSONSerializer,
    MessagePackSerializer,
    PickleSerializer
)

__all__ = [
    'RedisClient',
    'RedisConfig',
    'RedisMode',
    'CacheManager',
    'CacheStrategy',
    'DistributedRateLimiter',
    'CacheWarmer',
    'Serializer',
    'JSONSerializer',
    'MessagePackSerializer',
    'PickleSerializer'
]

