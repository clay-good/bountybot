"""
Cache manager with multiple caching strategies.
"""

import logging
import hashlib
from typing import Any, Optional, Callable, List
from enum import Enum
from datetime import datetime, timedelta

from .redis_client import RedisClient, RedisConfig
from .serializers import Serializer, JSONSerializer

logger = logging.getLogger(__name__)


class CacheStrategy(Enum):
    """Cache strategy."""
    CACHE_ASIDE = "cache_aside"  # Read from cache, write to DB, invalidate cache
    WRITE_THROUGH = "write_through"  # Write to cache and DB synchronously
    WRITE_BEHIND = "write_behind"  # Write to cache immediately, DB asynchronously
    REFRESH_AHEAD = "refresh_ahead"  # Proactively refresh before expiration


class CacheManager:
    """
    Distributed cache manager using Redis.
    
    Supports multiple caching strategies:
    - Cache-aside (lazy loading)
    - Write-through (synchronous writes)
    - Write-behind (asynchronous writes)
    - Refresh-ahead (proactive refresh)
    """
    
    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        redis_config: Optional[RedisConfig] = None,
        serializer: Optional[Serializer] = None,
        namespace: str = "bountybot",
        default_ttl: int = 3600,
        strategy: CacheStrategy = CacheStrategy.CACHE_ASIDE
    ):
        """
        Initialize cache manager.
        
        Args:
            redis_client: Redis client instance
            redis_config: Redis configuration (if client not provided)
            serializer: Data serializer (defaults to JSON)
            namespace: Cache key namespace
            default_ttl: Default TTL in seconds
            strategy: Caching strategy
        """
        self.redis_client = redis_client or RedisClient(redis_config)
        self.serializer = serializer or JSONSerializer(compress=True)
        self.namespace = namespace
        self.default_ttl = default_ttl
        self.strategy = strategy
        
        # Statistics
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.errors = 0
        
        # Connect to Redis
        if not self.redis_client.is_connected():
            self.redis_client.connect()
    
    def _make_key(self, key: str, version: Optional[str] = None) -> str:
        """
        Create namespaced cache key.
        
        Args:
            key: Cache key
            version: Optional version for cache invalidation
            
        Returns:
            Namespaced key
        """
        if version:
            return f"{self.namespace}:v{version}:{key}"
        return f"{self.namespace}:{key}"
    
    def _hash_key(self, data: Any) -> str:
        """
        Create hash key from data.
        
        Args:
            data: Data to hash
            
        Returns:
            Hash string
        """
        if isinstance(data, str):
            data_str = data
        else:
            data_str = str(data)
        
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]
    
    def get(self, key: str, version: Optional[str] = None) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key
            version: Optional version

        Returns:
            Cached value or None if not found
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                self.misses += 1
                return None

            cache_key = self._make_key(key, version)
            data = client.get(cache_key)

            if data is None:
                self.misses += 1
                logger.debug(f"Cache MISS: {cache_key}")
                return None

            self.hits += 1
            logger.debug(f"Cache HIT: {cache_key}")
            return self.serializer.deserialize(data)

        except Exception as e:
            self.errors += 1
            logger.error(f"Cache get error: {e}")
            return None
    
    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        version: Optional[str] = None
    ) -> bool:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (None = default)
            version: Optional version
            
        Returns:
            True if successful
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return False
            
            cache_key = self._make_key(key, version)
            data = self.serializer.serialize(value)
            ttl = ttl if ttl is not None else self.default_ttl
            
            if ttl > 0:
                client.setex(cache_key, ttl, data)
            else:
                client.set(cache_key, data)
            
            self.sets += 1
            logger.debug(f"Cache SET: {cache_key} (TTL: {ttl}s)")
            return True
            
        except Exception as e:
            self.errors += 1
            logger.error(f"Cache set error: {e}")
            return False
    
    def delete(self, key: str, version: Optional[str] = None) -> bool:
        """
        Delete value from cache.
        
        Args:
            key: Cache key
            version: Optional version
            
        Returns:
            True if successful
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return False
            
            cache_key = self._make_key(key, version)
            client.delete(cache_key)
            
            self.deletes += 1
            logger.debug(f"Cache DELETE: {cache_key}")
            return True
            
        except Exception as e:
            self.errors += 1
            logger.error(f"Cache delete error: {e}")
            return False
    
    def exists(self, key: str, version: Optional[str] = None) -> bool:
        """
        Check if key exists in cache.
        
        Args:
            key: Cache key
            version: Optional version
            
        Returns:
            True if exists
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return False
            
            cache_key = self._make_key(key, version)
            return client.exists(cache_key) > 0
            
        except Exception as e:
            logger.error(f"Cache exists error: {e}")
            return False
    
    def get_ttl(self, key: str, version: Optional[str] = None) -> Optional[int]:
        """
        Get remaining TTL for key.
        
        Args:
            key: Cache key
            version: Optional version
            
        Returns:
            TTL in seconds or None if key doesn't exist
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return None
            
            cache_key = self._make_key(key, version)
            ttl = client.ttl(cache_key)
            
            if ttl < 0:
                return None
            
            return ttl
            
        except Exception as e:
            logger.error(f"Cache get_ttl error: {e}")
            return None
    
    def extend_ttl(self, key: str, ttl: int, version: Optional[str] = None) -> bool:
        """
        Extend TTL for key.
        
        Args:
            key: Cache key
            ttl: New TTL in seconds
            version: Optional version
            
        Returns:
            True if successful
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return False
            
            cache_key = self._make_key(key, version)
            return client.expire(cache_key, ttl)
            
        except Exception as e:
            logger.error(f"Cache extend_ttl error: {e}")
            return False
    
    def get_or_set(
        self,
        key: str,
        factory: Callable[[], Any],
        ttl: Optional[int] = None,
        version: Optional[str] = None
    ) -> Optional[Any]:
        """
        Get value from cache or compute and set it.

        Args:
            key: Cache key
            factory: Function to compute value if not cached
            ttl: Time to live in seconds
            version: Optional version

        Returns:
            Cached or computed value
        """
        # Try to get from cache
        value = self.get(key, version)
        if value is not None:
            return value

        # Compute value
        try:
            value = factory()
            self.set(key, value, ttl, version)
            return value
        except Exception as e:
            logger.error(f"Factory function error: {e}")
            return None

    def get_many(self, keys: List[str], version: Optional[str] = None) -> dict:
        """
        Get multiple values from cache.

        Args:
            keys: List of cache keys
            version: Optional version

        Returns:
            Dictionary of key-value pairs
        """
        result = {}

        try:
            client = self.redis_client.get_client()
            if not client:
                return result

            cache_keys = [self._make_key(key, version) for key in keys]
            values = client.mget(cache_keys)

            for key, value in zip(keys, values):
                if value is not None:
                    try:
                        result[key] = self.serializer.deserialize(value)
                        self.hits += 1
                    except Exception as e:
                        logger.error(f"Deserialization error for key {key}: {e}")
                else:
                    self.misses += 1

            return result

        except Exception as e:
            self.errors += 1
            logger.error(f"Cache get_many error: {e}")
            return result

    def set_many(
        self,
        mapping: dict,
        ttl: Optional[int] = None,
        version: Optional[str] = None
    ) -> bool:
        """
        Set multiple values in cache.

        Args:
            mapping: Dictionary of key-value pairs
            ttl: Time to live in seconds
            version: Optional version

        Returns:
            True if successful
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return False

            pipe = client.pipeline()
            ttl = ttl if ttl is not None else self.default_ttl

            for key, value in mapping.items():
                cache_key = self._make_key(key, version)
                data = self.serializer.serialize(value)

                if ttl > 0:
                    pipe.setex(cache_key, ttl, data)
                else:
                    pipe.set(cache_key, data)

            pipe.execute()
            self.sets += len(mapping)
            return True

        except Exception as e:
            self.errors += 1
            logger.error(f"Cache set_many error: {e}")
            return False

    def delete_many(self, keys: List[str], version: Optional[str] = None) -> bool:
        """
        Delete multiple values from cache.

        Args:
            keys: List of cache keys
            version: Optional version

        Returns:
            True if successful
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return False

            cache_keys = [self._make_key(key, version) for key in keys]
            client.delete(*cache_keys)

            self.deletes += len(keys)
            return True

        except Exception as e:
            self.errors += 1
            logger.error(f"Cache delete_many error: {e}")
            return False

    def clear_namespace(self, version: Optional[str] = None) -> int:
        """
        Clear all keys in namespace.

        Args:
            version: Optional version

        Returns:
            Number of keys deleted
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return 0

            pattern = self._make_key("*", version)
            keys = client.keys(pattern)

            if keys:
                client.delete(*keys)
                self.deletes += len(keys)
                logger.info(f"Cleared {len(keys)} keys from namespace {self.namespace}")
                return len(keys)

            return 0

        except Exception as e:
            self.errors += 1
            logger.error(f"Cache clear_namespace error: {e}")
            return 0

    def get_stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Statistics dictionary
        """
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

        redis_stats = self.redis_client.get_stats()

        return {
            'hits': self.hits,
            'misses': self.misses,
            'sets': self.sets,
            'deletes': self.deletes,
            'errors': self.errors,
            'total_requests': total_requests,
            'hit_rate_percent': round(hit_rate, 2),
            'namespace': self.namespace,
            'default_ttl': self.default_ttl,
            'strategy': self.strategy.value,
            'redis': redis_stats
        }

    def reset_stats(self):
        """Reset statistics."""
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.errors = 0

