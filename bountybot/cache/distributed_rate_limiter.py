"""
Distributed rate limiter using Redis.
"""

import time
import logging
from typing import Optional
from datetime import datetime, timedelta

from .redis_client import RedisClient, RedisConfig

logger = logging.getLogger(__name__)


class DistributedRateLimiter:
    """
    Distributed rate limiter using Redis.
    
    Supports multiple algorithms:
    - Token bucket (smooth rate limiting)
    - Fixed window (simple, but can have burst at window boundaries)
    - Sliding window (accurate, prevents bursts)
    """
    
    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        redis_config: Optional[RedisConfig] = None,
        namespace: str = "ratelimit"
    ):
        """
        Initialize distributed rate limiter.
        
        Args:
            redis_client: Redis client instance
            redis_config: Redis configuration (if client not provided)
            namespace: Rate limit key namespace
        """
        self.redis_client = redis_client or RedisClient(redis_config)
        self.namespace = namespace
        
        # Connect to Redis
        if not self.redis_client.is_connected():
            self.redis_client.connect()
    
    def _make_key(self, identifier: str, resource: str = "default") -> str:
        """
        Create rate limit key.
        
        Args:
            identifier: User/IP/API key identifier
            resource: Resource being rate limited
            
        Returns:
            Rate limit key
        """
        return f"{self.namespace}:{resource}:{identifier}"
    
    def check_rate_limit_token_bucket(
        self,
        identifier: str,
        max_tokens: int,
        refill_rate: float,
        tokens_requested: int = 1,
        resource: str = "default"
    ) -> tuple[bool, dict]:
        """
        Check rate limit using token bucket algorithm.
        
        Args:
            identifier: User/IP/API key identifier
            max_tokens: Maximum tokens in bucket
            refill_rate: Tokens added per second
            tokens_requested: Tokens to consume
            resource: Resource being rate limited
            
        Returns:
            Tuple of (allowed, info_dict)
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                # Fail open if Redis unavailable
                return True, {'error': 'Redis unavailable'}
            
            key = self._make_key(identifier, resource)
            now = time.time()
            
            # Lua script for atomic token bucket operation
            lua_script = """
            local key = KEYS[1]
            local max_tokens = tonumber(ARGV[1])
            local refill_rate = tonumber(ARGV[2])
            local tokens_requested = tonumber(ARGV[3])
            local now = tonumber(ARGV[4])
            
            local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
            local tokens = tonumber(bucket[1]) or max_tokens
            local last_refill = tonumber(bucket[2]) or now
            
            -- Refill tokens
            local time_passed = now - last_refill
            local tokens_to_add = time_passed * refill_rate
            tokens = math.min(max_tokens, tokens + tokens_to_add)
            
            -- Try to consume tokens
            local allowed = 0
            if tokens >= tokens_requested then
                tokens = tokens - tokens_requested
                allowed = 1
            end
            
            -- Update bucket
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
            redis.call('EXPIRE', key, 3600)  -- 1 hour expiry
            
            return {allowed, tokens}
            """
            
            result = client.eval(
                lua_script,
                1,
                key,
                max_tokens,
                refill_rate,
                tokens_requested,
                now
            )
            
            allowed = bool(result[0])
            remaining_tokens = float(result[1])
            
            info = {
                'allowed': allowed,
                'remaining_tokens': remaining_tokens,
                'max_tokens': max_tokens,
                'refill_rate': refill_rate,
                'identifier': identifier,
                'resource': resource
            }
            
            if not allowed:
                wait_time = (tokens_requested - remaining_tokens) / refill_rate
                info['retry_after_seconds'] = wait_time
                logger.warning(f"Rate limit exceeded for {identifier} on {resource}")
            
            return allowed, info
            
        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            # Fail open on error
            return True, {'error': str(e)}
    
    def check_rate_limit_fixed_window(
        self,
        identifier: str,
        max_requests: int,
        window_seconds: int,
        resource: str = "default"
    ) -> tuple[bool, dict]:
        """
        Check rate limit using fixed window algorithm.
        
        Args:
            identifier: User/IP/API key identifier
            max_requests: Maximum requests per window
            window_seconds: Window size in seconds
            resource: Resource being rate limited
            
        Returns:
            Tuple of (allowed, info_dict)
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return True, {'error': 'Redis unavailable'}
            
            key = self._make_key(identifier, resource)
            now = int(time.time())
            window_start = now - (now % window_seconds)
            window_key = f"{key}:{window_start}"
            
            # Increment counter
            pipe = client.pipeline()
            pipe.incr(window_key)
            pipe.expire(window_key, window_seconds * 2)  # Keep for 2 windows
            results = pipe.execute()
            
            current_count = results[0]
            allowed = current_count <= max_requests
            
            info = {
                'allowed': allowed,
                'current_count': current_count,
                'max_requests': max_requests,
                'window_seconds': window_seconds,
                'window_start': window_start,
                'identifier': identifier,
                'resource': resource
            }
            
            if not allowed:
                window_end = window_start + window_seconds
                info['retry_after_seconds'] = window_end - now
                logger.warning(f"Rate limit exceeded for {identifier} on {resource}")
            
            return allowed, info
            
        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            return True, {'error': str(e)}
    
    def check_rate_limit_sliding_window(
        self,
        identifier: str,
        max_requests: int,
        window_seconds: int,
        resource: str = "default"
    ) -> tuple[bool, dict]:
        """
        Check rate limit using sliding window algorithm.
        
        Args:
            identifier: User/IP/API key identifier
            max_requests: Maximum requests per window
            window_seconds: Window size in seconds
            resource: Resource being rate limited
            
        Returns:
            Tuple of (allowed, info_dict)
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return True, {'error': 'Redis unavailable'}
            
            key = self._make_key(identifier, resource)
            now = time.time()
            window_start = now - window_seconds
            
            # Lua script for atomic sliding window operation
            lua_script = """
            local key = KEYS[1]
            local window_start = tonumber(ARGV[1])
            local now = tonumber(ARGV[2])
            local max_requests = tonumber(ARGV[3])
            
            -- Remove old entries
            redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
            
            -- Count current requests
            local current_count = redis.call('ZCARD', key)
            
            -- Check if allowed
            local allowed = 0
            if current_count < max_requests then
                redis.call('ZADD', key, now, now)
                redis.call('EXPIRE', key, math.ceil(ARGV[4]))
                allowed = 1
                current_count = current_count + 1
            end
            
            return {allowed, current_count}
            """
            
            result = client.eval(
                lua_script,
                1,
                key,
                window_start,
                now,
                max_requests,
                window_seconds * 2
            )
            
            allowed = bool(result[0])
            current_count = int(result[1])
            
            info = {
                'allowed': allowed,
                'current_count': current_count,
                'max_requests': max_requests,
                'window_seconds': window_seconds,
                'identifier': identifier,
                'resource': resource
            }
            
            if not allowed:
                info['retry_after_seconds'] = 1  # Try again in 1 second
                logger.warning(f"Rate limit exceeded for {identifier} on {resource}")
            
            return allowed, info
            
        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            return True, {'error': str(e)}
    
    def reset_rate_limit(self, identifier: str, resource: str = "default") -> bool:
        """
        Reset rate limit for identifier.
        
        Args:
            identifier: User/IP/API key identifier
            resource: Resource being rate limited
            
        Returns:
            True if successful
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return False
            
            key = self._make_key(identifier, resource)
            pattern = f"{key}*"
            keys = client.keys(pattern)
            
            if keys:
                client.delete(*keys)
                logger.info(f"Reset rate limit for {identifier} on {resource}")
            
            return True
            
        except Exception as e:
            logger.error(f"Reset rate limit error: {e}")
            return False
    
    def get_rate_limit_info(self, identifier: str, resource: str = "default") -> dict:
        """
        Get rate limit information.
        
        Args:
            identifier: User/IP/API key identifier
            resource: Resource being rate limited
            
        Returns:
            Rate limit info dictionary
        """
        try:
            client = self.redis_client.get_client()
            if not client:
                return {}
            
            key = self._make_key(identifier, resource)
            
            # Try to get token bucket info
            bucket = client.hgetall(key)
            if bucket:
                return {
                    'tokens': float(bucket.get(b'tokens', 0)),
                    'last_refill': float(bucket.get(b'last_refill', 0)),
                    'identifier': identifier,
                    'resource': resource
                }
            
            return {}
            
        except Exception as e:
            logger.error(f"Get rate limit info error: {e}")
            return {}

