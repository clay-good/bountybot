"""
Async base provider for AI services with rate limiting, caching, and circuit breaker.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, AsyncIterator
import logging
import asyncio
import hashlib
import json
from datetime import datetime, timedelta
from collections import deque
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open or unavailable."""
    pass


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class AsyncCircuitBreaker:
    """
    Async circuit breaker pattern for API resilience.
    Prevents cascading failures by stopping requests to failing services.
    """

    def __init__(self, failure_threshold: int = 5, timeout: int = 60, half_open_max_calls: int = 3):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            timeout: Seconds to wait before attempting recovery
            half_open_max_calls: Max calls to allow in half-open state
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.half_open_max_calls = half_open_max_calls

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.half_open_calls = 0
        self.lock = asyncio.Lock()

    async def call(self, func, *args, **kwargs):
        """
        Execute async function with circuit breaker protection.

        Args:
            func: Async function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerError: If circuit is open or unavailable
        """
        async with self.lock:
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    logger.info("Circuit breaker: Attempting reset (HALF_OPEN)")
                    self.state = CircuitState.HALF_OPEN
                    self.half_open_calls = 0
                else:
                    raise CircuitBreakerError(f"Circuit breaker is OPEN. Service unavailable. Retry after {self.timeout}s")

            if self.state == CircuitState.HALF_OPEN:
                if self.half_open_calls >= self.half_open_max_calls:
                    raise CircuitBreakerError("Circuit breaker is HALF_OPEN. Max test calls reached")
                self.half_open_calls += 1

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure()
            raise e

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        return (datetime.now() - self.last_failure_time).total_seconds() >= self.timeout

    async def _on_success(self):
        """Handle successful call."""
        async with self.lock:
            if self.state == CircuitState.HALF_OPEN:
                logger.info("Circuit breaker: Service recovered (CLOSED)")
                self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.half_open_calls = 0

    async def _on_failure(self):
        """Handle failed call."""
        async with self.lock:
            self.failure_count += 1
            self.last_failure_time = datetime.now()

            if self.state == CircuitState.HALF_OPEN:
                logger.warning("Circuit breaker: Recovery failed, reopening circuit (OPEN)")
                self.state = CircuitState.OPEN
            elif self.failure_count >= self.failure_threshold:
                logger.error(f"Circuit breaker: Failure threshold reached ({self.failure_count}), opening circuit (OPEN)")
                self.state = CircuitState.OPEN


class AsyncBaseAIProvider(ABC):
    """
    Abstract base class for async AI providers with rate limiting, caching, and circuit breaker.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize base provider.

        Args:
            config: Provider configuration
        """
        self.config = config
        self.model = config.get('model', 'default')
        self.max_tokens = config.get('max_tokens', 4096)
        self.temperature = config.get('temperature', 0.3)

        # Rate limiting (token bucket algorithm)
        rate_limit = config.get('rate_limit', {})
        self.requests_per_minute = rate_limit.get('requests_per_minute', 50)
        self.tokens_per_minute = rate_limit.get('tokens_per_minute', 100000)

        # Token bucket for requests
        self.request_tokens = self.requests_per_minute
        self.request_bucket_size = self.requests_per_minute
        self.last_request_refill = datetime.now()

        # Token bucket for tokens
        self.token_tokens = self.tokens_per_minute
        self.token_bucket_size = self.tokens_per_minute
        self.last_token_refill = datetime.now()

        # Request tracking
        self.request_times = deque(maxlen=100)
        self.token_usage = deque(maxlen=100)

        # Response caching
        self.cache_enabled = config.get('cache_enabled', True)
        self.cache_ttl = config.get('cache_ttl', 3600)  # 1 hour default
        self.cache: Dict[str, tuple] = {}  # key -> (response, timestamp)
        self.max_cache_size = config.get('max_cache_size', 1000)

        # Statistics
        self.total_requests = 0
        self.total_tokens_in = 0
        self.total_tokens_out = 0
        self.total_cost = 0.0
        self.total_cache_hits = 0
        self.total_cache_misses = 0

        # Circuit breaker
        self.circuit_breaker = AsyncCircuitBreaker(
            failure_threshold=config.get('circuit_breaker_threshold', 5),
            timeout=config.get('circuit_breaker_timeout', 60),
            half_open_max_calls=config.get('circuit_breaker_half_open_calls', 3)
        )

        # Async lock for thread-safe operations
        self.lock = asyncio.Lock()

        logger.info(f"Async {self.__class__.__name__} initialized with model={self.model}")

    async def _refill_buckets(self):
        """Refill rate limit buckets based on time elapsed."""
        now = datetime.now()

        # Refill request bucket
        request_elapsed = (now - self.last_request_refill).total_seconds()
        request_refill = (request_elapsed / 60.0) * self.requests_per_minute
        self.request_tokens = min(self.request_bucket_size, self.request_tokens + request_refill)
        self.last_request_refill = now

        # Refill token bucket
        token_elapsed = (now - self.last_token_refill).total_seconds()
        token_refill = (token_elapsed / 60.0) * self.tokens_per_minute
        self.token_tokens = min(self.token_bucket_size, self.token_tokens + token_refill)
        self.last_token_refill = now

    async def _wait_for_rate_limit(self, estimated_tokens: int = 1000):
        """
        Wait if rate limits would be exceeded.

        Args:
            estimated_tokens: Estimated tokens for this request
        """
        async with self.lock:
            await self._refill_buckets()

            # Check request rate limit
            if self.request_tokens < 1:
                wait_time = 60.0 / self.requests_per_minute
                logger.warning(f"Request rate limit reached, waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                await self._refill_buckets()

            # Check token rate limit
            if self.token_tokens < estimated_tokens:
                wait_time = (estimated_tokens - self.token_tokens) / (self.tokens_per_minute / 60.0)
                logger.warning(f"Token rate limit reached, waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                await self._refill_buckets()

            # Consume tokens
            self.request_tokens -= 1
            self.token_tokens -= estimated_tokens

    def _get_cache_key(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        """
        Generate cache key from prompts and parameters.

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            **kwargs: Additional parameters

        Returns:
            Cache key (SHA-256 hash)
        """
        cache_data = {
            'system': system_prompt,
            'user': user_prompt,
            'model': self.model,
            'temperature': self.temperature,
            **kwargs
        }
        cache_str = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_str.encode()).hexdigest()

    async def _check_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Check if response is in cache and not expired.

        Args:
            cache_key: Cache key

        Returns:
            Cached response or None
        """
        if not self.cache_enabled:
            return None

        async with self.lock:
            if cache_key in self.cache:
                response, timestamp = self.cache[cache_key]
                age = (datetime.now() - timestamp).total_seconds()

                if age < self.cache_ttl:
                    self.total_cache_hits += 1
                    logger.debug(f"Cache hit (age={age:.1f}s)")
                    return response
                else:
                    # Expired, remove from cache
                    del self.cache[cache_key]
                    logger.debug(f"Cache expired (age={age:.1f}s)")

            self.total_cache_misses += 1
            return None

    async def _store_cache(self, cache_key: str, response: Dict[str, Any]):
        """
        Store response in cache.

        Args:
            cache_key: Cache key
            response: Response to cache
        """
        if not self.cache_enabled:
            return

        async with self.lock:
            # Evict oldest entry if cache is full
            if len(self.cache) >= self.max_cache_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                logger.debug("Cache full, evicted oldest entry")

            self.cache[cache_key] = (response, datetime.now())

    @abstractmethod
    async def complete(self, system_prompt: str, user_prompt: str,
                      max_tokens: Optional[int] = None,
                      temperature: Optional[float] = None,
                      json_mode: bool = False) -> Dict[str, Any]:
        """
        Make a completion request (async).

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            json_mode: Whether to request JSON output

        Returns:
            Response dictionary with 'content', 'tokens_in', 'tokens_out', 'cost'
        """
        pass

    @abstractmethod
    async def stream_complete(self, system_prompt: str, user_prompt: str,
                             max_tokens: Optional[int] = None,
                             temperature: Optional[float] = None) -> AsyncIterator[str]:
        """
        Make a streaming completion request (async).

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature

        Yields:
            Content chunks as they arrive
        """
        pass

    async def complete_with_json(self, system_prompt: str, user_prompt: str,
                                max_tokens: Optional[int] = None) -> Dict[str, Any]:
        """
        Make a completion request and parse JSON response (async).

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Parsed JSON response
        """
        result = await self.complete(system_prompt, user_prompt,
                                     max_tokens=max_tokens,
                                     json_mode=True)

        try:
            # Try to parse JSON from content
            content = result['content'].strip()

            # Remove markdown code blocks if present
            if content.startswith('```'):
                lines = content.split('\n')
                content = '\n'.join(lines[1:-1]) if len(lines) > 2 else content

            parsed = json.loads(content)
            result['parsed'] = parsed
            return result

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Response content: {result['content']}")
            result['parsed'] = None
            return result

    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """
        Count tokens in text.

        Args:
            text: Text to count tokens for

        Returns:
            Token count
        """
        pass

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get provider statistics (async).

        Returns:
            Dictionary with usage statistics
        """
        async with self.lock:
            cache_hit_rate = 0.0
            total_cache_requests = self.total_cache_hits + self.total_cache_misses
            if total_cache_requests > 0:
                cache_hit_rate = (self.total_cache_hits / total_cache_requests) * 100

            avg_cost_per_request = 0.0
            if self.total_requests > 0:
                avg_cost_per_request = self.total_cost / self.total_requests

            return {
                'provider': self.__class__.__name__,
                'model': self.model,
                'requests': {
                    'total': self.total_requests,
                    'recent_minute': len(self.request_times),
                },
                'tokens': {
                    'total_input': self.total_tokens_in,
                    'total_output': self.total_tokens_out,
                    'total': self.total_tokens_in + self.total_tokens_out,
                    'recent_minute': sum(tokens for _, tokens in self.token_usage),
                },
                'cost': {
                    'total': round(self.total_cost, 4),
                    'average_per_request': round(avg_cost_per_request, 4),
                },
                'cache': {
                    'enabled': self.cache_enabled,
                    'size': len(self.cache),
                    'max_size': self.max_cache_size,
                    'hits': self.total_cache_hits,
                    'misses': self.total_cache_misses,
                    'hit_rate_percent': round(cache_hit_rate, 2),
                },
                'circuit_breaker': {
                    'state': self.circuit_breaker.state.value,
                    'failure_count': self.circuit_breaker.failure_count,
                },
                'rate_limits': {
                    'requests_per_minute': self.requests_per_minute,
                    'tokens_per_minute': self.tokens_per_minute,
                },
            }

    async def clear_cache(self):
        """Clear the response cache and reset cache statistics (async)."""
        async with self.lock:
            cache_size = len(self.cache)
            self.cache.clear()
            logger.info(f"Cache cleared ({cache_size} entries removed)")

    async def reset_stats(self):
        """Reset all usage statistics (async)."""
        async with self.lock:
            self.total_cost = 0.0
            self.total_requests = 0
            self.total_tokens_in = 0
            self.total_tokens_out = 0
            self.total_cache_hits = 0
            self.total_cache_misses = 0
            logger.info("Statistics reset")

