from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
import logging
import time
import hashlib
import json
from datetime import datetime, timedelta
from collections import deque
from enum import Enum
import threading

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern for API resilience.
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
        self.lock = threading.Lock()

    def call(self, func, *args, **kwargs):
        """
        Execute function with circuit breaker protection.

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            Exception: If circuit is open or function fails
        """
        with self.lock:
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    logger.info("Circuit breaker: Attempting reset (HALF_OPEN)")
                    self.state = CircuitState.HALF_OPEN
                    self.half_open_calls = 0
                else:
                    raise Exception(f"Circuit breaker is OPEN. Service unavailable. Retry after {self.timeout}s")

            if self.state == CircuitState.HALF_OPEN:
                if self.half_open_calls >= self.half_open_max_calls:
                    raise Exception("Circuit breaker is HALF_OPEN. Max test calls reached")
                self.half_open_calls += 1

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        return (datetime.now() - self.last_failure_time).total_seconds() >= self.timeout

    def _on_success(self):
        """Handle successful call."""
        with self.lock:
            if self.state == CircuitState.HALF_OPEN:
                logger.info("Circuit breaker: Service recovered (CLOSED)")
                self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.half_open_calls = 0

    def _on_failure(self):
        """Handle failed call."""
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = datetime.now()

            if self.state == CircuitState.HALF_OPEN:
                logger.warning("Circuit breaker: Recovery failed (OPEN)")
                self.state = CircuitState.OPEN
                self.half_open_calls = 0
            elif self.failure_count >= self.failure_threshold:
                logger.error(f"Circuit breaker: Failure threshold reached (OPEN)")
                self.state = CircuitState.OPEN


class CacheEntry:
    """Cache entry with TTL support."""

    def __init__(self, value: Any, ttl: int = 3600):
        """
        Initialize cache entry.

        Args:
            value: Cached value
            ttl: Time to live in seconds
        """
        self.value = value
        self.created_at = datetime.now()
        self.ttl = ttl

    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return (datetime.now() - self.created_at).total_seconds() > self.ttl


class BaseAIProvider(ABC):
    """
    Abstract base class for AI providers.
    Handles rate limiting, cost tracking, caching, circuit breaking, and error handling.

    Features:
    - Token bucket rate limiting with burst capacity
    - TTL-based caching with automatic expiration
    - Circuit breaker pattern for resilience
    - Retry logic with exponential backoff
    - Comprehensive metrics and logging
    - Thread-safe operations
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize AI provider with configuration.

        Args:
            config: Provider configuration including API key, model, rate limits
        """
        self.config = config
        self.api_key = config.get('api_key')
        self.model = config.get('model')
        self.max_tokens = config.get('max_tokens', 4096)
        self.temperature = config.get('temperature', 0.3)

        # Rate limiting with token bucket algorithm
        rate_limit = config.get('rate_limit', {})
        self.requests_per_minute = rate_limit.get('requests_per_minute', 50)
        self.tokens_per_minute = rate_limit.get('tokens_per_minute', 100000)
        self.burst_capacity = rate_limit.get('burst_capacity', 10)  # Allow bursts

        # Tracking with thread-safe deque
        self.request_times: deque = deque(maxlen=self.requests_per_minute * 2)
        self.token_usage: deque = deque(maxlen=1000)  # (timestamp, tokens)
        self.total_cost = 0.0
        self.total_requests = 0
        self.total_tokens_in = 0
        self.total_tokens_out = 0
        self.total_cache_hits = 0
        self.total_cache_misses = 0

        # Cache with TTL support
        self.cache: Dict[str, CacheEntry] = {}
        self.cache_enabled = config.get('cache_enabled', True)
        self.cache_ttl = config.get('cache_ttl', 3600)  # 1 hour default
        self.max_cache_size = config.get('max_cache_size', 1000)

        # Circuit breaker for resilience
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=config.get('circuit_breaker_threshold', 5),
            timeout=config.get('circuit_breaker_timeout', 60),
            half_open_max_calls=config.get('circuit_breaker_half_open_calls', 3)
        )

        # Retry configuration
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 1.0)  # Initial delay in seconds
        self.retry_backoff = config.get('retry_backoff', 2.0)  # Exponential backoff multiplier

        # Thread safety
        self.lock = threading.Lock()

        logger.info(f"Initialized {self.__class__.__name__} with model {self.model}")
        logger.debug(f"Rate limits: {self.requests_per_minute} req/min, {self.tokens_per_minute} tokens/min")
        logger.debug(f"Cache: enabled={self.cache_enabled}, ttl={self.cache_ttl}s, max_size={self.max_cache_size}")
    
    @abstractmethod
    def complete(self, 
                 system_prompt: str, 
                 user_prompt: str,
                 max_tokens: Optional[int] = None,
                 temperature: Optional[float] = None,
                 json_mode: bool = False) -> Dict[str, Any]:
        """
        Make a completion request to the AI provider.
        
        Args:
            system_prompt: System/instruction prompt
            user_prompt: User message/query
            max_tokens: Maximum tokens to generate (overrides default)
            temperature: Sampling temperature (overrides default)
            json_mode: Whether to request JSON output
            
        Returns:
            Dictionary with 'content', 'input_tokens', 'output_tokens', 'cost'
        """
        pass
    
    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """
        Count tokens in text using provider's tokenizer.
        
        Args:
            text: Text to count tokens for
            
        Returns:
            Number of tokens
        """
        pass
    
    @abstractmethod
    def calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Calculate cost for token usage.
        
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            
        Returns:
            Cost in USD
        """
        pass
    
    def _check_rate_limits(self, estimated_tokens: int = 0):
        """
        Check and enforce rate limits using token bucket algorithm.
        Allows bursts while maintaining average rate.

        Args:
            estimated_tokens: Estimated tokens for the request
        """
        with self.lock:
            now = datetime.now()
            one_minute_ago = now - timedelta(minutes=1)

            # Clean old entries (efficient with deque)
            while self.request_times and self.request_times[0] < one_minute_ago:
                self.request_times.popleft()

            while self.token_usage and self.token_usage[0][0] < one_minute_ago:
                self.token_usage.popleft()

            # Check request rate limit with burst capacity
            if len(self.request_times) >= self.requests_per_minute + self.burst_capacity:
                sleep_time = (self.request_times[0] - one_minute_ago).total_seconds() + 0.1
                if sleep_time > 0:
                    logger.info(f"Request rate limit reached, sleeping for {sleep_time:.2f}s")
                    time.sleep(sleep_time)
                    return self._check_rate_limits(estimated_tokens)

            # Check token rate limit
            current_tokens = sum(tokens for _, tokens in self.token_usage)
            if current_tokens + estimated_tokens > self.tokens_per_minute:
                if self.token_usage:
                    sleep_time = (self.token_usage[0][0] - one_minute_ago).total_seconds() + 0.1
                    if sleep_time > 0:
                        logger.info(f"Token rate limit reached ({current_tokens}/{self.tokens_per_minute}), sleeping for {sleep_time:.2f}s")
                        time.sleep(sleep_time)
                        return self._check_rate_limits(estimated_tokens)

            # Record this request
            self.request_times.append(now)
            if estimated_tokens > 0:
                self.token_usage.append((now, estimated_tokens))

            logger.debug(f"Rate check passed: {len(self.request_times)}/{self.requests_per_minute} requests, {current_tokens}/{self.tokens_per_minute} tokens")
    
    def _record_usage(self, input_tokens: int, output_tokens: int, cost: float):
        """
        Record token usage and cost with comprehensive metrics.

        Args:
            input_tokens: Number of input tokens used
            output_tokens: Number of output tokens used
            cost: Cost of the request
        """
        with self.lock:
            self.total_cost += cost
            self.total_requests += 1
            self.total_tokens_in += input_tokens
            self.total_tokens_out += output_tokens

            # Update token usage for rate limiting
            now = datetime.now()
            self.token_usage.append((now, input_tokens + output_tokens))

            logger.info(f"API call completed: ${cost:.4f} | {input_tokens} in + {output_tokens} out = {input_tokens + output_tokens} tokens")
            logger.debug(f"Cumulative: {self.total_requests} requests, ${self.total_cost:.2f} total cost")
    
    def _get_cache_key(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        """
        Generate deterministic cache key for a request.

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            **kwargs: Additional parameters (sorted for consistency)

        Returns:
            SHA-256 hash as cache key
        """
        # Sort kwargs for consistent hashing
        sorted_kwargs = json.dumps(kwargs, sort_keys=True)
        content = f"{system_prompt}|{user_prompt}|{sorted_kwargs}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _check_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Check if response is cached and not expired.

        Args:
            cache_key: Cache key to check

        Returns:
            Cached response or None if not found/expired
        """
        if not self.cache_enabled:
            self.total_cache_misses += 1
            return None

        with self.lock:
            if cache_key in self.cache:
                entry = self.cache[cache_key]
                if not entry.is_expired():
                    self.total_cache_hits += 1
                    logger.info(f"Cache HIT (age: {(datetime.now() - entry.created_at).total_seconds():.1f}s)")
                    return entry.value
                else:
                    # Remove expired entry
                    del self.cache[cache_key]
                    logger.debug("Cache entry expired, removed")

            self.total_cache_misses += 1
            logger.debug("Cache MISS")
            return None

    def _store_cache(self, cache_key: str, response: Dict[str, Any]):
        """
        Store response in cache with TTL and size management.

        Args:
            cache_key: Cache key
            response: Response to cache
        """
        if not self.cache_enabled:
            return

        with self.lock:
            # Evict oldest entries if cache is full
            if len(self.cache) >= self.max_cache_size:
                # Remove 10% of oldest entries
                num_to_remove = max(1, self.max_cache_size // 10)
                sorted_entries = sorted(
                    self.cache.items(),
                    key=lambda x: x[1].created_at
                )
                for key, _ in sorted_entries[:num_to_remove]:
                    del self.cache[key]
                logger.debug(f"Cache full, evicted {num_to_remove} oldest entries")

            self.cache[cache_key] = CacheEntry(response, ttl=self.cache_ttl)
            logger.debug(f"Cached response (cache size: {len(self.cache)}/{self.max_cache_size})")
    
    def _retry_with_backoff(self, func, *args, **kwargs) -> Any:
        """
        Execute function with exponential backoff retry logic.

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            Exception: If all retries fail
        """
        last_exception = None
        delay = self.retry_delay

        for attempt in range(self.max_retries + 1):
            try:
                if attempt > 0:
                    logger.info(f"Retry attempt {attempt}/{self.max_retries} after {delay:.1f}s delay")
                    time.sleep(delay)

                return func(*args, **kwargs)

            except Exception as e:
                last_exception = e
                error_msg = str(e)

                # Don't retry on certain errors
                if any(x in error_msg.lower() for x in ['invalid api key', 'authentication', 'unauthorized']):
                    logger.error(f"Non-retryable error: {error_msg}")
                    raise e

                if attempt < self.max_retries:
                    logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}): {error_msg}")
                    delay *= self.retry_backoff  # Exponential backoff
                else:
                    logger.error(f"All retry attempts failed: {error_msg}")

        raise last_exception

    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive provider usage statistics.

        Returns:
            Dictionary with detailed usage stats
        """
        with self.lock:
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

    def clear_cache(self):
        """Clear the response cache and reset cache statistics."""
        with self.lock:
            cache_size = len(self.cache)
            self.cache.clear()
            logger.info(f"Cache cleared ({cache_size} entries removed)")

    def reset_stats(self):
        """Reset all usage statistics."""
        with self.lock:
            self.total_cost = 0.0
            self.total_requests = 0
            self.total_tokens_in = 0
            self.total_tokens_out = 0
            self.total_cache_hits = 0
            self.total_cache_misses = 0
            logger.info("Statistics reset")

