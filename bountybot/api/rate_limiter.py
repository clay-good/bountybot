import time
from typing import Dict, Optional
from threading import Lock
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class TokenBucket:
    """Token bucket for rate limiting."""
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.
        
        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = Lock()
    
    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        
        # Add tokens based on elapsed time
        tokens_to_add = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens consumed, False if insufficient tokens
        """
        with self.lock:
            self._refill()
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def get_wait_time(self, tokens: int = 1) -> float:
        """
        Get time to wait until tokens available.
        
        Args:
            tokens: Number of tokens needed
            
        Returns:
            Wait time in seconds
        """
        with self.lock:
            self._refill()
            
            if self.tokens >= tokens:
                return 0.0
            
            tokens_needed = tokens - self.tokens
            return tokens_needed / self.refill_rate


class RateLimiter:
    """Rate limiter using token bucket algorithm."""
    
    def __init__(self):
        self.buckets: Dict[str, TokenBucket] = {}
        self.lock = Lock()
        self.request_counts: Dict[str, int] = defaultdict(int)
        self.blocked_counts: Dict[str, int] = defaultdict(int)
    
    def _get_bucket(self, key: str, rate_limit: int) -> TokenBucket:
        """
        Get or create token bucket for key.
        
        Args:
            key: Rate limit key (e.g., "api_key:abc123")
            rate_limit: Requests per minute
            
        Returns:
            TokenBucket instance
        """
        with self.lock:
            if key not in self.buckets:
                # Convert requests per minute to tokens per second
                refill_rate = rate_limit / 60.0
                # Allow burst of 2x rate limit
                capacity = rate_limit * 2
                
                self.buckets[key] = TokenBucket(capacity, refill_rate)
            
            return self.buckets[key]
    
    def allow_request(self, key: str, rate_limit: int, tokens: int = 1) -> bool:
        """
        Check if request is allowed.
        
        Args:
            key: Rate limit key
            rate_limit: Requests per minute
            tokens: Number of tokens to consume
            
        Returns:
            True if request allowed, False otherwise
        """
        bucket = self._get_bucket(key, rate_limit)
        
        self.request_counts[key] += 1
        
        if bucket.consume(tokens):
            return True
        
        self.blocked_counts[key] += 1
        logger.warning(f"Rate limit exceeded for key: {key}")
        return False
    
    def get_wait_time(self, key: str, rate_limit: int, tokens: int = 1) -> float:
        """
        Get time to wait until request allowed.
        
        Args:
            key: Rate limit key
            rate_limit: Requests per minute
            tokens: Number of tokens needed
            
        Returns:
            Wait time in seconds
        """
        bucket = self._get_bucket(key, rate_limit)
        return bucket.get_wait_time(tokens)
    
    def get_stats(self, key: str) -> Dict[str, int]:
        """
        Get rate limit statistics for key.
        
        Args:
            key: Rate limit key
            
        Returns:
            Dictionary with request and blocked counts
        """
        return {
            'total_requests': self.request_counts.get(key, 0),
            'blocked_requests': self.blocked_counts.get(key, 0),
            'allowed_requests': self.request_counts.get(key, 0) - self.blocked_counts.get(key, 0)
        }
    
    def reset(self, key: Optional[str] = None):
        """
        Reset rate limiter.
        
        Args:
            key: Specific key to reset, or None to reset all
        """
        with self.lock:
            if key:
                if key in self.buckets:
                    del self.buckets[key]
                if key in self.request_counts:
                    del self.request_counts[key]
                if key in self.blocked_counts:
                    del self.blocked_counts[key]
            else:
                self.buckets.clear()
                self.request_counts.clear()
                self.blocked_counts.clear()


class SlidingWindowRateLimiter:
    """Rate limiter using sliding window algorithm."""
    
    def __init__(self, window_size: int = 60):
        """
        Initialize sliding window rate limiter.
        
        Args:
            window_size: Window size in seconds
        """
        self.window_size = window_size
        self.requests: Dict[str, list[float]] = defaultdict(list)
        self.lock = Lock()
    
    def _clean_old_requests(self, key: str):
        """Remove requests outside the window."""
        now = time.time()
        cutoff = now - self.window_size
        
        self.requests[key] = [
            timestamp for timestamp in self.requests[key]
            if timestamp > cutoff
        ]
    
    def allow_request(self, key: str, rate_limit: int) -> bool:
        """
        Check if request is allowed.
        
        Args:
            key: Rate limit key
            rate_limit: Maximum requests in window
            
        Returns:
            True if request allowed, False otherwise
        """
        with self.lock:
            self._clean_old_requests(key)
            
            if len(self.requests[key]) < rate_limit:
                self.requests[key].append(time.time())
                return True
            
            return False
    
    def get_current_count(self, key: str) -> int:
        """
        Get current request count in window.
        
        Args:
            key: Rate limit key
            
        Returns:
            Number of requests in current window
        """
        with self.lock:
            self._clean_old_requests(key)
            return len(self.requests[key])
    
    def get_remaining(self, key: str, rate_limit: int) -> int:
        """
        Get remaining requests in window.
        
        Args:
            key: Rate limit key
            rate_limit: Maximum requests in window
            
        Returns:
            Number of remaining requests
        """
        current = self.get_current_count(key)
        return max(0, rate_limit - current)
    
    def reset(self, key: Optional[str] = None):
        """
        Reset rate limiter.
        
        Args:
            key: Specific key to reset, or None to reset all
        """
        with self.lock:
            if key:
                if key in self.requests:
                    del self.requests[key]
            else:
                self.requests.clear()


# Global rate limiter instance
rate_limiter = RateLimiter()

