from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import logging
import time
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BaseAIProvider(ABC):
    """
    Abstract base class for AI providers.
    Handles rate limiting, cost tracking, and error handling.
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
        
        # Rate limiting
        rate_limit = config.get('rate_limit', {})
        self.requests_per_minute = rate_limit.get('requests_per_minute', 50)
        self.tokens_per_minute = rate_limit.get('tokens_per_minute', 100000)
        
        # Tracking
        self.request_times: List[datetime] = []
        self.token_usage: List[tuple] = []  # (timestamp, tokens)
        self.total_cost = 0.0
        self.total_requests = 0
        
        # Cache
        self.cache: Dict[str, Any] = {}
        self.cache_enabled = True
    
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
        Check and enforce rate limits before making a request.
        Blocks if necessary to stay within limits.
        
        Args:
            estimated_tokens: Estimated tokens for the request
        """
        now = datetime.now()
        one_minute_ago = now - timedelta(minutes=1)
        
        # Clean old entries
        self.request_times = [t for t in self.request_times if t > one_minute_ago]
        self.token_usage = [(t, tokens) for t, tokens in self.token_usage if t > one_minute_ago]
        
        # Check request rate limit
        if len(self.request_times) >= self.requests_per_minute:
            sleep_time = (self.request_times[0] - one_minute_ago).total_seconds()
            if sleep_time > 0:
                logger.info(f"Rate limit reached, sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
                self._check_rate_limits(estimated_tokens)
                return
        
        # Check token rate limit
        current_tokens = sum(tokens for _, tokens in self.token_usage)
        if current_tokens + estimated_tokens > self.tokens_per_minute:
            sleep_time = (self.token_usage[0][0] - one_minute_ago).total_seconds()
            if sleep_time > 0:
                logger.info(f"Token rate limit reached, sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
                self._check_rate_limits(estimated_tokens)
                return
        
        # Record this request
        self.request_times.append(now)
        if estimated_tokens > 0:
            self.token_usage.append((now, estimated_tokens))
    
    def _record_usage(self, input_tokens: int, output_tokens: int, cost: float):
        """
        Record token usage and cost.
        
        Args:
            input_tokens: Number of input tokens used
            output_tokens: Number of output tokens used
            cost: Cost of the request
        """
        self.total_cost += cost
        self.total_requests += 1
        
        # Update token usage for rate limiting
        now = datetime.now()
        self.token_usage.append((now, input_tokens + output_tokens))
        
        logger.debug(f"Request cost: ${cost:.4f} ({input_tokens} in, {output_tokens} out)")
    
    def _get_cache_key(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        """
        Generate cache key for a request.
        
        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            **kwargs: Additional parameters
            
        Returns:
            Cache key string
        """
        import hashlib
        content = f"{system_prompt}|{user_prompt}|{kwargs}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _check_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Check if response is cached.
        
        Args:
            cache_key: Cache key to check
            
        Returns:
            Cached response or None
        """
        if not self.cache_enabled:
            return None
        
        if cache_key in self.cache:
            logger.debug("Cache hit")
            return self.cache[cache_key]
        
        return None
    
    def _store_cache(self, cache_key: str, response: Dict[str, Any]):
        """
        Store response in cache.
        
        Args:
            cache_key: Cache key
            response: Response to cache
        """
        if self.cache_enabled:
            self.cache[cache_key] = response
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get provider usage statistics.
        
        Returns:
            Dictionary with usage stats
        """
        return {
            'provider': self.__class__.__name__,
            'model': self.model,
            'total_requests': self.total_requests,
            'total_cost': self.total_cost,
            'cache_size': len(self.cache),
        }
    
    def clear_cache(self):
        """Clear the response cache."""
        self.cache.clear()
        logger.info("Cache cleared")

