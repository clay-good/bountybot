"""
Async Anthropic Claude provider with prompt caching support.
"""

import logging
import json
from typing import Dict, Any, Optional, AsyncIterator
from anthropic import AsyncAnthropic
from .async_base import AsyncBaseAIProvider

logger = logging.getLogger(__name__)


class AsyncAnthropicProvider(AsyncBaseAIProvider):
    """
    Async Anthropic Claude provider implementation with Prompt Caching support.
    Uses Claude 3.5 Sonnet by default.

    Prompt Caching Feature:
    - Caches prompt prefixes on Anthropic's servers
    - Reduces costs by 90% for cached content (write: $3.75/MTok, read: $0.30/MTok)
    - Cache TTL: 5 minutes
    - Minimum cacheable content: 1024 tokens
    - Automatically marks system prompts and knowledge base content for caching
    """

    # Pricing per million tokens (as of 2024)
    INPUT_COST_PER_MILLION = 3.0
    OUTPUT_COST_PER_MILLION = 15.0

    # Prompt caching pricing (90% cost reduction for cache reads)
    CACHE_WRITE_COST_PER_MILLION = 3.75  # Slightly higher than regular input
    CACHE_READ_COST_PER_MILLION = 0.30   # 90% cheaper than regular input

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize async Anthropic provider.

        Args:
            config: Provider configuration
        """
        super().__init__(config)
        self.api_key = config.get('api_key')
        if not self.api_key:
            raise ValueError("Anthropic API key is required")

        self.client = AsyncAnthropic(api_key=self.api_key)

        # Prompt caching configuration
        self.prompt_caching_enabled = config.get('prompt_caching_enabled', True)
        self.cache_min_tokens = config.get('cache_min_tokens', 1024)  # Minimum tokens to cache

        # Track cache performance
        self.cache_creation_tokens = 0
        self.cache_read_tokens = 0
        self.total_cache_savings = 0.0

        logger.info(f"Initialized async Anthropic provider with model: {self.model}")
        if self.prompt_caching_enabled:
            logger.info(f"Prompt caching ENABLED (min tokens: {self.cache_min_tokens})")

    async def complete(self,
                      system_prompt: str,
                      user_prompt: str,
                      max_tokens: Optional[int] = None,
                      temperature: Optional[float] = None,
                      json_mode: bool = False) -> Dict[str, Any]:
        """
        Make an async completion request to Claude with prompt caching.

        Args:
            system_prompt: System/instruction prompt (will be cached if >1024 tokens)
            user_prompt: User message/query
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            json_mode: Whether to request JSON output

        Returns:
            Dictionary with 'content', 'input_tokens', 'output_tokens', 'cost',
            'cache_creation_tokens', 'cache_read_tokens'
        """
        # Check local cache first
        cache_key = self._get_cache_key(system_prompt, user_prompt,
                                       max_tokens=max_tokens,
                                       temperature=temperature,
                                       json_mode=json_mode)
        cached = await self._check_cache(cache_key)
        if cached:
            return cached

        # Wait for rate limits
        estimated_tokens = self.count_tokens(system_prompt) + self.count_tokens(user_prompt)
        await self._wait_for_rate_limit(estimated_tokens)

        # Prepare system prompt with caching if enabled
        system_content = self._prepare_system_prompt_with_caching(system_prompt)

        # Prepare request parameters
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature

        messages = [{"role": "user", "content": user_prompt}]

        # Add JSON instruction if requested
        if json_mode:
            messages[0]["content"] += "\n\nPlease respond with valid JSON only."

        # Make API call with circuit breaker
        async def _api_call():
            return await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_content,
                messages=messages
            )

        response = await self.circuit_breaker.call(_api_call)

        # Extract response
        content = response.content[0].text

        # Extract token usage
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens

        # Extract cache metrics (if available)
        cache_creation_tokens = getattr(response.usage, 'cache_creation_input_tokens', 0)
        cache_read_tokens = getattr(response.usage, 'cache_read_input_tokens', 0)

        # Calculate cost with cache pricing
        cost = self.calculate_cost_with_cache(
            input_tokens, output_tokens,
            cache_creation_tokens, cache_read_tokens
        )

        # Update statistics
        async with self.lock:
            self.total_requests += 1
            self.total_tokens_in += input_tokens
            self.total_tokens_out += output_tokens
            self.total_cost += cost

            # Update cache metrics
            self.cache_creation_tokens += cache_creation_tokens
            self.cache_read_tokens += cache_read_tokens

            # Calculate savings from cache reads
            if cache_read_tokens > 0:
                regular_cost = (cache_read_tokens / 1_000_000) * self.INPUT_COST_PER_MILLION
                cache_cost = (cache_read_tokens / 1_000_000) * self.CACHE_READ_COST_PER_MILLION
                savings = regular_cost - cache_cost
                self.total_cache_savings += savings

        result = {
            'content': content,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'cost': cost,
            'cache_creation_tokens': cache_creation_tokens,
            'cache_read_tokens': cache_read_tokens,
        }

        # Store in local cache
        await self._store_cache(cache_key, result)

        return result

    async def stream_complete(self,
                             system_prompt: str,
                             user_prompt: str,
                             max_tokens: Optional[int] = None,
                             temperature: Optional[float] = None) -> AsyncIterator[str]:
        """
        Make a streaming async completion request to Claude.

        Args:
            system_prompt: System/instruction prompt
            user_prompt: User message/query
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature

        Yields:
            Content chunks as they arrive
        """
        # Wait for rate limits
        estimated_tokens = self.count_tokens(system_prompt) + self.count_tokens(user_prompt)
        await self._wait_for_rate_limit(estimated_tokens)

        # Prepare system prompt with caching if enabled
        system_content = self._prepare_system_prompt_with_caching(system_prompt)

        # Prepare request parameters
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature

        messages = [{"role": "user", "content": user_prompt}]

        # Make streaming API call with circuit breaker
        async def _api_call():
            return await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_content,
                messages=messages,
                stream=True
            )

        stream = await self.circuit_breaker.call(_api_call)

        # Stream response
        async for event in stream:
            if event.type == "content_block_delta":
                if hasattr(event.delta, 'text'):
                    yield event.delta.text

    def _prepare_system_prompt_with_caching(self, system_prompt: str):
        """
        Prepare system prompt with cache control markers if enabled.

        Args:
            system_prompt: System prompt text

        Returns:
            System prompt (string or list with cache control)
        """
        if not self.prompt_caching_enabled:
            return system_prompt

        # Check if prompt is large enough to cache
        prompt_tokens = self.count_tokens(system_prompt)
        if prompt_tokens < self.cache_min_tokens:
            return system_prompt

        # Mark for caching (ephemeral cache, 5-minute TTL)
        return [
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"}
            }
        ]

    def calculate_cost_with_cache(self,
                                  input_tokens: int,
                                  output_tokens: int,
                                  cache_creation_tokens: int,
                                  cache_read_tokens: int) -> float:
        """
        Calculate cost with cache pricing.

        Args:
            input_tokens: Regular input tokens
            output_tokens: Output tokens
            cache_creation_tokens: Tokens written to cache
            cache_read_tokens: Tokens read from cache

        Returns:
            Total cost in USD
        """
        # Regular input tokens (not cached)
        regular_tokens = input_tokens - cache_creation_tokens - cache_read_tokens
        regular_cost = (regular_tokens / 1_000_000) * self.INPUT_COST_PER_MILLION

        # Cache creation cost (25% more expensive)
        cache_write_cost = (cache_creation_tokens / 1_000_000) * self.CACHE_WRITE_COST_PER_MILLION

        # Cache read cost (90% cheaper)
        cache_read_cost = (cache_read_tokens / 1_000_000) * self.CACHE_READ_COST_PER_MILLION

        # Output cost
        output_cost = (output_tokens / 1_000_000) * self.OUTPUT_COST_PER_MILLION

        return regular_cost + cache_write_cost + cache_read_cost + output_cost

    def count_tokens(self, text: str) -> int:
        """
        Count tokens in text using Anthropic's tokenizer.

        Args:
            text: Text to count tokens for

        Returns:
            Token count
        """
        # Anthropic uses ~4 characters per token as approximation
        # For production, use the official tokenizer
        return len(text) // 4

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get provider statistics including prompt cache metrics.

        Returns:
            Dictionary with usage statistics and cache metrics
        """
        # Get base stats
        stats = await super().get_stats()

        # Add prompt cache metrics
        if self.prompt_caching_enabled:
            total_cache_tokens = self.cache_creation_tokens + self.cache_read_tokens
            cache_efficiency = 0.0
            if total_cache_tokens > 0:
                cache_efficiency = (self.cache_read_tokens / total_cache_tokens) * 100

            stats['prompt_cache'] = {
                'enabled': True,
                'cache_creation_tokens': self.cache_creation_tokens,
                'cache_read_tokens': self.cache_read_tokens,
                'total_cache_tokens': total_cache_tokens,
                'cache_efficiency_percent': round(cache_efficiency, 2),
                'total_savings_usd': round(self.total_cache_savings, 4),
                'min_tokens_for_caching': self.cache_min_tokens,
            }
        else:
            stats['prompt_cache'] = {'enabled': False}

        return stats

