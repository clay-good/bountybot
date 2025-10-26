import logging
import json
from typing import Dict, Any, Optional
from anthropic import Anthropic
from .base import BaseAIProvider

logger = logging.getLogger(__name__)


class AnthropicProvider(BaseAIProvider):
    """
    Anthropic Claude provider implementation with Prompt Caching support.
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
        Initialize Anthropic provider.

        Args:
            config: Provider configuration
        """
        super().__init__(config)
        self.client = Anthropic(api_key=self.api_key)

        # Prompt caching configuration
        self.prompt_caching_enabled = config.get('prompt_caching_enabled', True)
        self.cache_min_tokens = config.get('cache_min_tokens', 1024)  # Minimum tokens to cache

        # Track cache performance
        self.cache_creation_tokens = 0
        self.cache_read_tokens = 0
        self.total_cache_savings = 0.0

        logger.info(f"Initialized Anthropic provider with model: {self.model}")
        if self.prompt_caching_enabled:
            logger.info(f"Prompt caching ENABLED (min tokens: {self.cache_min_tokens})")
    
    def complete(self,
                 system_prompt: str,
                 user_prompt: str,
                 max_tokens: Optional[int] = None,
                 temperature: Optional[float] = None,
                 json_mode: bool = False) -> Dict[str, Any]:
        """
        Make a completion request to Claude with retry logic, circuit breaker, and prompt caching.

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
        cached = self._check_cache(cache_key)
        if cached:
            return cached

        # Estimate tokens for rate limiting
        estimated_tokens = self.count_tokens(system_prompt + user_prompt)
        self._check_rate_limits(estimated_tokens)

        # Prepare request parameters
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature

        # Add JSON instruction if needed
        if json_mode:
            system_prompt += "\n\nYou must respond with valid JSON only. Do not include any text outside the JSON structure."

        # Execute with circuit breaker and retry logic
        def make_request():
            try:
                logger.debug(f"Making API request to {self.model} (max_tokens={max_tokens}, temp={temperature})")

                # Prepare system prompt with caching if enabled
                system_content = self._prepare_system_prompt_with_caching(system_prompt)

                # Make API request with prompt caching support
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_content,
                    messages=[
                        {"role": "user", "content": user_prompt}
                    ]
                )

                # Extract response
                content = response.content[0].text
                input_tokens = response.usage.input_tokens
                output_tokens = response.usage.output_tokens

                # Extract cache metrics if available
                cache_creation_tokens = getattr(response.usage, 'cache_creation_input_tokens', 0)
                cache_read_tokens = getattr(response.usage, 'cache_read_input_tokens', 0)

                # Calculate cost with cache pricing
                cost = self.calculate_cost_with_cache(
                    input_tokens,
                    output_tokens,
                    cache_creation_tokens,
                    cache_read_tokens
                )

                # Track cache performance
                if cache_creation_tokens > 0 or cache_read_tokens > 0:
                    self.cache_creation_tokens += cache_creation_tokens
                    self.cache_read_tokens += cache_read_tokens

                    # Calculate savings (90% reduction for cache reads)
                    regular_cost = (cache_read_tokens / 1_000_000) * self.INPUT_COST_PER_MILLION
                    cache_cost = (cache_read_tokens / 1_000_000) * self.CACHE_READ_COST_PER_MILLION
                    savings = regular_cost - cache_cost
                    self.total_cache_savings += savings

                    logger.info(f"Prompt cache: created={cache_creation_tokens}, read={cache_read_tokens}, saved=${savings:.4f}")

                # Record usage
                self._record_usage(input_tokens, output_tokens, cost)

                result = {
                    'content': content,
                    'input_tokens': input_tokens,
                    'output_tokens': output_tokens,
                    'cost': cost,
                    'cache_creation_tokens': cache_creation_tokens,
                    'cache_read_tokens': cache_read_tokens,
                }

                # Cache the result locally
                self._store_cache(cache_key, result)

                return result

            except Exception as e:
                logger.error(f"Error calling Anthropic API: {e}")
                raise

        # Execute with circuit breaker and retry logic
        try:
            result = self.circuit_breaker.call(
                self._retry_with_backoff,
                make_request
            )
            return result
        except Exception as e:
            logger.error(f"Failed to complete request after all retries: {e}")
            raise
    
    def count_tokens(self, text: str) -> int:
        """
        Count tokens in text using Anthropic's token counting.
        Uses approximation: ~4 characters per token.
        
        Args:
            text: Text to count tokens for
            
        Returns:
            Estimated number of tokens
        """
        # Anthropic doesn't provide a public tokenizer
        # Use approximation: ~4 characters per token
        return len(text) // 4
    
    def calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Calculate cost for Claude API usage (without cache).

        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens

        Returns:
            Cost in USD
        """
        input_cost = (input_tokens / 1_000_000) * self.INPUT_COST_PER_MILLION
        output_cost = (output_tokens / 1_000_000) * self.OUTPUT_COST_PER_MILLION
        return input_cost + output_cost

    def calculate_cost_with_cache(self,
                                   input_tokens: int,
                                   output_tokens: int,
                                   cache_creation_tokens: int = 0,
                                   cache_read_tokens: int = 0) -> float:
        """
        Calculate cost for Claude API usage with prompt caching.

        Args:
            input_tokens: Number of regular input tokens
            output_tokens: Number of output tokens
            cache_creation_tokens: Tokens written to cache (25% more expensive)
            cache_read_tokens: Tokens read from cache (90% cheaper)

        Returns:
            Cost in USD
        """
        # Regular input tokens (not cached)
        regular_input_tokens = input_tokens - cache_creation_tokens - cache_read_tokens
        regular_cost = (regular_input_tokens / 1_000_000) * self.INPUT_COST_PER_MILLION

        # Cache creation cost (slightly higher)
        cache_write_cost = (cache_creation_tokens / 1_000_000) * self.CACHE_WRITE_COST_PER_MILLION

        # Cache read cost (90% cheaper)
        cache_read_cost = (cache_read_tokens / 1_000_000) * self.CACHE_READ_COST_PER_MILLION

        # Output cost (unchanged)
        output_cost = (output_tokens / 1_000_000) * self.OUTPUT_COST_PER_MILLION

        total_cost = regular_cost + cache_write_cost + cache_read_cost + output_cost

        logger.debug(f"Cost breakdown: regular=${regular_cost:.4f}, cache_write=${cache_write_cost:.4f}, "
                    f"cache_read=${cache_read_cost:.4f}, output=${output_cost:.4f}, total=${total_cost:.4f}")

        return total_cost

    def _prepare_system_prompt_with_caching(self, system_prompt: str):
        """
        Prepare system prompt with cache control markers.

        Anthropic's prompt caching works by marking content blocks with cache_control.
        Content must be at least 1024 tokens to be cached.
        Cache TTL is 5 minutes.

        Args:
            system_prompt: System prompt text

        Returns:
            System prompt formatted for caching (string or list of content blocks)
        """
        if not self.prompt_caching_enabled:
            return system_prompt

        # Estimate tokens in system prompt
        prompt_tokens = self.count_tokens(system_prompt)

        # Only use caching if prompt is large enough
        if prompt_tokens < self.cache_min_tokens:
            logger.debug(f"System prompt too small for caching ({prompt_tokens} < {self.cache_min_tokens} tokens)")
            return system_prompt

        # Mark system prompt for caching
        # Anthropic caches content blocks marked with cache_control: {"type": "ephemeral"}
        logger.debug(f"Marking system prompt for caching ({prompt_tokens} tokens)")

        return [
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"}
            }
        ]
    
    def complete_with_json(self, system_prompt: str, user_prompt: str,
                          max_tokens: Optional[int] = None) -> Dict[str, Any]:
        """
        Make a completion request and parse JSON response.

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Parsed JSON response
        """
        result = self.complete(system_prompt, user_prompt,
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
            # Return the raw content if parsing fails
            result['parsed'] = None
            return result

    def get_stats(self) -> Dict[str, Any]:
        """
        Get provider statistics including prompt cache performance.

        Returns:
            Dictionary with usage statistics and cache metrics
        """
        # Get base stats
        stats = super().get_stats()

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

