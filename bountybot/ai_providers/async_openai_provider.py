"""
Async OpenAI GPT provider implementation.
"""

import logging
import json
from typing import Dict, Any, Optional, AsyncIterator
try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from .async_base import AsyncBaseAIProvider

logger = logging.getLogger(__name__)


class AsyncOpenAIProvider(AsyncBaseAIProvider):
    """
    Async OpenAI GPT provider implementation.
    Supports GPT-4 Turbo, GPT-4, and GPT-3.5 Turbo.
    """

    # Pricing per million tokens (GPT-4 Turbo as of 2024)
    PRICING = {
        'gpt-4-turbo-preview': {'input': 10.0, 'output': 30.0},
        'gpt-4-turbo': {'input': 10.0, 'output': 30.0},
        'gpt-4': {'input': 30.0, 'output': 60.0},
        'gpt-3.5-turbo': {'input': 0.5, 'output': 1.5},
        'gpt-3.5-turbo-16k': {'input': 3.0, 'output': 4.0},
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize async OpenAI provider.

        Args:
            config: Provider configuration
        """
        if not OPENAI_AVAILABLE:
            raise ImportError("OpenAI package not installed. Install with: pip install openai")

        super().__init__(config)
        self.api_key = config.get('api_key')
        if not self.api_key:
            raise ValueError("OpenAI API key is required")

        self.client = AsyncOpenAI(api_key=self.api_key)

        # Get pricing for model
        self.input_cost_per_million = self.PRICING.get(self.model, {}).get('input', 10.0)
        self.output_cost_per_million = self.PRICING.get(self.model, {}).get('output', 30.0)

        logger.info(f"Initialized async OpenAI provider with model: {self.model}")

    async def complete(self,
                      system_prompt: str,
                      user_prompt: str,
                      max_tokens: Optional[int] = None,
                      temperature: Optional[float] = None,
                      json_mode: bool = False) -> Dict[str, Any]:
        """
        Make an async completion request to OpenAI.

        Args:
            system_prompt: System/instruction prompt
            user_prompt: User message/query
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            json_mode: Whether to request JSON output

        Returns:
            Dictionary with 'content', 'input_tokens', 'output_tokens', 'cost'
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

        # Prepare request parameters
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        # Prepare kwargs
        kwargs = {
            'model': self.model,
            'messages': messages,
            'max_tokens': max_tokens,
            'temperature': temperature,
        }

        # Enable JSON mode if requested (GPT-4 Turbo and later)
        if json_mode and 'turbo' in self.model.lower():
            kwargs['response_format'] = {"type": "json_object"}
            # Add JSON instruction to system prompt
            messages[0]["content"] += "\n\nYou must respond with valid JSON."

        # Make API call with circuit breaker
        async def _api_call():
            return await self.client.chat.completions.create(**kwargs)

        response = await self.circuit_breaker.call(_api_call)

        # Extract response
        content = response.choices[0].message.content

        # Extract token usage
        input_tokens = response.usage.prompt_tokens
        output_tokens = response.usage.completion_tokens

        # Calculate cost
        cost = self._calculate_cost(input_tokens, output_tokens)

        # Update statistics
        async with self.lock:
            self.total_requests += 1
            self.total_tokens_in += input_tokens
            self.total_tokens_out += output_tokens
            self.total_cost += cost

        result = {
            'content': content,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'cost': cost,
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
        Make a streaming async completion request to OpenAI.

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

        # Prepare request parameters
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        # Make streaming API call with circuit breaker
        async def _api_call():
            return await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                stream=True
            )

        stream = await self.circuit_breaker.call(_api_call)

        # Stream response
        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Calculate cost for request.

        Args:
            input_tokens: Input token count
            output_tokens: Output token count

        Returns:
            Cost in USD
        """
        input_cost = (input_tokens / 1_000_000) * self.input_cost_per_million
        output_cost = (output_tokens / 1_000_000) * self.output_cost_per_million
        return input_cost + output_cost

    def count_tokens(self, text: str) -> int:
        """
        Count tokens in text using approximation.

        Args:
            text: Text to count tokens for

        Returns:
            Token count (approximation)
        """
        # OpenAI uses ~4 characters per token as approximation
        # For production, use tiktoken library
        return len(text) // 4


class AsyncGeminiProvider(AsyncBaseAIProvider):
    """
    Async Google Gemini provider implementation.
    Supports Gemini 1.5 Pro and Flash models.
    """

    # Pricing per million tokens (Gemini 1.5 as of 2024)
    PRICING = {
        'gemini-1.5-pro': {'input': 3.5, 'output': 10.5},
        'gemini-1.5-flash': {'input': 0.35, 'output': 1.05},
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize async Gemini provider.

        Args:
            config: Provider configuration
        """
        try:
            import google.generativeai as genai
            self.genai = genai
            GEMINI_AVAILABLE = True
        except ImportError:
            raise ImportError("Google Generative AI package not installed. Install with: pip install google-generativeai")

        super().__init__(config)
        self.api_key = config.get('api_key')
        if not self.api_key:
            raise ValueError("Gemini API key is required")

        self.genai.configure(api_key=self.api_key)
        self.client = self.genai.GenerativeModel(self.model)

        # Get pricing for model
        self.input_cost_per_million = self.PRICING.get(self.model, {}).get('input', 3.5)
        self.output_cost_per_million = self.PRICING.get(self.model, {}).get('output', 10.5)

        logger.info(f"Initialized async Gemini provider with model: {self.model}")

    async def complete(self,
                      system_prompt: str,
                      user_prompt: str,
                      max_tokens: Optional[int] = None,
                      temperature: Optional[float] = None,
                      json_mode: bool = False) -> Dict[str, Any]:
        """
        Make an async completion request to Gemini.

        Args:
            system_prompt: System/instruction prompt
            user_prompt: User message/query
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            json_mode: Whether to request JSON output

        Returns:
            Dictionary with 'content', 'input_tokens', 'output_tokens', 'cost'
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

        # Combine prompts
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        if json_mode:
            full_prompt += "\n\nPlease respond with valid JSON only."

        # Prepare generation config
        generation_config = {
            'max_output_tokens': max_tokens or self.max_tokens,
            'temperature': temperature if temperature is not None else self.temperature,
        }

        # Make API call with circuit breaker (note: Gemini doesn't have native async yet)
        async def _api_call():
            import asyncio
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                lambda: self.client.generate_content(
                    full_prompt,
                    generation_config=generation_config
                )
            )

        response = await self.circuit_breaker.call(_api_call)

        # Extract response
        content = response.text

        # Count tokens (Gemini provides token counts)
        input_tokens = response.usage_metadata.prompt_token_count
        output_tokens = response.usage_metadata.candidates_token_count

        # Calculate cost
        cost = self._calculate_cost(input_tokens, output_tokens)

        # Update statistics
        async with self.lock:
            self.total_requests += 1
            self.total_tokens_in += input_tokens
            self.total_tokens_out += output_tokens
            self.total_cost += cost

        result = {
            'content': content,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'cost': cost,
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
        Make a streaming async completion request to Gemini.

        Args:
            system_prompt: System/instruction prompt
            user_prompt: User message/query
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature

        Yields:
            Content chunks as they arrive
        """
        # Gemini streaming not yet implemented in async
        # Fall back to non-streaming
        result = await self.complete(system_prompt, user_prompt, max_tokens, temperature)
        yield result['content']

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for request."""
        input_cost = (input_tokens / 1_000_000) * self.input_cost_per_million
        output_cost = (output_tokens / 1_000_000) * self.output_cost_per_million
        return input_cost + output_cost

    def count_tokens(self, text: str) -> int:
        """Count tokens in text using approximation."""
        return len(text) // 4

