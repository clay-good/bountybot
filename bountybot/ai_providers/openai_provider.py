import logging
import json
from typing import Dict, Any, Optional
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    
from .base import BaseAIProvider

logger = logging.getLogger(__name__)


class OpenAIProvider(BaseAIProvider):
    """
    OpenAI GPT-4 provider implementation.
    Supports GPT-4, GPT-4 Turbo, and GPT-3.5 Turbo with streaming and function calling.
    """
    
    # Pricing per million tokens (as of 2024)
    PRICING = {
        'gpt-4-turbo-preview': {'input': 10.0, 'output': 30.0},
        'gpt-4-turbo': {'input': 10.0, 'output': 30.0},
        'gpt-4': {'input': 30.0, 'output': 60.0},
        'gpt-4-32k': {'input': 60.0, 'output': 120.0},
        'gpt-3.5-turbo': {'input': 0.5, 'output': 1.5},
        'gpt-3.5-turbo-16k': {'input': 3.0, 'output': 4.0},
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize OpenAI provider.
        
        Args:
            config: Provider configuration
        """
        if not OPENAI_AVAILABLE:
            raise ImportError(
                "OpenAI package not installed. Install with: pip install openai"
            )
        
        super().__init__(config)
        self.client = OpenAI(api_key=self.api_key)
        
        # Default to GPT-4 Turbo if not specified
        if not self.model:
            self.model = 'gpt-4-turbo-preview'
        
        logger.info(f"Initialized OpenAI provider with model: {self.model}")
    
    def complete(self,
                 system_prompt: str,
                 user_prompt: str,
                 max_tokens: Optional[int] = None,
                 temperature: Optional[float] = None,
                 json_mode: bool = False) -> Dict[str, Any]:
        """
        Make a completion request to OpenAI with retry logic and circuit breaker.

        Args:
            system_prompt: System/instruction prompt
            user_prompt: User message/query
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            json_mode: Whether to request JSON output

        Returns:
            Dictionary with 'content', 'input_tokens', 'output_tokens', 'cost'
        """
        # Check cache first
        cache_key = self._get_cache_key(system_prompt, user_prompt,
                                       max_tokens=max_tokens,
                                       temperature=temperature,
                                       json_mode=json_mode)
        cached = self._check_cache(cache_key)
        if cached:
            return cached

        # Use defaults if not specified
        if max_tokens is None:
            max_tokens = self.max_tokens
        if temperature is None:
            temperature = self.temperature

        # Check rate limits
        estimated_tokens = self.count_tokens(system_prompt + user_prompt)
        self._check_rate_limits(estimated_tokens)

        # Execute with circuit breaker and retry logic
        def make_request():
            try:
                logger.debug(f"Making API request to {self.model} (max_tokens={max_tokens}, temp={temperature})")

                # Prepare request parameters
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
                
                request_params = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
                
                # Enable JSON mode if requested (GPT-4 Turbo and later)
                if json_mode and 'turbo' in self.model.lower():
                    request_params["response_format"] = {"type": "json_object"}
                    # Add JSON instruction to system prompt if not already there
                    if "json" not in system_prompt.lower():
                        messages[0]["content"] += "\n\nRespond with valid JSON only."

                # Make API request
                response = self.client.chat.completions.create(**request_params)

                # Extract response
                content = response.choices[0].message.content
                input_tokens = response.usage.prompt_tokens
                output_tokens = response.usage.completion_tokens

                # Calculate cost
                cost = self.calculate_cost(input_tokens, output_tokens)

                # Record usage
                self._record_usage(input_tokens, output_tokens, cost)

                result = {
                    'content': content,
                    'input_tokens': input_tokens,
                    'output_tokens': output_tokens,
                    'cost': cost,
                    'model': self.model,
                    'finish_reason': response.choices[0].finish_reason,
                }

                # Cache the result
                self._store_cache(cache_key, result)

                logger.debug(f"Request successful: {input_tokens} in, {output_tokens} out, ${cost:.4f}")
                return result

            except Exception as e:
                logger.error(f"OpenAI API request failed: {e}")
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
        Count tokens in text using OpenAI's token counting.
        Uses approximation: ~4 characters per token.
        
        For accurate counting, use tiktoken library.
        
        Args:
            text: Text to count tokens for
            
        Returns:
            Estimated number of tokens
        """
        # Simple approximation
        # For production, consider using tiktoken:
        # import tiktoken
        # encoding = tiktoken.encoding_for_model(self.model)
        # return len(encoding.encode(text))
        return len(text) // 4
    
    def calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Calculate cost for token usage based on model pricing.
        
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            
        Returns:
            Cost in USD
        """
        pricing = self.PRICING.get(self.model, {'input': 10.0, 'output': 30.0})
        
        input_cost = (input_tokens / 1_000_000) * pricing['input']
        output_cost = (output_tokens / 1_000_000) * pricing['output']
        
        return input_cost + output_cost
    
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
                # Remove first and last lines (``` markers)
                if len(lines) > 2:
                    content = '\n'.join(lines[1:-1])
                    # Remove language identifier if present
                    if content.startswith('json'):
                        content = '\n'.join(content.split('\n')[1:])
            
            parsed = json.loads(content)
            result['parsed'] = parsed
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Response content: {result['content']}")
            result['parsed'] = None
            result['parse_error'] = str(e)
            return result
    
    def stream_complete(self,
                       system_prompt: str,
                       user_prompt: str,
                       max_tokens: Optional[int] = None,
                       temperature: Optional[float] = None):
        """
        Make a streaming completion request to OpenAI.
        
        Args:
            system_prompt: System/instruction prompt
            user_prompt: User message/query
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            
        Yields:
            Chunks of generated text
        """
        # Use defaults if not specified
        if max_tokens is None:
            max_tokens = self.max_tokens
        if temperature is None:
            temperature = self.temperature

        # Check rate limits
        estimated_tokens = self.count_tokens(system_prompt + user_prompt)
        self._check_rate_limits(estimated_tokens)

        try:
            logger.debug(f"Making streaming API request to {self.model}")

            # Make streaming API request
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                stream=True
            )

            # Yield chunks as they arrive
            for chunk in stream:
                if chunk.choices[0].delta.content is not None:
                    yield chunk.choices[0].delta.content

        except Exception as e:
            logger.error(f"OpenAI streaming request failed: {e}")
            raise

