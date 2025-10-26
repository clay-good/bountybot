import logging
import json
from typing import Dict, Any, Optional
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    
from .base import BaseAIProvider

logger = logging.getLogger(__name__)


class GeminiProvider(BaseAIProvider):
    """
    Google Gemini provider implementation.
    Supports Gemini Pro and Gemini Pro Vision with multimodal capabilities.
    """
    
    # Pricing per million tokens (as of 2024)
    PRICING = {
        'gemini-pro': {'input': 0.5, 'output': 1.5},
        'gemini-pro-vision': {'input': 0.5, 'output': 1.5},
        'gemini-1.5-pro': {'input': 3.5, 'output': 10.5},
        'gemini-1.5-flash': {'input': 0.35, 'output': 1.05},
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Gemini provider.
        
        Args:
            config: Provider configuration
        """
        if not GEMINI_AVAILABLE:
            raise ImportError(
                "Google Generative AI package not installed. "
                "Install with: pip install google-generativeai"
            )
        
        super().__init__(config)
        
        # Configure Gemini
        genai.configure(api_key=self.api_key)
        
        # Default to Gemini 1.5 Pro if not specified
        if not self.model:
            self.model = 'gemini-1.5-pro'
        
        # Initialize model
        self.client = genai.GenerativeModel(self.model)
        
        logger.info(f"Initialized Gemini provider with model: {self.model}")
    
    def complete(self,
                 system_prompt: str,
                 user_prompt: str,
                 max_tokens: Optional[int] = None,
                 temperature: Optional[float] = None,
                 json_mode: bool = False) -> Dict[str, Any]:
        """
        Make a completion request to Gemini with retry logic and circuit breaker.

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

                # Combine system and user prompts
                # Gemini doesn't have separate system/user roles in the same way
                full_prompt = f"{system_prompt}\n\n{user_prompt}"
                
                if json_mode:
                    full_prompt += "\n\nRespond with valid JSON only."

                # Configure generation
                generation_config = genai.types.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=temperature,
                )

                # Make API request
                response = self.client.generate_content(
                    full_prompt,
                    generation_config=generation_config
                )

                # Extract response
                content = response.text
                
                # Estimate token usage (Gemini doesn't always provide exact counts)
                input_tokens = self.count_tokens(full_prompt)
                output_tokens = self.count_tokens(content)

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
                    'finish_reason': 'stop',  # Gemini doesn't provide this directly
                }

                # Cache the result
                self._store_cache(cache_key, result)

                logger.debug(f"Request successful: {input_tokens} in, {output_tokens} out, ${cost:.4f}")
                return result

            except Exception as e:
                logger.error(f"Gemini API request failed: {e}")
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
        Count tokens in text using Gemini's token counting.
        Uses approximation: ~4 characters per token.
        
        Args:
            text: Text to count tokens for
            
        Returns:
            Estimated number of tokens
        """
        try:
            # Try to use Gemini's token counting if available
            result = self.client.count_tokens(text)
            return result.total_tokens
        except Exception as e:
            # Fallback to approximation
            logger.debug(f"Token counting failed, using approximation: {e}")
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
        pricing = self.PRICING.get(self.model, {'input': 0.5, 'output': 1.5})
        
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
                if len(lines) > 2:
                    content = '\n'.join(lines[1:-1])
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
        Make a streaming completion request to Gemini.
        
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
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        estimated_tokens = self.count_tokens(full_prompt)
        self._check_rate_limits(estimated_tokens)

        try:
            logger.debug(f"Making streaming API request to {self.model}")

            # Configure generation
            generation_config = genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            )

            # Make streaming API request
            response = self.client.generate_content(
                full_prompt,
                generation_config=generation_config,
                stream=True
            )

            # Yield chunks as they arrive
            for chunk in response:
                if chunk.text:
                    yield chunk.text

        except Exception as e:
            logger.error(f"Gemini streaming request failed: {e}")
            raise

