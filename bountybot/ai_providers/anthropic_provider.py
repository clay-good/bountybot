import logging
import json
from typing import Dict, Any, Optional
from anthropic import Anthropic
from .base import BaseAIProvider

logger = logging.getLogger(__name__)


class AnthropicProvider(BaseAIProvider):
    """
    Anthropic Claude provider implementation.
    Uses Claude 3.5 Sonnet by default.
    """
    
    # Pricing per million tokens (as of 2024)
    INPUT_COST_PER_MILLION = 3.0
    OUTPUT_COST_PER_MILLION = 15.0
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Anthropic provider.
        
        Args:
            config: Provider configuration
        """
        super().__init__(config)
        self.client = Anthropic(api_key=self.api_key)
        logger.info(f"Initialized Anthropic provider with model: {self.model}")
    
    def complete(self, 
                 system_prompt: str, 
                 user_prompt: str,
                 max_tokens: Optional[int] = None,
                 temperature: Optional[float] = None,
                 json_mode: bool = False) -> Dict[str, Any]:
        """
        Make a completion request to Claude.
        
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
        
        # Estimate tokens for rate limiting
        estimated_tokens = self.count_tokens(system_prompt + user_prompt)
        self._check_rate_limits(estimated_tokens)
        
        # Prepare request parameters
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature
        
        # Add JSON instruction if needed
        if json_mode:
            system_prompt += "\n\nYou must respond with valid JSON only. Do not include any text outside the JSON structure."
        
        try:
            # Make API request
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            # Extract response
            content = response.content[0].text
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            
            # Calculate cost
            cost = self.calculate_cost(input_tokens, output_tokens)
            
            # Record usage
            self._record_usage(input_tokens, output_tokens, cost)
            
            result = {
                'content': content,
                'input_tokens': input_tokens,
                'output_tokens': output_tokens,
                'cost': cost,
            }
            
            # Cache the result
            self._store_cache(cache_key, result)
            
            logger.info(f"Completion successful: {input_tokens} in, {output_tokens} out, ${cost:.4f}")
            return result
            
        except Exception as e:
            logger.error(f"Error calling Anthropic API: {e}")
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
        Calculate cost for Claude API usage.
        
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            
        Returns:
            Cost in USD
        """
        input_cost = (input_tokens / 1_000_000) * self.INPUT_COST_PER_MILLION
        output_cost = (output_tokens / 1_000_000) * self.OUTPUT_COST_PER_MILLION
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

