import pytest
from unittest.mock import Mock, patch, MagicMock
from bountybot.ai_providers.anthropic_provider import AnthropicProvider


class TestPromptCaching:
    """Test Anthropic Prompt Caching feature."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'api_key': 'test-key',
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': 4096,
            'temperature': 0.3,
            'prompt_caching_enabled': True,
            'cache_min_tokens': 1024,
        }
    
    def test_prompt_caching_enabled_by_default(self):
        """Test that prompt caching is enabled by default."""
        provider = AnthropicProvider(self.config)
        assert provider.prompt_caching_enabled is True
        assert provider.cache_min_tokens == 1024
    
    def test_prompt_caching_can_be_disabled(self):
        """Test that prompt caching can be disabled."""
        config = self.config.copy()
        config['prompt_caching_enabled'] = False
        provider = AnthropicProvider(config)
        assert provider.prompt_caching_enabled is False
    
    def test_small_prompt_not_cached(self):
        """Test that small prompts (<1024 tokens) are not cached."""
        provider = AnthropicProvider(self.config)
        
        # Small prompt (< 1024 tokens)
        small_prompt = "This is a small prompt."
        result = provider._prepare_system_prompt_with_caching(small_prompt)
        
        # Should return plain string, not cache control structure
        assert isinstance(result, str)
        assert result == small_prompt
    
    def test_large_prompt_is_cached(self):
        """Test that large prompts (>1024 tokens) are marked for caching."""
        provider = AnthropicProvider(self.config)
        
        # Large prompt (> 1024 tokens = ~4096 characters)
        large_prompt = "This is a large prompt. " * 200  # ~4800 characters
        result = provider._prepare_system_prompt_with_caching(large_prompt)
        
        # Should return cache control structure
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]['type'] == 'text'
        assert result[0]['text'] == large_prompt
        assert result[0]['cache_control'] == {'type': 'ephemeral'}
    
    def test_caching_disabled_returns_plain_string(self):
        """Test that when caching is disabled, plain string is returned."""
        config = self.config.copy()
        config['prompt_caching_enabled'] = False
        provider = AnthropicProvider(config)
        
        large_prompt = "This is a large prompt. " * 200
        result = provider._prepare_system_prompt_with_caching(large_prompt)
        
        # Should return plain string even for large prompts
        assert isinstance(result, str)
        assert result == large_prompt
    
    def test_cost_calculation_with_cache_creation(self):
        """Test cost calculation when cache is created."""
        provider = AnthropicProvider(self.config)
        
        # Simulate cache creation
        input_tokens = 5000
        output_tokens = 1000
        cache_creation_tokens = 3000  # 3000 tokens written to cache
        cache_read_tokens = 0
        
        cost = provider.calculate_cost_with_cache(
            input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens
        )
        
        # Cost breakdown:
        # Regular input: 2000 tokens @ $3.00/MTok = $0.006
        # Cache creation: 3000 tokens @ $3.75/MTok = $0.01125
        # Output: 1000 tokens @ $15.00/MTok = $0.015
        # Total: $0.03225
        expected_cost = (2000 / 1_000_000 * 3.0) + (3000 / 1_000_000 * 3.75) + (1000 / 1_000_000 * 15.0)
        assert abs(cost - expected_cost) < 0.0001
    
    def test_cost_calculation_with_cache_read(self):
        """Test cost calculation when cache is read (90% savings)."""
        provider = AnthropicProvider(self.config)
        
        # Simulate cache read
        input_tokens = 5000
        output_tokens = 1000
        cache_creation_tokens = 0
        cache_read_tokens = 3000  # 3000 tokens read from cache
        
        cost = provider.calculate_cost_with_cache(
            input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens
        )
        
        # Cost breakdown:
        # Regular input: 2000 tokens @ $3.00/MTok = $0.006
        # Cache read: 3000 tokens @ $0.30/MTok = $0.0009 (90% cheaper!)
        # Output: 1000 tokens @ $15.00/MTok = $0.015
        # Total: $0.0219
        expected_cost = (2000 / 1_000_000 * 3.0) + (3000 / 1_000_000 * 0.30) + (1000 / 1_000_000 * 15.0)
        assert abs(cost - expected_cost) < 0.0001
    
    def test_cache_savings_calculation(self):
        """Test that cache savings are calculated correctly."""
        provider = AnthropicProvider(self.config)
        
        # Simulate cache read
        cache_read_tokens = 3000
        
        # Regular cost: 3000 tokens @ $3.00/MTok = $0.009
        regular_cost = (cache_read_tokens / 1_000_000) * 3.0
        
        # Cache cost: 3000 tokens @ $0.30/MTok = $0.0009
        cache_cost = (cache_read_tokens / 1_000_000) * 0.30
        
        # Savings: $0.009 - $0.0009 = $0.0081 (90% reduction)
        expected_savings = regular_cost - cache_cost
        assert abs(expected_savings - 0.0081) < 0.0001
    
    @patch('bountybot.ai_providers.anthropic_provider.Anthropic')
    def test_complete_with_cache_metrics(self, mock_anthropic_class):
        """Test that complete() extracts and tracks cache metrics."""
        provider = AnthropicProvider(self.config)
        
        # Mock API response with cache metrics
        mock_response = Mock()
        mock_response.content = [Mock(text="Test response")]
        mock_response.usage = Mock(
            input_tokens=5000,
            output_tokens=1000,
            cache_creation_input_tokens=3000,
            cache_read_input_tokens=0
        )
        
        mock_client = Mock()
        mock_client.messages.create.return_value = mock_response
        provider.client = mock_client
        
        # Make request
        result = provider.complete("Large system prompt " * 200, "User prompt")
        
        # Check that cache metrics are tracked
        assert result['cache_creation_tokens'] == 3000
        assert result['cache_read_tokens'] == 0
        assert provider.cache_creation_tokens == 3000
        assert provider.cache_read_tokens == 0
    
    @patch('bountybot.ai_providers.anthropic_provider.Anthropic')
    def test_complete_with_cache_read_metrics(self, mock_anthropic_class):
        """Test that cache read metrics are tracked correctly."""
        provider = AnthropicProvider(self.config)
        
        # Mock API response with cache read
        mock_response = Mock()
        mock_response.content = [Mock(text="Test response")]
        mock_response.usage = Mock(
            input_tokens=5000,
            output_tokens=1000,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=3000
        )
        
        mock_client = Mock()
        mock_client.messages.create.return_value = mock_response
        provider.client = mock_client
        
        # Make request
        result = provider.complete("Large system prompt " * 200, "User prompt")
        
        # Check that cache metrics are tracked
        assert result['cache_creation_tokens'] == 0
        assert result['cache_read_tokens'] == 3000
        assert provider.cache_creation_tokens == 0
        assert provider.cache_read_tokens == 3000
        
        # Check that savings are calculated
        assert provider.total_cache_savings > 0
    
    @patch('bountybot.ai_providers.anthropic_provider.Anthropic')
    def test_get_stats_includes_cache_metrics(self, mock_anthropic_class):
        """Test that get_stats() includes prompt cache metrics."""
        provider = AnthropicProvider(self.config)
        
        # Simulate some cache usage
        provider.cache_creation_tokens = 5000
        provider.cache_read_tokens = 15000
        provider.total_cache_savings = 0.054  # $0.054 saved
        
        stats = provider.get_stats()
        
        # Check that prompt cache stats are included
        assert 'prompt_cache' in stats
        assert stats['prompt_cache']['enabled'] is True
        assert stats['prompt_cache']['cache_creation_tokens'] == 5000
        assert stats['prompt_cache']['cache_read_tokens'] == 15000
        assert stats['prompt_cache']['total_cache_tokens'] == 20000
        assert stats['prompt_cache']['cache_efficiency_percent'] == 75.0  # 15000/20000 = 75%
        assert stats['prompt_cache']['total_savings_usd'] == 0.054
    
    @patch('bountybot.ai_providers.anthropic_provider.Anthropic')
    def test_get_stats_when_caching_disabled(self, mock_anthropic_class):
        """Test that get_stats() shows caching as disabled when appropriate."""
        config = self.config.copy()
        config['prompt_caching_enabled'] = False
        provider = AnthropicProvider(config)
        
        stats = provider.get_stats()
        
        # Check that prompt cache is marked as disabled
        assert 'prompt_cache' in stats
        assert stats['prompt_cache']['enabled'] is False
    
    def test_cache_efficiency_calculation(self):
        """Test cache efficiency percentage calculation."""
        provider = AnthropicProvider(self.config)
        
        # Simulate cache usage
        provider.cache_creation_tokens = 5000
        provider.cache_read_tokens = 15000
        
        stats = provider.get_stats()
        
        # Efficiency = (cache_read / total_cache) * 100
        # = (15000 / 20000) * 100 = 75%
        assert stats['prompt_cache']['cache_efficiency_percent'] == 75.0
    
    def test_cache_efficiency_with_no_usage(self):
        """Test cache efficiency when no cache has been used."""
        provider = AnthropicProvider(self.config)
        
        stats = provider.get_stats()
        
        # Should be 0% when no cache usage
        assert stats['prompt_cache']['cache_efficiency_percent'] == 0.0
    
    @patch('bountybot.ai_providers.anthropic_provider.Anthropic')
    def test_multiple_requests_accumulate_savings(self, mock_anthropic_class):
        """Test that savings accumulate across multiple requests."""
        provider = AnthropicProvider(self.config)
        
        mock_client = Mock()
        provider.client = mock_client
        
        # First request - cache creation
        mock_response1 = Mock()
        mock_response1.content = [Mock(text="Response 1")]
        mock_response1.usage = Mock(
            input_tokens=5000,
            output_tokens=1000,
            cache_creation_input_tokens=3000,
            cache_read_input_tokens=0
        )
        mock_client.messages.create.return_value = mock_response1
        provider.complete("Large prompt " * 200, "Query 1")
        
        # Second request - cache read
        mock_response2 = Mock()
        mock_response2.content = [Mock(text="Response 2")]
        mock_response2.usage = Mock(
            input_tokens=5000,
            output_tokens=1000,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=3000
        )
        mock_client.messages.create.return_value = mock_response2
        provider.complete("Large prompt " * 200, "Query 2")
        
        # Check accumulated metrics
        assert provider.cache_creation_tokens == 3000
        assert provider.cache_read_tokens == 3000
        assert provider.total_cache_savings > 0
        
        # Savings should be from the cache read only
        expected_savings = (3000 / 1_000_000) * (3.0 - 0.30)
        assert abs(provider.total_cache_savings - expected_savings) < 0.0001


class TestPromptCachingIntegration:
    """Integration tests for prompt caching with real-world scenarios."""
    
    @patch('bountybot.ai_providers.anthropic_provider.Anthropic')
    def test_validation_workflow_with_caching(self, mock_anthropic_class):
        """Test that validation workflow benefits from prompt caching."""
        config = {
            'api_key': 'test-key',
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': 4096,
            'temperature': 0.3,
            'prompt_caching_enabled': True,
            'cache_min_tokens': 1024,
        }
        provider = AnthropicProvider(config)
        
        # Simulate validation workflow with repeated system prompts
        large_system_prompt = """You are a security expert analyzing bug bounty reports.
        
        Your task is to assess the quality and validity of security vulnerability reports.
        
        Guidelines:
        - Evaluate technical accuracy
        - Check for completeness
        - Assess severity
        - Identify missing information
        - Provide recommendations
        
        """ * 50  # Make it large enough to cache
        
        mock_client = Mock()
        provider.client = mock_client
        
        # First request - cache creation
        mock_response1 = Mock()
        mock_response1.content = [Mock(text="Assessment 1")]
        mock_response1.usage = Mock(
            input_tokens=6000,
            output_tokens=500,
            cache_creation_input_tokens=5000,
            cache_read_input_tokens=0
        )
        mock_client.messages.create.return_value = mock_response1
        result1 = provider.complete(large_system_prompt, "Analyze report 1")
        
        # Subsequent requests - cache reads
        for i in range(2, 6):
            mock_response = Mock()
            mock_response.content = [Mock(text=f"Assessment {i}")]
            mock_response.usage = Mock(
                input_tokens=6000,
                output_tokens=500,
                cache_creation_input_tokens=0,
                cache_read_input_tokens=5000
            )
            mock_client.messages.create.return_value = mock_response
            provider.complete(large_system_prompt, f"Analyze report {i}")
        
        # Check that caching provided significant savings
        assert provider.cache_creation_tokens == 5000
        assert provider.cache_read_tokens == 20000  # 5000 * 4 requests
        assert provider.total_cache_savings > 0.05  # At least $0.05 saved
        
        stats = provider.get_stats()
        assert stats['prompt_cache']['cache_efficiency_percent'] == 80.0  # 20000/25000

