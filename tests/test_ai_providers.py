import pytest
import os
from unittest.mock import Mock, patch, MagicMock

from bountybot.ai_providers import AnthropicProvider, OPENAI_AVAILABLE, GEMINI_AVAILABLE

if OPENAI_AVAILABLE:
    from bountybot.ai_providers import OpenAIProvider

if GEMINI_AVAILABLE:
    from bountybot.ai_providers import GeminiProvider


class TestAnthropicProvider:
    """Test Anthropic provider."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'api_key': 'test-key',
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': 4096,
            'temperature': 0.3,
            'rate_limit': {
                'requests_per_minute': 50,
                'tokens_per_minute': 100000
            }
        }
    
    def test_provider_initialization(self):
        """Test provider initialization."""
        provider = AnthropicProvider(self.config)
        assert provider.model == 'claude-sonnet-4-20250514'
        assert provider.max_tokens == 4096
        assert provider.temperature == 0.3
    
    def test_token_counting(self):
        """Test token counting."""
        provider = AnthropicProvider(self.config)
        text = "This is a test message"
        tokens = provider.count_tokens(text)
        assert tokens > 0
        assert isinstance(tokens, int)
    
    def test_cost_calculation(self):
        """Test cost calculation."""
        provider = AnthropicProvider(self.config)
        cost = provider.calculate_cost(1000, 500)
        assert cost > 0
        assert isinstance(cost, float)
    
    def test_cache_key_generation(self):
        """Test cache key generation."""
        provider = AnthropicProvider(self.config)
        key1 = provider._get_cache_key("system", "user", max_tokens=100)
        key2 = provider._get_cache_key("system", "user", max_tokens=100)
        key3 = provider._get_cache_key("system", "different", max_tokens=100)
        
        assert key1 == key2
        assert key1 != key3
    
    def test_stats_tracking(self):
        """Test statistics tracking."""
        provider = AnthropicProvider(self.config)
        stats = provider.get_stats()

        assert 'requests' in stats
        assert 'cost' in stats
        assert 'cache' in stats
        assert 'rate_limits' in stats  # Note: plural form


@pytest.mark.skipif(not OPENAI_AVAILABLE, reason="OpenAI package not installed")
class TestOpenAIProvider:
    """Test OpenAI provider."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'api_key': 'test-key',
            'model': 'gpt-4-turbo-preview',
            'max_tokens': 4096,
            'temperature': 0.3,
            'rate_limit': {
                'requests_per_minute': 500,
                'tokens_per_minute': 150000
            }
        }
    
    def test_provider_initialization(self):
        """Test provider initialization."""
        provider = OpenAIProvider(self.config)
        assert provider.model == 'gpt-4-turbo-preview'
        assert provider.max_tokens == 4096
        assert provider.temperature == 0.3
    
    def test_token_counting(self):
        """Test token counting."""
        provider = OpenAIProvider(self.config)
        text = "This is a test message"
        tokens = provider.count_tokens(text)
        assert tokens > 0
        assert isinstance(tokens, int)
    
    def test_cost_calculation(self):
        """Test cost calculation for different models."""
        provider = OpenAIProvider(self.config)
        
        # Test GPT-4 Turbo pricing
        cost = provider.calculate_cost(1000, 500)
        assert cost > 0
        assert isinstance(cost, float)
        
        # Test GPT-3.5 Turbo pricing
        provider.model = 'gpt-3.5-turbo'
        cost_35 = provider.calculate_cost(1000, 500)
        assert cost_35 < cost  # GPT-3.5 should be cheaper
    
    def test_json_mode_support(self):
        """Test JSON mode configuration."""
        provider = OpenAIProvider(self.config)
        
        # Mock the API call
        with patch.object(provider.client.chat.completions, 'create') as mock_create:
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = '{"test": "value"}'
            mock_response.choices[0].finish_reason = 'stop'
            mock_response.usage.prompt_tokens = 100
            mock_response.usage.completion_tokens = 50
            mock_create.return_value = mock_response
            
            result = provider.complete("system", "user", json_mode=True)
            assert 'content' in result
            assert result['input_tokens'] == 100
            assert result['output_tokens'] == 50


@pytest.mark.skipif(not GEMINI_AVAILABLE, reason="Gemini package not installed")
class TestGeminiProvider:
    """Test Gemini provider."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'api_key': 'test-key',
            'model': 'gemini-1.5-pro',
            'max_tokens': 8192,
            'temperature': 0.3,
            'rate_limit': {
                'requests_per_minute': 60,
                'tokens_per_minute': 100000
            }
        }
    
    def test_provider_initialization(self):
        """Test provider initialization."""
        provider = GeminiProvider(self.config)
        assert provider.model == 'gemini-1.5-pro'
        assert provider.max_tokens == 8192
        assert provider.temperature == 0.3
    
    def test_token_counting(self):
        """Test token counting."""
        provider = GeminiProvider(self.config)
        text = "This is a test message"
        tokens = provider.count_tokens(text)
        assert tokens > 0
        assert isinstance(tokens, int)
    
    def test_cost_calculation(self):
        """Test cost calculation for different models."""
        provider = GeminiProvider(self.config)
        
        # Test Gemini 1.5 Pro pricing
        cost = provider.calculate_cost(1000, 500)
        assert cost > 0
        assert isinstance(cost, float)
        
        # Test Gemini 1.5 Flash pricing
        provider.model = 'gemini-1.5-flash'
        cost_flash = provider.calculate_cost(1000, 500)
        assert cost_flash < cost  # Flash should be cheaper


class TestProviderSelection:
    """Test provider selection and configuration."""
    
    def test_anthropic_provider_selection(self):
        """Test selecting Anthropic provider."""
        config = {
            'api': {
                'default_provider': 'anthropic',
                'providers': {
                    'anthropic': {
                        'api_key': 'test-key',
                        'model': 'claude-sonnet-4-20250514',
                        'max_tokens': 4096,
                        'temperature': 0.3
                    }
                }
            }
        }
        
        provider_name = config['api']['default_provider']
        assert provider_name == 'anthropic'
    
    @pytest.mark.skipif(not OPENAI_AVAILABLE, reason="OpenAI package not installed")
    def test_openai_provider_selection(self):
        """Test selecting OpenAI provider."""
        config = {
            'api': {
                'default_provider': 'openai',
                'providers': {
                    'openai': {
                        'api_key': 'test-key',
                        'model': 'gpt-4-turbo-preview',
                        'max_tokens': 4096,
                        'temperature': 0.3
                    }
                }
            }
        }
        
        provider_name = config['api']['default_provider']
        assert provider_name == 'openai'
    
    @pytest.mark.skipif(not GEMINI_AVAILABLE, reason="Gemini package not installed")
    def test_gemini_provider_selection(self):
        """Test selecting Gemini provider."""
        config = {
            'api': {
                'default_provider': 'gemini',
                'providers': {
                    'gemini': {
                        'api_key': 'test-key',
                        'model': 'gemini-1.5-pro',
                        'max_tokens': 8192,
                        'temperature': 0.3
                    }
                }
            }
        }
        
        provider_name = config['api']['default_provider']
        assert provider_name == 'gemini'


class TestProviderFeatures:
    """Test common provider features."""
    
    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        config = {
            'api_key': 'test-key',
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': 4096,
            'temperature': 0.3,
            'rate_limit': {
                'requests_per_minute': 1,  # Very low limit for testing
                'tokens_per_minute': 1000
            }
        }
        
        provider = AnthropicProvider(config)
        
        # Rate limiting should not raise errors, just slow down
        provider._check_rate_limits(100)
        provider._check_rate_limits(100)
    
    def test_caching(self):
        """Test response caching."""
        config = {
            'api_key': 'test-key',
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': 4096,
            'temperature': 0.3
        }

        provider = AnthropicProvider(config)

        # Cache a result
        cache_key = provider._get_cache_key("system", "user")
        result = {
            'content': 'test response',
            'input_tokens': 100,
            'output_tokens': 50,
            'cost': 0.001
        }
        provider._store_cache(cache_key, result)

        # Retrieve from cache
        cached = provider._check_cache(cache_key)
        assert cached is not None
        assert cached['content'] == 'test response'

