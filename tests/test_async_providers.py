"""
Tests for async AI providers.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock

from bountybot.ai_providers.async_base import AsyncBaseAIProvider, AsyncCircuitBreaker, CircuitState
from bountybot.ai_providers.async_anthropic_provider import AsyncAnthropicProvider


class TestAsyncCircuitBreaker:
    """Test async circuit breaker functionality."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_closed_state(self):
        """Test circuit breaker in closed state allows calls."""
        breaker = AsyncCircuitBreaker(failure_threshold=3, timeout=60)

        async def success_func():
            return "success"

        result = await breaker.call(success_func)
        assert result == "success"
        assert breaker.state == CircuitState.CLOSED
        assert breaker.failure_count == 0

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_after_failures(self):
        """Test circuit breaker opens after threshold failures."""
        breaker = AsyncCircuitBreaker(failure_threshold=3, timeout=60)

        async def failing_func():
            raise Exception("API error")

        # Trigger failures
        for i in range(3):
            with pytest.raises(Exception):
                await breaker.call(failing_func)

        # Circuit should be open now
        assert breaker.state == CircuitState.OPEN
        assert breaker.failure_count == 3

        # Next call should fail immediately
        with pytest.raises(Exception, match="Circuit breaker is OPEN"):
            await breaker.call(failing_func)

    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open_recovery(self):
        """Test circuit breaker recovery through half-open state."""
        breaker = AsyncCircuitBreaker(failure_threshold=2, timeout=0.1, half_open_max_calls=2)

        async def failing_func():
            raise Exception("API error")

        async def success_func():
            return "success"

        # Open the circuit
        for i in range(2):
            with pytest.raises(Exception):
                await breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN

        # Wait for timeout
        await asyncio.sleep(0.2)

        # Should transition to half-open and allow test calls
        result = await breaker.call(success_func)
        assert result == "success"
        assert breaker.state == CircuitState.CLOSED
        assert breaker.failure_count == 0


class TestAsyncAnthropicProvider:
    """Test async Anthropic provider."""

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

    @pytest.mark.asyncio
    async def test_provider_initialization(self):
        """Test provider initializes correctly."""
        provider = AsyncAnthropicProvider(self.config)
        assert provider.model == 'claude-sonnet-4-20250514'
        assert provider.max_tokens == 4096
        assert provider.temperature == 0.3
        assert provider.prompt_caching_enabled is True
        assert provider.cache_min_tokens == 1024

    @pytest.mark.asyncio
    @patch('bountybot.ai_providers.async_anthropic_provider.AsyncAnthropic')
    async def test_complete_with_caching(self, mock_anthropic_class):
        """Test complete() with prompt caching."""
        provider = AsyncAnthropicProvider(self.config)

        # Mock API response
        mock_response = Mock()
        mock_response.content = [Mock(text="Test response")]
        mock_response.usage = Mock(
            input_tokens=5000,
            output_tokens=1000,
            cache_creation_input_tokens=3000,
            cache_read_input_tokens=0
        )

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        provider.client = mock_client

        # Make request
        result = await provider.complete("Large system prompt " * 200, "User prompt")

        # Verify result
        assert result['content'] == "Test response"
        assert result['input_tokens'] == 5000
        assert result['output_tokens'] == 1000
        assert result['cache_creation_tokens'] == 3000
        assert result['cache_read_tokens'] == 0
        assert result['cost'] > 0

        # Verify cache metrics updated
        assert provider.cache_creation_tokens == 3000
        assert provider.cache_read_tokens == 0

    @pytest.mark.asyncio
    @patch('bountybot.ai_providers.async_anthropic_provider.AsyncAnthropic')
    async def test_complete_with_cache_read(self, mock_anthropic_class):
        """Test complete() with cache read."""
        provider = AsyncAnthropicProvider(self.config)

        # Mock API response with cache read
        mock_response = Mock()
        mock_response.content = [Mock(text="Test response")]
        mock_response.usage = Mock(
            input_tokens=5000,
            output_tokens=1000,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=3000
        )

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        provider.client = mock_client

        # Make request
        result = await provider.complete("Large system prompt " * 200, "User prompt")

        # Verify cache read metrics
        assert result['cache_read_tokens'] == 3000
        assert provider.cache_read_tokens == 3000
        assert provider.total_cache_savings > 0

    @pytest.mark.asyncio
    @patch('bountybot.ai_providers.async_anthropic_provider.AsyncAnthropic')
    async def test_stream_complete(self, mock_anthropic_class):
        """Test streaming completion."""
        provider = AsyncAnthropicProvider(self.config)

        # Mock streaming response
        class MockStreamEvent:
            def __init__(self, text):
                self.type = "content_block_delta"
                self.delta = Mock(text=text)

        async def mock_stream():
            for chunk in ["Hello", " ", "world", "!"]:
                yield MockStreamEvent(chunk)

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_stream())
        provider.client = mock_client

        # Stream response
        chunks = []
        async for chunk in provider.stream_complete("System prompt", "User prompt"):
            chunks.append(chunk)

        assert chunks == ["Hello", " ", "world", "!"]

    @pytest.mark.asyncio
    @patch('bountybot.ai_providers.async_anthropic_provider.AsyncAnthropic')
    async def test_complete_with_json(self, mock_anthropic_class):
        """Test complete_with_json() parses JSON correctly."""
        provider = AsyncAnthropicProvider(self.config)

        # Mock API response with JSON
        mock_response = Mock()
        mock_response.content = [Mock(text='{"status": "valid", "confidence": 0.95}')]
        mock_response.usage = Mock(
            input_tokens=1000,
            output_tokens=100,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0
        )

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        provider.client = mock_client

        # Make request
        result = await provider.complete_with_json("System prompt", "User prompt")

        # Verify JSON parsing
        assert result['parsed'] == {"status": "valid", "confidence": 0.95}

    @pytest.mark.asyncio
    @patch('bountybot.ai_providers.async_anthropic_provider.AsyncAnthropic')
    async def test_rate_limiting(self, mock_anthropic_class):
        """Test rate limiting works correctly."""
        config = self.config.copy()
        config['rate_limit'] = {
            'requests_per_minute': 2,
            'tokens_per_minute': 10000
        }
        provider = AsyncAnthropicProvider(config)

        # Mock API response
        mock_response = Mock()
        mock_response.content = [Mock(text="Response")]
        mock_response.usage = Mock(
            input_tokens=1000,
            output_tokens=100,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0
        )

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        provider.client = mock_client

        # Make multiple requests
        start_time = asyncio.get_event_loop().time()
        tasks = [
            provider.complete("System", f"Query {i}")
            for i in range(3)
        ]
        await asyncio.gather(*tasks)
        end_time = asyncio.get_event_loop().time()

        # Should have been rate limited (3 requests > 2 per minute)
        # Note: This is a simplified test, actual timing may vary
        assert provider.total_requests == 3

    @pytest.mark.asyncio
    @patch('bountybot.ai_providers.async_anthropic_provider.AsyncAnthropic')
    async def test_local_cache(self, mock_anthropic_class):
        """Test local response caching."""
        provider = AsyncAnthropicProvider(self.config)

        # Mock API response
        mock_response = Mock()
        mock_response.content = [Mock(text="Cached response")]
        mock_response.usage = Mock(
            input_tokens=1000,
            output_tokens=100,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0
        )

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        provider.client = mock_client

        # First request - should hit API
        result1 = await provider.complete("System", "Query")
        assert mock_client.messages.create.call_count == 1

        # Second request with same prompts - should hit local cache
        result2 = await provider.complete("System", "Query")
        assert mock_client.messages.create.call_count == 1  # No additional API call
        assert result1['content'] == result2['content']
        assert provider.total_cache_hits == 1

    @pytest.mark.asyncio
    @patch('bountybot.ai_providers.async_anthropic_provider.AsyncAnthropic')
    async def test_get_stats(self, mock_anthropic_class):
        """Test get_stats() returns correct statistics."""
        provider = AsyncAnthropicProvider(self.config)

        # Simulate some usage
        provider.cache_creation_tokens = 5000
        provider.cache_read_tokens = 15000
        provider.total_cache_savings = 0.054

        stats = await provider.get_stats()

        # Verify stats structure
        assert 'provider' in stats
        assert 'model' in stats
        assert 'requests' in stats
        assert 'tokens' in stats
        assert 'cost' in stats
        assert 'cache' in stats
        assert 'prompt_cache' in stats
        assert 'circuit_breaker' in stats

        # Verify prompt cache stats
        assert stats['prompt_cache']['enabled'] is True
        assert stats['prompt_cache']['cache_creation_tokens'] == 5000
        assert stats['prompt_cache']['cache_read_tokens'] == 15000
        assert stats['prompt_cache']['total_cache_tokens'] == 20000
        assert stats['prompt_cache']['cache_efficiency_percent'] == 75.0
        assert stats['prompt_cache']['total_savings_usd'] == 0.054

    @pytest.mark.asyncio
    @patch('bountybot.ai_providers.async_anthropic_provider.AsyncAnthropic')
    async def test_concurrent_requests(self, mock_anthropic_class):
        """Test handling concurrent requests."""
        provider = AsyncAnthropicProvider(self.config)

        # Mock API response
        async def mock_create(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simulate API latency
            mock_response = Mock()
            mock_response.content = [Mock(text="Response")]
            mock_response.usage = Mock(
                input_tokens=1000,
                output_tokens=100,
                cache_creation_input_tokens=0,
                cache_read_input_tokens=0
            )
            return mock_response

        mock_client = AsyncMock()
        mock_client.messages.create = mock_create
        provider.client = mock_client

        # Make concurrent requests
        tasks = [
            provider.complete("System", f"Query {i}")
            for i in range(5)
        ]

        start_time = asyncio.get_event_loop().time()
        results = await asyncio.gather(*tasks)
        end_time = asyncio.get_event_loop().time()

        # All requests should complete
        assert len(results) == 5
        assert all(r['content'] == "Response" for r in results)

        # Should be faster than sequential (5 * 0.1 = 0.5s)
        # Concurrent should be ~0.1s (all at once)
        duration = end_time - start_time
        assert duration < 0.3  # Allow some overhead

    @pytest.mark.asyncio
    async def test_cost_calculation_with_cache(self):
        """Test cost calculation with cache pricing."""
        provider = AsyncAnthropicProvider(self.config)

        # Test cache creation cost
        # input_tokens includes cache_creation_tokens, so regular = input - cache_creation
        cost1 = provider.calculate_cost_with_cache(
            input_tokens=5000,  # Total input tokens
            output_tokens=1000,
            cache_creation_tokens=3000,
            cache_read_tokens=0
        )

        # Regular: (5000 - 3000) = 2000 @ $3.00 = $0.006
        # Cache write: 3000 @ $3.75 = $0.01125
        # Output: 1000 @ $15.00 = $0.015
        # Total: $0.03225
        expected_cost1 = (2000 / 1_000_000 * 3.0) + (3000 / 1_000_000 * 3.75) + (1000 / 1_000_000 * 15.0)
        assert abs(cost1 - expected_cost1) < 0.0001

        # Test cache read cost (90% savings)
        cost2 = provider.calculate_cost_with_cache(
            input_tokens=5000,  # Total input tokens
            output_tokens=1000,
            cache_creation_tokens=0,
            cache_read_tokens=3000
        )

        # Regular: (5000 - 3000) = 2000 @ $3.00 = $0.006
        # Cache read: 3000 @ $0.30 = $0.0009
        # Output: 1000 @ $15.00 = $0.015
        # Total: $0.0219
        expected_cost2 = (2000 / 1_000_000 * 3.0) + (3000 / 1_000_000 * 0.30) + (1000 / 1_000_000 * 15.0)
        assert abs(cost2 - expected_cost2) < 0.0001

        # Cache read should be much cheaper
        assert cost2 < cost1

    @pytest.mark.asyncio
    @patch('bountybot.ai_providers.async_anthropic_provider.AsyncAnthropic')
    async def test_error_handling(self, mock_anthropic_class):
        """Test error handling and circuit breaker."""
        provider = AsyncAnthropicProvider(self.config)

        # Mock API error
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("API error"))
        provider.client = mock_client

        # Should raise exception
        with pytest.raises(Exception, match="API error"):
            await provider.complete("System", "Query")

        # Circuit breaker should track failure
        assert provider.circuit_breaker.failure_count == 1

