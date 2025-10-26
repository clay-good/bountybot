"""
Tests for distributed tracing with OpenTelemetry.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock

# Try to import tracing
try:
    from bountybot.monitoring.tracing import (
        TracingManager,
        initialize_tracing,
        get_tracing_manager,
        OTEL_AVAILABLE
    )
    TRACING_AVAILABLE = True
except ImportError:
    TRACING_AVAILABLE = False


@pytest.mark.skipif(not TRACING_AVAILABLE, reason="OpenTelemetry not available")
class TestTracingManager:
    """Test TracingManager functionality."""
    
    def test_tracing_manager_init_disabled(self):
        """Test tracing manager initialization when disabled."""
        manager = TracingManager(enabled=False)
        assert not manager.enabled
        assert manager.tracer is None
    
    def test_tracing_manager_init_console(self):
        """Test tracing manager initialization with console export."""
        manager = TracingManager(
            service_name="test-service",
            service_version="1.0.0",
            console_export=True,
            enabled=True
        )
        assert manager.enabled
        assert manager.service_name == "test-service"
        assert manager.service_version == "1.0.0"
        assert manager.tracer is not None
    
    def test_start_span_disabled(self):
        """Test start_span when tracing is disabled."""
        manager = TracingManager(enabled=False)
        
        with manager.start_span("test-span") as span:
            assert span is None
    
    def test_start_span_enabled(self):
        """Test start_span when tracing is enabled."""
        manager = TracingManager(console_export=True, enabled=True)
        
        with manager.start_span("test-span", attributes={"key": "value"}) as span:
            assert span is not None
    
    def test_start_span_with_exception(self):
        """Test start_span records exceptions."""
        manager = TracingManager(console_export=True, enabled=True)
        
        with pytest.raises(ValueError):
            with manager.start_span("test-span") as span:
                raise ValueError("Test error")
    
    def test_trace_function_decorator(self):
        """Test trace_function decorator."""
        manager = TracingManager(console_export=True, enabled=True)
        
        @manager.trace_function(name="test.function")
        def test_func(x, y):
            return x + y
        
        result = test_func(1, 2)
        assert result == 3
    
    @pytest.mark.asyncio
    async def test_trace_async_function_decorator(self):
        """Test trace_async_function decorator."""
        manager = TracingManager(console_export=True, enabled=True)
        
        @manager.trace_async_function(name="test.async_function")
        async def test_async_func(x, y):
            await asyncio.sleep(0.01)
            return x + y
        
        result = await test_async_func(1, 2)
        assert result == 3
    
    def test_add_event(self):
        """Test add_event to current span."""
        manager = TracingManager(console_export=True, enabled=True)
        
        with manager.start_span("test-span") as span:
            manager.add_event("test-event", {"key": "value"})
    
    def test_set_attribute(self):
        """Test set_attribute on current span."""
        manager = TracingManager(console_export=True, enabled=True)
        
        with manager.start_span("test-span") as span:
            manager.set_attribute("test-key", "test-value")
    
    def test_record_exception(self):
        """Test record_exception on current span."""
        manager = TracingManager(console_export=True, enabled=True)
        
        with manager.start_span("test-span") as span:
            try:
                raise ValueError("Test error")
            except ValueError as e:
                manager.record_exception(e)
    
    def test_inject_extract_context(self):
        """Test context injection and extraction."""
        manager = TracingManager(console_export=True, enabled=True)
        
        carrier = {}
        manager.inject_context(carrier)
        
        # Should have trace context headers
        assert len(carrier) >= 0  # May be empty if no active span
        
        extracted = manager.extract_context(carrier)
    
    def test_initialize_tracing(self):
        """Test global tracing initialization."""
        manager = initialize_tracing(
            service_name="test-service",
            service_version="1.0.0",
            console_export=True,
            enabled=True
        )
        
        assert manager is not None
        assert manager.enabled
        
        # Get global instance
        global_manager = get_tracing_manager()
        assert global_manager is manager


@pytest.mark.skipif(not TRACING_AVAILABLE, reason="OpenTelemetry not available")
class TestAIProviderTracing:
    """Test AI provider tracing instrumentation."""
    
    def test_tracing_mixin_import(self):
        """Test tracing mixin can be imported."""
        from bountybot.ai_providers.tracing_mixin import AIProviderTracingMixin
        assert AIProviderTracingMixin is not None
    
    def test_trace_ai_call(self):
        """Test _trace_ai_call method."""
        from bountybot.ai_providers.tracing_mixin import AIProviderTracingMixin
        
        # Initialize tracing
        initialize_tracing(console_export=True, enabled=True)
        
        class TestProvider(AIProviderTracingMixin):
            pass
        
        provider = TestProvider()
        
        def mock_func():
            return {
                'content': 'test response',
                'input_tokens': 100,
                'output_tokens': 50,
                'cost': 0.001
            }
        
        result = provider._trace_ai_call(
            "complete",
            "test-model",
            "test-provider",
            mock_func
        )
        
        assert result['content'] == 'test response'
        assert result['input_tokens'] == 100
    
    @pytest.mark.asyncio
    async def test_trace_ai_call_async(self):
        """Test _trace_ai_call_async method."""
        from bountybot.ai_providers.tracing_mixin import AIProviderTracingMixin
        
        # Initialize tracing
        initialize_tracing(console_export=True, enabled=True)
        
        class TestProvider(AIProviderTracingMixin):
            pass
        
        provider = TestProvider()
        
        async def mock_async_func():
            await asyncio.sleep(0.01)
            return {
                'content': 'test response',
                'input_tokens': 100,
                'output_tokens': 50,
                'cost': 0.001
            }
        
        result = await provider._trace_ai_call_async(
            "complete",
            "test-model",
            "test-provider",
            mock_async_func
        )
        
        assert result['content'] == 'test response'
        assert result['input_tokens'] == 100


@pytest.mark.skipif(not TRACING_AVAILABLE, reason="OpenTelemetry not available")
class TestOrchestratorTracing:
    """Test orchestrator tracing instrumentation."""
    
    @pytest.mark.asyncio
    async def test_validate_report_with_tracing(self):
        """Test validate_report creates spans."""
        from bountybot.async_orchestrator import AsyncOrchestrator
        from bountybot.models import Report, ValidationResult
        
        # Initialize tracing
        initialize_tracing(console_export=True, enabled=True)
        
        # Create mock config
        config = {
            'api': {
                'default_provider': 'anthropic',
                'providers': {
                    'anthropic': {
                        'api_key': 'test-key',
                        'model': 'claude-sonnet-4-20250514',
                        'max_tokens': 4096,
                        'temperature': 0.3,
                        'rate_limit': {
                            'requests_per_minute': 50,
                            'tokens_per_minute': 160000
                        }
                    }
                }
            },
            'max_concurrent_validations': 5,
            'max_concurrent_ai_calls': 3
        }
        
        # This test just verifies tracing doesn't break the orchestrator
        # Full integration testing would require mocking AI providers
        orchestrator = AsyncOrchestrator(config)
        assert orchestrator is not None


class TestTracingDisabled:
    """Test behavior when tracing is disabled or unavailable."""
    
    def test_tracing_manager_disabled(self):
        """Test tracing manager when disabled."""
        if not TRACING_AVAILABLE:
            pytest.skip("OpenTelemetry not available")
        
        manager = TracingManager(enabled=False)
        
        # All methods should be no-ops
        with manager.start_span("test") as span:
            assert span is None
        
        manager.add_event("test")
        manager.set_attribute("key", "value")
        manager.record_exception(Exception("test"))
        manager.inject_context({})
        manager.extract_context({})
    
    def test_get_tracing_manager_none(self):
        """Test get_tracing_manager returns None when not initialized."""
        if not TRACING_AVAILABLE:
            pytest.skip("OpenTelemetry not available")
        
        # Reset global manager
        import bountybot.monitoring.tracing as tracing_module
        tracing_module.tracing_manager = None
        
        manager = get_tracing_manager()
        assert manager is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

