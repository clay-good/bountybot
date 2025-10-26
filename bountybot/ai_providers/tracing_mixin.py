"""
Tracing mixin for AI providers.

Adds distributed tracing instrumentation to AI provider calls.
"""

import logging
import time
from typing import Dict, Any, Optional
from functools import wraps

logger = logging.getLogger(__name__)


class AIProviderTracingMixin:
    """
    Mixin class that adds tracing to AI provider methods.
    
    Tracks:
    - AI API call duration
    - Token usage (input, output, cache)
    - Cost per request
    - Model and provider information
    - Success/failure status
    - Error details
    """
    
    def _trace_ai_call(
        self,
        operation: str,
        model: str,
        provider: str,
        func,
        *args,
        **kwargs
    ):
        """
        Trace an AI provider call.
        
        Args:
            operation: Operation name (complete, stream, json)
            model: Model name
            provider: Provider name
            func: Function to call
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result with tracing
        """
        # Try to get tracing manager
        try:
            from bountybot.monitoring.tracing import get_tracing_manager
            tracing_manager = get_tracing_manager()
        except ImportError:
            tracing_manager = None
        
        if not tracing_manager or not tracing_manager.enabled:
            # No tracing - just call function
            return func(*args, **kwargs)
        
        # Start span
        span_name = f"ai.{provider}.{operation}"
        attributes = {
            "ai.provider": provider,
            "ai.model": model,
            "ai.operation": operation,
        }
        
        start_time = time.time()
        
        with tracing_manager.start_span(span_name, attributes=attributes) as span:
            try:
                # Call function
                result = func(*args, **kwargs)
                
                # Extract metrics from result
                duration = time.time() - start_time
                
                if isinstance(result, dict):
                    # Add token metrics
                    if 'input_tokens' in result:
                        span.set_attribute("ai.tokens.input", result['input_tokens'])
                    if 'output_tokens' in result:
                        span.set_attribute("ai.tokens.output", result['output_tokens'])
                    if 'cache_creation_tokens' in result:
                        span.set_attribute("ai.tokens.cache_creation", result['cache_creation_tokens'])
                    if 'cache_read_tokens' in result:
                        span.set_attribute("ai.tokens.cache_read", result['cache_read_tokens'])
                    
                    # Add cost
                    if 'cost' in result:
                        span.set_attribute("ai.cost", result['cost'])
                    
                    # Add content length
                    if 'content' in result:
                        span.set_attribute("ai.response.length", len(result['content']))
                
                # Add duration
                span.set_attribute("ai.duration_ms", duration * 1000)
                
                # Add success event
                span.add_event("ai.call.success", {
                    "duration_ms": duration * 1000
                })
                
                return result
                
            except Exception as e:
                # Record error
                duration = time.time() - start_time
                span.set_attribute("ai.duration_ms", duration * 1000)
                span.set_attribute("ai.error", str(e))
                span.add_event("ai.call.error", {
                    "error": str(e),
                    "duration_ms": duration * 1000
                })
                raise
    
    async def _trace_ai_call_async(
        self,
        operation: str,
        model: str,
        provider: str,
        func,
        *args,
        **kwargs
    ):
        """
        Trace an async AI provider call.
        
        Args:
            operation: Operation name (complete, stream, json)
            model: Model name
            provider: Provider name
            func: Async function to call
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result with tracing
        """
        # Try to get tracing manager
        try:
            from bountybot.monitoring.tracing import get_tracing_manager
            tracing_manager = get_tracing_manager()
        except ImportError:
            tracing_manager = None
        
        if not tracing_manager or not tracing_manager.enabled:
            # No tracing - just call function
            return await func(*args, **kwargs)
        
        # Start span
        span_name = f"ai.{provider}.{operation}"
        attributes = {
            "ai.provider": provider,
            "ai.model": model,
            "ai.operation": operation,
        }
        
        start_time = time.time()
        
        with tracing_manager.start_span(span_name, attributes=attributes) as span:
            try:
                # Call async function
                result = await func(*args, **kwargs)
                
                # Extract metrics from result
                duration = time.time() - start_time
                
                if isinstance(result, dict):
                    # Add token metrics
                    if 'input_tokens' in result:
                        span.set_attribute("ai.tokens.input", result['input_tokens'])
                    if 'output_tokens' in result:
                        span.set_attribute("ai.tokens.output", result['output_tokens'])
                    if 'cache_creation_tokens' in result:
                        span.set_attribute("ai.tokens.cache_creation", result['cache_creation_tokens'])
                    if 'cache_read_tokens' in result:
                        span.set_attribute("ai.tokens.cache_read", result['cache_read_tokens'])
                    
                    # Add cost
                    if 'cost' in result:
                        span.set_attribute("ai.cost", result['cost'])
                    
                    # Add content length
                    if 'content' in result:
                        span.set_attribute("ai.response.length", len(result['content']))
                
                # Add duration
                span.set_attribute("ai.duration_ms", duration * 1000)
                
                # Add success event
                span.add_event("ai.call.success", {
                    "duration_ms": duration * 1000
                })
                
                return result
                
            except Exception as e:
                # Record error
                duration = time.time() - start_time
                span.set_attribute("ai.duration_ms", duration * 1000)
                span.set_attribute("ai.error", str(e))
                span.add_event("ai.call.error", {
                    "error": str(e),
                    "duration_ms": duration * 1000
                })
                raise


def trace_ai_complete(provider: str, model: str):
    """
    Decorator to trace AI complete() calls.
    
    Args:
        provider: Provider name
        model: Model name
        
    Returns:
        Decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if hasattr(self, '_trace_ai_call'):
                return self._trace_ai_call(
                    "complete",
                    model,
                    provider,
                    lambda: func(self, *args, **kwargs)
                )
            else:
                return func(self, *args, **kwargs)
        return wrapper
    return decorator


def trace_ai_complete_async(provider: str, model: str):
    """
    Decorator to trace async AI complete() calls.
    
    Args:
        provider: Provider name
        model: Model name
        
    Returns:
        Decorated async function
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            if hasattr(self, '_trace_ai_call_async'):
                return await self._trace_ai_call_async(
                    "complete",
                    model,
                    provider,
                    lambda: func(self, *args, **kwargs)
                )
            else:
                return await func(self, *args, **kwargs)
        return wrapper
    return decorator


def trace_ai_stream(provider: str, model: str):
    """
    Decorator to trace AI stream_complete() calls.
    
    Args:
        provider: Provider name
        model: Model name
        
    Returns:
        Decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Try to get tracing manager
            try:
                from bountybot.monitoring.tracing import get_tracing_manager
                tracing_manager = get_tracing_manager()
            except ImportError:
                tracing_manager = None
            
            if not tracing_manager or not tracing_manager.enabled:
                return func(self, *args, **kwargs)
            
            # Start span for streaming
            span_name = f"ai.{provider}.stream"
            attributes = {
                "ai.provider": provider,
                "ai.model": model,
                "ai.operation": "stream",
            }
            
            with tracing_manager.start_span(span_name, attributes=attributes) as span:
                start_time = time.time()
                chunk_count = 0
                total_length = 0
                
                try:
                    # Stream chunks
                    for chunk in func(self, *args, **kwargs):
                        chunk_count += 1
                        total_length += len(chunk) if isinstance(chunk, str) else 0
                        yield chunk
                    
                    # Add metrics
                    duration = time.time() - start_time
                    span.set_attribute("ai.duration_ms", duration * 1000)
                    span.set_attribute("ai.stream.chunks", chunk_count)
                    span.set_attribute("ai.stream.total_length", total_length)
                    span.add_event("ai.stream.complete", {
                        "chunks": chunk_count,
                        "total_length": total_length,
                        "duration_ms": duration * 1000
                    })
                    
                except Exception as e:
                    duration = time.time() - start_time
                    span.set_attribute("ai.duration_ms", duration * 1000)
                    span.set_attribute("ai.error", str(e))
                    span.add_event("ai.stream.error", {
                        "error": str(e),
                        "chunks_before_error": chunk_count
                    })
                    raise
        
        return wrapper
    return decorator

