"""
OpenTelemetry distributed tracing for BountyBot.

Provides comprehensive request tracing across all components:
- HTTP requests and responses
- AI provider API calls
- Database queries
- Validation pipeline stages
- Code analysis operations
- Dynamic scanning
- Async operations

Exports traces to Jaeger, Zipkin, or OTLP collectors.
"""

import logging
import time
from typing import Dict, Any, Optional, Callable
from functools import wraps
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Try to import OpenTelemetry
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
    from opentelemetry.trace import Status, StatusCode, SpanKind
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

    OTEL_AVAILABLE = True
except ImportError:
    logger.warning("OpenTelemetry not available - install opentelemetry-api, opentelemetry-sdk")
    OTEL_AVAILABLE = False
    trace = None
    TracerProvider = None
    SpanKind = None

# Try to import exporters (optional)
try:
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    JAEGER_AVAILABLE = True
except ImportError:
    JAEGER_AVAILABLE = False
    JaegerExporter = None

try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    OTLP_AVAILABLE = True
except ImportError:
    OTLP_AVAILABLE = False
    OTLPSpanExporter = None

# Try to import instrumentation (optional)
try:
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    REQUESTS_INSTRUMENTATION_AVAILABLE = True
except ImportError:
    REQUESTS_INSTRUMENTATION_AVAILABLE = False
    RequestsInstrumentor = None

try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    FASTAPI_INSTRUMENTATION_AVAILABLE = True
except ImportError:
    FASTAPI_INSTRUMENTATION_AVAILABLE = False
    FastAPIInstrumentor = None


class TracingManager:
    """
    Manages distributed tracing with OpenTelemetry.
    
    Features:
    - Automatic instrumentation for HTTP, FastAPI
    - Custom spans for AI providers, validation, code analysis
    - Trace context propagation
    - Multiple exporter support (Jaeger, OTLP, Console)
    - Span attributes for debugging
    - Error tracking
    """
    
    def __init__(
        self,
        service_name: str = "bountybot",
        service_version: str = "2.7.0",
        jaeger_endpoint: Optional[str] = None,
        otlp_endpoint: Optional[str] = None,
        console_export: bool = False,
        enabled: bool = True
    ):
        """
        Initialize tracing manager.
        
        Args:
            service_name: Service name for traces
            service_version: Service version
            jaeger_endpoint: Jaeger collector endpoint (e.g., "localhost:6831")
            otlp_endpoint: OTLP collector endpoint (e.g., "localhost:4317")
            console_export: Export traces to console for debugging
            enabled: Enable/disable tracing
        """
        self.service_name = service_name
        self.service_version = service_version
        self.enabled = enabled and OTEL_AVAILABLE
        self.tracer = None
        self.propagator = None
        
        if not self.enabled:
            if not OTEL_AVAILABLE:
                logger.warning("Tracing disabled - OpenTelemetry not available")
            else:
                logger.info("Tracing disabled by configuration")
            return
        
        # Create resource
        resource = Resource(attributes={
            SERVICE_NAME: service_name,
            SERVICE_VERSION: service_version,
            "deployment.environment": "production"
        })
        
        # Create tracer provider
        provider = TracerProvider(resource=resource)
        
        # Add exporters
        if jaeger_endpoint:
            if not JAEGER_AVAILABLE:
                logger.warning("Jaeger exporter requested but not available - install opentelemetry-exporter-jaeger")
            else:
                jaeger_exporter = JaegerExporter(
                    agent_host_name=jaeger_endpoint.split(':')[0],
                    agent_port=int(jaeger_endpoint.split(':')[1]) if ':' in jaeger_endpoint else 6831,
                )
                provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))
                logger.info(f"Jaeger exporter configured: {jaeger_endpoint}")

        if otlp_endpoint:
            if not OTLP_AVAILABLE:
                logger.warning("OTLP exporter requested but not available - install opentelemetry-exporter-otlp")
            else:
                otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
                provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
                logger.info(f"OTLP exporter configured: {otlp_endpoint}")
        
        if console_export:
            console_exporter = ConsoleSpanExporter()
            provider.add_span_processor(BatchSpanProcessor(console_exporter))
            logger.info("Console exporter configured")
        
        # Set global tracer provider
        trace.set_tracer_provider(provider)
        
        # Get tracer
        self.tracer = trace.get_tracer(__name__)
        
        # Create propagator for context propagation
        self.propagator = TraceContextTextMapPropagator()
        
        # Instrument libraries
        self._instrument_libraries()
        
        logger.info(f"Distributed tracing initialized for {service_name}")
    
    def _instrument_libraries(self):
        """Automatically instrument common libraries."""
        if REQUESTS_INSTRUMENTATION_AVAILABLE:
            try:
                # Instrument requests library
                RequestsInstrumentor().instrument()
                logger.info("Requests library instrumented")
            except Exception as e:
                logger.warning(f"Failed to instrument requests: {e}")
        else:
            logger.debug("Requests instrumentation not available")
    
    def instrument_fastapi(self, app):
        """
        Instrument FastAPI application.

        Args:
            app: FastAPI application instance
        """
        if not self.enabled:
            return

        if not FASTAPI_INSTRUMENTATION_AVAILABLE:
            logger.warning("FastAPI instrumentation not available - install opentelemetry-instrumentation-fastapi")
            return

        try:
            FastAPIInstrumentor.instrument_app(app)
            logger.info("FastAPI application instrumented")
        except Exception as e:
            logger.warning(f"Failed to instrument FastAPI: {e}")
    
    @contextmanager
    def start_span(
        self,
        name: str,
        kind: Optional[Any] = None,
        attributes: Optional[Dict[str, Any]] = None
    ):
        """
        Start a new span as a context manager.
        
        Args:
            name: Span name
            kind: Span kind (SERVER, CLIENT, INTERNAL, etc.)
            attributes: Span attributes
            
        Yields:
            Span object
        """
        if not self.enabled or not self.tracer:
            # No-op context manager when tracing disabled
            yield None
            return
        
        span_kind = kind or SpanKind.INTERNAL
        
        with self.tracer.start_as_current_span(name, kind=span_kind) as span:
            # Add attributes
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, value)
            
            try:
                yield span
            except Exception as e:
                # Record exception
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                raise
    
    def trace_function(
        self,
        name: Optional[str] = None,
        kind: Optional[Any] = None,
        attributes: Optional[Dict[str, Any]] = None
    ):
        """
        Decorator to trace a function.
        
        Args:
            name: Span name (defaults to function name)
            kind: Span kind
            attributes: Span attributes
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)
                
                span_name = name or f"{func.__module__}.{func.__name__}"
                
                with self.start_span(span_name, kind=kind, attributes=attributes) as span:
                    result = func(*args, **kwargs)
                    return result
            
            return wrapper
        return decorator
    
    def trace_async_function(
        self,
        name: Optional[str] = None,
        kind: Optional[Any] = None,
        attributes: Optional[Dict[str, Any]] = None
    ):
        """
        Decorator to trace an async function.
        
        Args:
            name: Span name (defaults to function name)
            kind: Span kind
            attributes: Span attributes
            
        Returns:
            Decorated async function
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                if not self.enabled:
                    return await func(*args, **kwargs)
                
                span_name = name or f"{func.__module__}.{func.__name__}"
                
                with self.start_span(span_name, kind=kind, attributes=attributes) as span:
                    result = await func(*args, **kwargs)
                    return result
            
            return wrapper
        return decorator
    
    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """
        Add an event to the current span.
        
        Args:
            name: Event name
            attributes: Event attributes
        """
        if not self.enabled:
            return
        
        span = trace.get_current_span()
        if span:
            span.add_event(name, attributes=attributes or {})
    
    def set_attribute(self, key: str, value: Any):
        """
        Set an attribute on the current span.
        
        Args:
            key: Attribute key
            value: Attribute value
        """
        if not self.enabled:
            return
        
        span = trace.get_current_span()
        if span:
            span.set_attribute(key, value)
    
    def record_exception(self, exception: Exception):
        """
        Record an exception on the current span.
        
        Args:
            exception: Exception to record
        """
        if not self.enabled:
            return
        
        span = trace.get_current_span()
        if span:
            span.set_status(Status(StatusCode.ERROR, str(exception)))
            span.record_exception(exception)
    
    def inject_context(self, carrier: Dict[str, str]):
        """
        Inject trace context into carrier (e.g., HTTP headers).
        
        Args:
            carrier: Dictionary to inject context into
        """
        if not self.enabled or not self.propagator:
            return
        
        self.propagator.inject(carrier)
    
    def extract_context(self, carrier: Dict[str, str]):
        """
        Extract trace context from carrier (e.g., HTTP headers).
        
        Args:
            carrier: Dictionary to extract context from
        """
        if not self.enabled or not self.propagator:
            return None
        
        return self.propagator.extract(carrier)


# Global tracing manager instance
tracing_manager: Optional[TracingManager] = None


def initialize_tracing(
    service_name: str = "bountybot",
    service_version: str = "2.7.0",
    jaeger_endpoint: Optional[str] = None,
    otlp_endpoint: Optional[str] = None,
    console_export: bool = False,
    enabled: bool = True
) -> TracingManager:
    """
    Initialize global tracing manager.
    
    Args:
        service_name: Service name
        service_version: Service version
        jaeger_endpoint: Jaeger endpoint
        otlp_endpoint: OTLP endpoint
        console_export: Enable console export
        enabled: Enable tracing
        
    Returns:
        TracingManager instance
    """
    global tracing_manager
    
    tracing_manager = TracingManager(
        service_name=service_name,
        service_version=service_version,
        jaeger_endpoint=jaeger_endpoint,
        otlp_endpoint=otlp_endpoint,
        console_export=console_export,
        enabled=enabled
    )
    
    return tracing_manager


def get_tracing_manager() -> Optional[TracingManager]:
    """Get global tracing manager instance."""
    return tracing_manager

