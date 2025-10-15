import logging
import json
import time
import uuid
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from contextvars import ContextVar
from functools import wraps
import traceback

# Context variables for request tracking
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
user_context_var: ContextVar[Optional[Dict]] = ContextVar('user_context', default=None)


class SensitiveDataRedactor:
    """Redacts sensitive data from logs."""
    
    # Patterns for sensitive data
    PATTERNS = {
        'api_key': re.compile(r'(api[_-]?key|apikey|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{8,})', re.IGNORECASE),
        'password': re.compile(r'(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']+)', re.IGNORECASE),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'credit_card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'jwt': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
    }
    
    @classmethod
    def redact(cls, text: str, redaction_char: str = '*') -> str:
        """Redact sensitive data from text."""
        if not text:
            return text
        
        redacted = text
        
        for pattern_name, pattern in cls.PATTERNS.items():
            if pattern_name in ['api_key', 'password']:
                # Keep the key name, redact the value
                redacted = pattern.sub(lambda m: f"{m.group(1)}={redaction_char * 8}", redacted)
            elif pattern_name == 'email':
                # Partially redact email
                redacted = pattern.sub(lambda m: cls._redact_email(m.group(0)), redacted)
            else:
                # Fully redact
                redacted = pattern.sub(redaction_char * 8, redacted)
        
        return redacted
    
    @staticmethod
    def _redact_email(email: str) -> str:
        """Partially redact email address."""
        parts = email.split('@')
        if len(parts) == 2:
            username = parts[0]
            domain = parts[1]
            if len(username) > 2:
                redacted_username = username[0] + '*' * (len(username) - 2) + username[-1]
            else:
                redacted_username = '*' * len(username)
            return f"{redacted_username}@{domain}"
        return email


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def __init__(self, include_context: bool = True, redact_sensitive: bool = True):
        """
        Initialize structured formatter.
        
        Args:
            include_context: Include request context in logs
            redact_sensitive: Redact sensitive data
        """
        super().__init__()
        self.include_context = include_context
        self.redact_sensitive = redact_sensitive
        self.redactor = SensitiveDataRedactor()
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add request context
        if self.include_context:
            request_id = request_id_var.get()
            if request_id:
                log_data['request_id'] = request_id
            
            user_context = user_context_var.get()
            if user_context:
                log_data['user_context'] = user_context
        
        # Add exception info
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info),
            }
        
        # Add extra fields
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        # Redact sensitive data
        if self.redact_sensitive:
            log_data['message'] = self.redactor.redact(log_data['message'])
        
        return json.dumps(log_data)


class StructuredLogger:
    """
    Structured logger with context tracking and performance metrics.
    """
    
    def __init__(self, name: str, enable_json: bool = False):
        """
        Initialize structured logger.
        
        Args:
            name: Logger name
            enable_json: Enable JSON output
        """
        self.logger = logging.getLogger(name)
        self.enable_json = enable_json
        
        if enable_json:
            handler = logging.StreamHandler()
            handler.setFormatter(StructuredFormatter())
            self.logger.addHandler(handler)
    
    def set_request_id(self, request_id: Optional[str] = None):
        """Set request ID for context tracking."""
        if request_id is None:
            request_id = str(uuid.uuid4())
        request_id_var.set(request_id)
        return request_id
    
    def set_user_context(self, context: Dict[str, Any]):
        """Set user context for logging."""
        user_context_var.set(context)
    
    def clear_context(self):
        """Clear request context."""
        request_id_var.set(None)
        user_context_var.set(None)
    
    def log(self, level: str, message: str, **extra_fields):
        """Log with extra fields."""
        record = self.logger.makeRecord(
            self.logger.name,
            getattr(logging, level.upper()),
            "(unknown file)", 0,
            message, (), None
        )
        record.extra_fields = extra_fields
        self.logger.handle(record)
    
    def debug(self, message: str, **extra_fields):
        """Log debug message."""
        self.log('DEBUG', message, **extra_fields)
    
    def info(self, message: str, **extra_fields):
        """Log info message."""
        self.log('INFO', message, **extra_fields)
    
    def warning(self, message: str, **extra_fields):
        """Log warning message."""
        self.log('WARNING', message, **extra_fields)
    
    def error(self, message: str, **extra_fields):
        """Log error message."""
        self.log('ERROR', message, **extra_fields)
    
    def critical(self, message: str, **extra_fields):
        """Log critical message."""
        self.log('CRITICAL', message, **extra_fields)
    
    def security_event(self, event_type: str, details: Dict[str, Any], severity: str = 'INFO'):
        """Log security event."""
        self.log(
            severity,
            f"Security event: {event_type}",
            event_type=event_type,
            event_category='security',
            **details
        )
    
    def audit_log(self, action: str, resource: str, result: str, **details):
        """Log audit trail."""
        self.log(
            'INFO',
            f"Audit: {action} on {resource} - {result}",
            audit_action=action,
            audit_resource=resource,
            audit_result=result,
            event_category='audit',
            **details
        )
    
    def performance_metric(self, operation: str, duration_ms: float, **metrics):
        """Log performance metric."""
        self.log(
            'INFO',
            f"Performance: {operation} took {duration_ms:.2f}ms",
            operation=operation,
            duration_ms=duration_ms,
            event_category='performance',
            **metrics
        )


def timed_operation(operation_name: str):
    """
    Decorator to time operations and log performance metrics.
    
    Usage:
        @timed_operation("validate_report")
        def validate(report):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            logger = StructuredLogger(func.__module__)
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                logger.performance_metric(
                    operation=operation_name,
                    duration_ms=duration_ms,
                    status='success'
                )
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                logger.performance_metric(
                    operation=operation_name,
                    duration_ms=duration_ms,
                    status='error',
                    error=str(e)
                )
                raise
        
        return wrapper
    return decorator


class PerformanceTracker:
    """Track performance metrics for operations."""
    
    def __init__(self, operation: str, logger: Optional[StructuredLogger] = None):
        """
        Initialize performance tracker.
        
        Args:
            operation: Operation name
            logger: Optional structured logger
        """
        self.operation = operation
        self.logger = logger or StructuredLogger(__name__)
        self.start_time = None
        self.metrics = {}
    
    def __enter__(self):
        """Start tracking."""
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop tracking and log metrics."""
        duration_ms = (time.time() - self.start_time) * 1000
        status = 'error' if exc_type else 'success'
        
        self.logger.performance_metric(
            operation=self.operation,
            duration_ms=duration_ms,
            status=status,
            **self.metrics
        )
    
    def add_metric(self, key: str, value: Any):
        """Add custom metric."""
        self.metrics[key] = value

