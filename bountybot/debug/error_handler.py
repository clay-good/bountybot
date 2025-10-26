"""
Enhanced error handling with helpful suggestions and recovery options.

Provides context-aware error messages, suggestions, and automatic recovery.
"""

import logging
import traceback
import sys
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class ErrorSuggestion:
    """Error suggestion with recovery action."""
    message: str
    action: Optional[Callable] = None
    action_label: Optional[str] = None


class EnhancedErrorHandler:
    """
    Enhanced error handler with context and suggestions.
    
    Features:
    - Context-aware error messages
    - Actionable suggestions
    - Automatic recovery options
    - Error categorization
    - Debug information
    """
    
    # Error patterns and suggestions
    ERROR_PATTERNS = {
        'FileNotFoundError': {
            'category': 'File System',
            'suggestions': [
                'Check if the file path is correct',
                'Verify the file exists',
                'Check file permissions',
                'Use absolute path instead of relative path'
            ]
        },
        'PermissionError': {
            'category': 'Permissions',
            'suggestions': [
                'Check file/directory permissions',
                'Run with appropriate user privileges',
                'Verify ownership of files',
                'Check if file is locked by another process'
            ]
        },
        'ConnectionError': {
            'category': 'Network',
            'suggestions': [
                'Check internet connection',
                'Verify API endpoint is accessible',
                'Check firewall settings',
                'Verify proxy configuration',
                'Check if service is running'
            ]
        },
        'TimeoutError': {
            'category': 'Network',
            'suggestions': [
                'Increase timeout value in configuration',
                'Check network latency',
                'Verify service is responding',
                'Try again later'
            ]
        },
        'KeyError': {
            'category': 'Data',
            'suggestions': [
                'Check if required field exists in data',
                'Verify data structure matches expected format',
                'Check for typos in field names',
                'Validate input data'
            ]
        },
        'ValueError': {
            'category': 'Data',
            'suggestions': [
                'Check input data format',
                'Verify data types are correct',
                'Check for invalid values',
                'Validate input against schema'
            ]
        },
        'ImportError': {
            'category': 'Dependencies',
            'suggestions': [
                'Install missing package: pip install <package>',
                'Check if package is in requirements.txt',
                'Verify virtual environment is activated',
                'Update dependencies: pip install -U -r requirements.txt'
            ]
        },
        'ModuleNotFoundError': {
            'category': 'Dependencies',
            'suggestions': [
                'Install missing module: pip install <module>',
                'Check if module name is correct',
                'Verify PYTHONPATH is set correctly',
                'Reinstall package: pip install --force-reinstall <package>'
            ]
        },
        'AttributeError': {
            'category': 'Code',
            'suggestions': [
                'Check if object has the attribute',
                'Verify object type is correct',
                'Check for typos in attribute name',
                'Update to latest version of library'
            ]
        },
        'TypeError': {
            'category': 'Code',
            'suggestions': [
                'Check function arguments',
                'Verify data types are correct',
                'Check for None values',
                'Review function signature'
            ]
        },
        'JSONDecodeError': {
            'category': 'Data',
            'suggestions': [
                'Check if response is valid JSON',
                'Verify API returned expected format',
                'Check for empty response',
                'Inspect raw response data'
            ]
        },
        'RateLimitError': {
            'category': 'API',
            'suggestions': [
                'Wait before retrying',
                'Reduce request frequency',
                'Check rate limit configuration',
                'Use exponential backoff',
                'Consider upgrading API plan'
            ]
        },
        'AuthenticationError': {
            'category': 'API',
            'suggestions': [
                'Check API key is set correctly',
                'Verify API key is valid',
                'Check environment variables',
                'Regenerate API key if expired',
                'Verify API key has required permissions'
            ]
        }
    }
    
    def __init__(self, debug_mode: bool = False):
        """
        Initialize error handler.
        
        Args:
            debug_mode: Enable debug mode with full tracebacks
        """
        self.debug_mode = debug_mode
        
    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        show_traceback: bool = None
    ):
        """
        Handle error with enhanced messaging.
        
        Args:
            error: Exception object
            context: Additional context information
            show_traceback: Override debug_mode for traceback display
        """
        error_type = type(error).__name__
        error_message = str(error)
        
        # Get error pattern
        pattern = self.ERROR_PATTERNS.get(error_type, {
            'category': 'Unknown',
            'suggestions': ['Check error message for details', 'Enable debug mode for more information']
        })
        
        # Create error panel
        console.print("\n")
        console.print(Panel.fit(
            f"[bold red]Error: {error_type}[/bold red]\n"
            f"[red]{error_message}[/red]",
            title=f"❌ {pattern['category']} Error",
            border_style="red"
        ))
        
        # Show context if available
        if context:
            console.print("\n[bold]Context:[/bold]")
            context_table = Table(box=box.SIMPLE)
            context_table.add_column("Key", style="cyan")
            context_table.add_column("Value", style="white")
            
            for key, value in context.items():
                context_table.add_row(key, str(value))
            
            console.print(context_table)
        
        # Show suggestions
        console.print("\n[bold yellow]💡 Suggestions:[/bold yellow]")
        for idx, suggestion in enumerate(pattern['suggestions'], 1):
            console.print(f"  {idx}. {suggestion}")
        
        # Show traceback in debug mode
        show_tb = show_traceback if show_traceback is not None else self.debug_mode
        if show_tb:
            console.print("\n[bold]Debug Traceback:[/bold]")
            console.print(Panel(
                traceback.format_exc(),
                border_style="dim",
                title="Stack Trace"
            ))
        else:
            console.print("\n[dim]Run with --debug flag for full traceback[/dim]")
        
        # Log error
        logger.error(f"{error_type}: {error_message}", exc_info=True, extra={'context': context})
    
    def handle_validation_error(
        self,
        error: Exception,
        report_path: str,
        stage: str,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Handle validation-specific error.
        
        Args:
            error: Exception object
            report_path: Path to report being validated
            stage: Validation stage where error occurred
            context: Additional context
        """
        validation_context = {
            'report_path': report_path,
            'stage': stage,
            **(context or {})
        }
        
        console.print(Panel.fit(
            f"[bold red]Validation Failed[/bold red]\n"
            f"Report: {report_path}\n"
            f"Stage: {stage}\n"
            f"Error: {type(error).__name__}: {str(error)}",
            title="❌ Validation Error",
            border_style="red"
        ))
        
        # Stage-specific suggestions
        stage_suggestions = {
            'parsing': [
                'Check if report file format is supported (JSON, Markdown, HTML)',
                'Verify file is not corrupted',
                'Check file encoding (should be UTF-8)',
                'Try with a different report format'
            ],
            'extraction': [
                'Check if report contains HTTP requests',
                'Verify request format is correct',
                'Check for malformed URLs',
                'Inspect report content manually'
            ],
            'analysis': [
                'Check if codebase path is correct',
                'Verify code files are accessible',
                'Check for syntax errors in code',
                'Try without code analysis'
            ],
            'validation': [
                'Check AI provider API key',
                'Verify network connectivity',
                'Check rate limits',
                'Try with different AI provider',
                'Reduce prompt size'
            ],
            'scanning': [
                'Check if target URL is accessible',
                'Verify target allows scanning',
                'Check firewall/WAF settings',
                'Try with reduced scan depth',
                'Skip dynamic scanning'
            ]
        }
        
        suggestions = stage_suggestions.get(stage, [])
        if suggestions:
            console.print("\n[bold yellow]💡 Stage-Specific Suggestions:[/bold yellow]")
            for idx, suggestion in enumerate(suggestions, 1):
                console.print(f"  {idx}. {suggestion}")
        
        self.handle_error(error, validation_context, show_traceback=self.debug_mode)
    
    def handle_api_error(
        self,
        error: Exception,
        provider: str,
        operation: str,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Handle AI provider API error.
        
        Args:
            error: Exception object
            provider: AI provider name
            operation: API operation
            context: Additional context
        """
        api_context = {
            'provider': provider,
            'operation': operation,
            **(context or {})
        }
        
        console.print(Panel.fit(
            f"[bold red]AI Provider Error[/bold red]\n"
            f"Provider: {provider}\n"
            f"Operation: {operation}\n"
            f"Error: {type(error).__name__}: {str(error)}",
            title="❌ API Error",
            border_style="red"
        ))
        
        # Provider-specific suggestions
        provider_suggestions = {
            'anthropic': [
                'Check ANTHROPIC_API_KEY environment variable',
                'Verify API key at https://console.anthropic.com',
                'Check rate limits and usage',
                'Try with different model',
                'Check prompt size (max 200K tokens)'
            ],
            'openai': [
                'Check OPENAI_API_KEY environment variable',
                'Verify API key at https://platform.openai.com',
                'Check rate limits and usage',
                'Try with different model',
                'Check if organization ID is required'
            ],
            'gemini': [
                'Check GEMINI_API_KEY environment variable',
                'Verify API key at https://makersuite.google.com',
                'Check rate limits and usage',
                'Try with different model',
                'Check if API is enabled in Google Cloud'
            ]
        }
        
        suggestions = provider_suggestions.get(provider, [])
        if suggestions:
            console.print("\n[bold yellow]💡 Provider-Specific Suggestions:[/bold yellow]")
            for idx, suggestion in enumerate(suggestions, 1):
                console.print(f"  {idx}. {suggestion}")
        
        self.handle_error(error, api_context, show_traceback=self.debug_mode)

