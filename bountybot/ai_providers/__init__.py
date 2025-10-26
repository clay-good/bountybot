from .base import BaseAIProvider, CircuitBreakerError
from .anthropic_provider import AnthropicProvider

# Async providers
from .async_base import AsyncBaseAIProvider
from .async_anthropic_provider import AsyncAnthropicProvider

# Optional providers - import only if dependencies are available
try:
    from .openai_provider import OpenAIProvider
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    OpenAIProvider = None

try:
    from .gemini_provider import GeminiProvider
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    GeminiProvider = None

# Optional async providers
try:
    from .async_openai_provider import AsyncOpenAIProvider, AsyncGeminiProvider
    ASYNC_OPENAI_AVAILABLE = OPENAI_AVAILABLE
    ASYNC_GEMINI_AVAILABLE = True
except ImportError:
    ASYNC_OPENAI_AVAILABLE = False
    ASYNC_GEMINI_AVAILABLE = False
    AsyncOpenAIProvider = None
    AsyncGeminiProvider = None

__all__ = ['BaseAIProvider', 'CircuitBreakerError', 'AnthropicProvider', 'AsyncBaseAIProvider', 'AsyncAnthropicProvider']

if OPENAI_AVAILABLE:
    __all__.append('OpenAIProvider')
if GEMINI_AVAILABLE:
    __all__.append('GeminiProvider')
if ASYNC_OPENAI_AVAILABLE:
    __all__.append('AsyncOpenAIProvider')
if ASYNC_GEMINI_AVAILABLE:
    __all__.append('AsyncGeminiProvider')

