"""
Researcher Communication Assistant

AI-powered communication tools for bug bounty programs:
- Automated response generation
- Template management
- Tone analysis
- Multi-language support
- Sentiment analysis
- Professional communication scoring

Features:
- Context-aware response generation
- Customizable templates for common scenarios
- Tone checking and professionalism scoring
- Multi-language translation
- Sentiment analysis
- Communication history tracking
- Best practice recommendations

Example:
    >>> from bountybot.communication import CommunicationAssistant
    >>> 
    >>> assistant = CommunicationAssistant()
    >>> 
    >>> # Generate response
    >>> response = assistant.generate_response(
    ...     scenario="report_accepted",
    ...     context={"report_id": "123", "payout": 5000}
    ... )
    >>> print(response.message)
"""

from .models import (
    CommunicationScenario,
    ResponseTemplate,
    GeneratedResponse,
    ToneAnalysis,
    SentimentScore,
    CommunicationHistory,
    Language,
    TranslationResult,
    ToneType
)

from .response_generator import ResponseGenerator
from .tone_analyzer import ToneAnalyzer
from .template_manager import TemplateManager
from .translator import MultiLanguageTranslator

__all__ = [
    # Models
    'CommunicationScenario',
    'ResponseTemplate',
    'GeneratedResponse',
    'ToneAnalysis',
    'SentimentScore',
    'CommunicationHistory',
    'Language',
    'TranslationResult',
    'ToneType',

    # Core Components
    'ResponseGenerator',
    'ToneAnalyzer',
    'TemplateManager',
    'MultiLanguageTranslator',
]

