"""
Data models for researcher communication.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class CommunicationScenario(Enum):
    """Communication scenario types."""
    REPORT_RECEIVED = "report_received"
    REPORT_ACCEPTED = "report_accepted"
    REPORT_REJECTED = "report_rejected"
    REPORT_DUPLICATE = "report_duplicate"
    NEEDS_MORE_INFO = "needs_more_info"
    PAYOUT_NOTIFICATION = "payout_notification"
    THANK_YOU = "thank_you"
    FOLLOW_UP = "follow_up"
    CLARIFICATION_REQUEST = "clarification_request"
    STATUS_UPDATE = "status_update"


class Language(Enum):
    """Supported languages."""
    ENGLISH = "en"
    SPANISH = "es"
    FRENCH = "fr"
    GERMAN = "de"
    CHINESE = "zh"
    JAPANESE = "ja"
    KOREAN = "ko"
    PORTUGUESE = "pt"
    RUSSIAN = "ru"
    ARABIC = "ar"


class ToneType(Enum):
    """Tone types."""
    PROFESSIONAL = "professional"
    FRIENDLY = "friendly"
    FORMAL = "formal"
    CASUAL = "casual"
    APOLOGETIC = "apologetic"
    GRATEFUL = "grateful"
    NEUTRAL = "neutral"


@dataclass
class ResponseTemplate:
    """Template for communication responses."""
    template_id: str
    scenario: CommunicationScenario
    language: Language
    subject: str
    body: str
    variables: List[str]  # Variables that can be substituted
    tone: ToneType
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ToneAnalysis:
    """Analysis of communication tone."""
    tone_type: ToneType
    professionalism_score: float  # 0-1
    friendliness_score: float  # 0-1
    formality_score: float  # 0-1
    clarity_score: float  # 0-1
    overall_score: float  # 0-1
    issues: List[str]
    suggestions: List[str]
    confidence: float


@dataclass
class SentimentScore:
    """Sentiment analysis score."""
    sentiment: str  # "positive", "negative", "neutral"
    score: float  # -1 to 1
    confidence: float
    emotions: Dict[str, float]  # emotion -> intensity
    analyzed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class GeneratedResponse:
    """Generated communication response."""
    scenario: CommunicationScenario
    language: Language
    subject: str
    body: str
    tone_analysis: ToneAnalysis
    sentiment: SentimentScore
    template_used: Optional[str]
    context: Dict[str, Any]
    alternatives: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CommunicationHistory:
    """History of communications with a researcher."""
    researcher_id: str
    report_id: Optional[str]
    messages: List[Dict[str, Any]]
    total_messages: int
    avg_response_time_hours: float
    sentiment_trend: List[float]  # Historical sentiment scores
    last_contact: datetime
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TranslationResult:
    """Result of text translation."""
    original_text: str
    translated_text: str
    source_language: Language
    target_language: Language
    confidence: float
    method: str  # "ai", "dictionary", "hybrid"
    translated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CommunicationMetrics:
    """Metrics for communication quality."""
    total_communications: int
    avg_professionalism_score: float
    avg_response_time_hours: float
    positive_sentiment_rate: float
    researcher_satisfaction_score: float
    template_usage_rate: float
    multi_language_rate: float
    period_start: datetime
    period_end: datetime


@dataclass
class TranslationResult:
    """Result of a translation operation."""
    original_text: str
    translated_text: str
    source_language: Language
    target_language: Language
    confidence: float
    method: str  # "dictionary", "ai", "fallback", "none"
