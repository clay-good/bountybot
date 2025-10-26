"""
AI-powered response generation for researcher communications.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from .models import (
    CommunicationScenario,
    GeneratedResponse,
    Language,
    ToneType,
    ToneAnalysis,
    SentimentScore
)
from .template_manager import TemplateManager
from .tone_analyzer import ToneAnalyzer

logger = logging.getLogger(__name__)


class ResponseGenerator:
    """
    Generates AI-powered responses for researcher communications.
    
    Features:
    - Context-aware generation
    - Template-based responses
    - Tone customization
    - Variable substitution
    
    Example:
        >>> generator = ResponseGenerator()
        >>> response = generator.generate_response(
        ...     scenario=CommunicationScenario.REPORT_ACCEPTED,
        ...     context={"researcher_name": "John", "payout": 5000}
        ... )
        >>> print(response.body)
    """
    
    def __init__(self):
        """Initialize response generator."""
        self.template_manager = TemplateManager()
        self.tone_analyzer = ToneAnalyzer()
        logger.info("ResponseGenerator initialized")
    
    def generate_response(
        self,
        scenario: CommunicationScenario,
        context: Dict[str, Any],
        language: Language = Language.ENGLISH,
        tone: ToneType = ToneType.PROFESSIONAL
    ) -> GeneratedResponse:
        """
        Generate response for a scenario.
        
        Args:
            scenario: Communication scenario
            context: Context variables
            language: Target language
            tone: Desired tone
            
        Returns:
            GeneratedResponse
        """
        # Get template
        template = self.template_manager.get_template(scenario, language)
        
        if template:
            # Use template
            subject, body = self._apply_template(template, context)
            template_id = template.template_id
        else:
            # Generate from scratch
            subject, body = self._generate_from_scratch(scenario, context, tone)
            template_id = None
        
        # Analyze tone
        tone_analysis = self.tone_analyzer.analyze_tone(body)
        
        # Analyze sentiment
        sentiment = self._analyze_sentiment(body)
        
        # Generate alternatives
        alternatives = self._generate_alternatives(scenario, context, language, tone)
        
        return GeneratedResponse(
            scenario=scenario,
            language=language,
            subject=subject,
            body=body,
            tone_analysis=tone_analysis,
            sentiment=sentiment,
            template_used=template_id,
            context=context,
            alternatives=alternatives
        )
    
    def _apply_template(
        self,
        template: Any,
        context: Dict[str, Any]
    ) -> tuple:
        """Apply template with context variables."""
        subject = template.subject
        body = template.body
        
        # Substitute variables
        for var in template.variables:
            placeholder = f"{{{var}}}"
            value = context.get(var, f"[{var}]")
            subject = subject.replace(placeholder, str(value))
            body = body.replace(placeholder, str(value))
        
        return subject, body
    
    def _generate_from_scratch(
        self,
        scenario: CommunicationScenario,
        context: Dict[str, Any],
        tone: ToneType
    ) -> tuple:
        """Generate response from scratch."""
        # Default responses for each scenario
        responses = {
            CommunicationScenario.REPORT_RECEIVED: (
                "Thank you for your security report",
                "Thank you for submitting your security report. We have received it and our security team will review it shortly. We appreciate your contribution to our security program."
            ),
            CommunicationScenario.REPORT_ACCEPTED: (
                "Your security report has been accepted",
                f"Great news! Your security report has been accepted. We have validated the vulnerability and will be awarding a bounty of ${context.get('payout', 'TBD')}. Thank you for helping us improve our security."
            ),
            CommunicationScenario.REPORT_REJECTED: (
                "Update on your security report",
                "Thank you for your submission. After careful review, we have determined that this report does not qualify for a bounty at this time. We appreciate your effort and encourage you to continue participating in our program."
            ),
            CommunicationScenario.REPORT_DUPLICATE: (
                "Your report is a duplicate",
                "Thank you for your submission. We have determined that this vulnerability was previously reported. While we cannot award a bounty for duplicate reports, we appreciate your diligence."
            ),
            CommunicationScenario.NEEDS_MORE_INFO: (
                "Additional information needed",
                "Thank you for your report. To proceed with validation, we need some additional information. Please provide more details about the reproduction steps and the impact of this vulnerability."
            ),
            CommunicationScenario.PAYOUT_NOTIFICATION: (
                "Bounty payout notification",
                f"Your bounty payment of ${context.get('payout', 'TBD')} has been processed. Thank you for your valuable contribution to our security program."
            ),
        }
        
        return responses.get(scenario, ("Update", "Thank you for your submission."))
    
    def _analyze_sentiment(self, text: str) -> SentimentScore:
        """Analyze sentiment of text."""
        # Simple sentiment analysis
        positive_words = ['thank', 'great', 'excellent', 'appreciate', 'valuable']
        negative_words = ['unfortunately', 'cannot', 'rejected', 'invalid']
        
        text_lower = text.lower()
        positive_count = sum(1 for word in positive_words if word in text_lower)
        negative_count = sum(1 for word in negative_words if word in text_lower)
        
        if positive_count > negative_count:
            sentiment = "positive"
            score = 0.7
        elif negative_count > positive_count:
            sentiment = "negative"
            score = -0.5
        else:
            sentiment = "neutral"
            score = 0.0
        
        return SentimentScore(
            sentiment=sentiment,
            score=score,
            confidence=0.75,
            emotions={"gratitude": 0.8 if positive_count > 0 else 0.2}
        )
    
    def _generate_alternatives(
        self,
        scenario: CommunicationScenario,
        context: Dict[str, Any],
        language: Language,
        tone: ToneType
    ) -> List[str]:
        """Generate alternative phrasings."""
        # Return 2-3 alternative versions
        alternatives = []
        
        if scenario == CommunicationScenario.REPORT_ACCEPTED:
            alternatives = [
                "We're pleased to inform you that your security report has been validated.",
                "Excellent work! Your vulnerability report has been confirmed and accepted.",
                "Your security submission has been reviewed and approved for a bounty."
            ]
        elif scenario == CommunicationScenario.REPORT_REJECTED:
            alternatives = [
                "After thorough review, we've determined this report doesn't meet our bounty criteria.",
                "We appreciate your submission, but this issue doesn't qualify for our program.",
                "Thank you for your report. Unfortunately, it doesn't meet our acceptance criteria."
            ]
        
        return alternatives[:3]
    
    def customize_tone(
        self,
        text: str,
        target_tone: ToneType
    ) -> str:
        """Customize tone of existing text."""
        # Simple tone adjustment
        if target_tone == ToneType.FRIENDLY:
            # Add friendly elements
            if not text.startswith("Hi") and not text.startswith("Hello"):
                text = "Hi there! " + text
            text = text.replace("Thank you", "Thanks so much")
        elif target_tone == ToneType.FORMAL:
            # Make more formal
            text = text.replace("Thanks", "Thank you")
            text = text.replace("Hi", "Dear")
        
        return text

