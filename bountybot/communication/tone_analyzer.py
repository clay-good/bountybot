"""
Tone analysis for communications.
"""

import logging
import re
from typing import List

from .models import ToneAnalysis, ToneType

logger = logging.getLogger(__name__)


class ToneAnalyzer:
    """
    Analyzes tone and professionalism of communications.
    
    Features:
    - Professionalism scoring
    - Tone detection
    - Issue identification
    - Improvement suggestions
    
    Example:
        >>> analyzer = ToneAnalyzer()
        >>> analysis = analyzer.analyze_tone("Thank you for your report.")
        >>> print(f"Professionalism: {analysis.professionalism_score:.2f}")
    """
    
    def __init__(self):
        """Initialize tone analyzer."""
        logger.info("ToneAnalyzer initialized")
    
    def analyze_tone(self, text: str) -> ToneAnalysis:
        """
        Analyze tone of text.
        
        Args:
            text: Text to analyze
            
        Returns:
            ToneAnalysis
        """
        # Calculate scores
        professionalism = self._calculate_professionalism(text)
        friendliness = self._calculate_friendliness(text)
        formality = self._calculate_formality(text)
        clarity = self._calculate_clarity(text)
        
        # Determine tone type
        tone_type = self._determine_tone_type(professionalism, friendliness, formality)
        
        # Find issues
        issues = self._find_issues(text)
        
        # Generate suggestions
        suggestions = self._generate_suggestions(text, issues)
        
        # Overall score
        overall = (professionalism + friendliness + clarity) / 3.0
        
        return ToneAnalysis(
            tone_type=tone_type,
            professionalism_score=professionalism,
            friendliness_score=friendliness,
            formality_score=formality,
            clarity_score=clarity,
            overall_score=overall,
            issues=issues,
            suggestions=suggestions,
            confidence=0.8
        )
    
    def _calculate_professionalism(self, text: str) -> float:
        """Calculate professionalism score."""
        score = 0.7  # Base score
        
        # Positive indicators
        if "thank you" in text.lower():
            score += 0.1
        if "please" in text.lower():
            score += 0.05
        if re.search(r'\b(appreciate|grateful|valued)\b', text.lower()):
            score += 0.1
        
        # Negative indicators
        if re.search(r'\b(hey|yo|sup)\b', text.lower()):
            score -= 0.2
        if "!!!" in text:
            score -= 0.1
        if text.isupper():
            score -= 0.3
        
        return max(0.0, min(1.0, score))
    
    def _calculate_friendliness(self, text: str) -> float:
        """Calculate friendliness score."""
        score = 0.5  # Base score
        
        # Friendly indicators
        if re.search(r'\b(hi|hello|hey)\b', text.lower()):
            score += 0.2
        if "!" in text:
            score += 0.1
        if re.search(r'\b(great|excellent|awesome)\b', text.lower()):
            score += 0.15
        
        return max(0.0, min(1.0, score))
    
    def _calculate_formality(self, text: str) -> float:
        """Calculate formality score."""
        score = 0.6  # Base score
        
        # Formal indicators
        if re.search(r'\b(dear|sincerely|regards)\b', text.lower()):
            score += 0.2
        if "thank you" in text.lower() and "thanks" not in text.lower():
            score += 0.1
        
        # Informal indicators
        if re.search(r'\b(hey|yo|gonna|wanna)\b', text.lower()):
            score -= 0.3
        
        return max(0.0, min(1.0, score))
    
    def _calculate_clarity(self, text: str) -> float:
        """Calculate clarity score."""
        score = 0.7  # Base score
        
        # Check sentence length
        sentences = text.split('.')
        avg_length = sum(len(s.split()) for s in sentences) / max(len(sentences), 1)
        
        if avg_length > 30:
            score -= 0.2  # Too long
        elif avg_length < 5:
            score -= 0.1  # Too short
        
        # Check for jargon
        jargon_words = ['utilize', 'leverage', 'synergy', 'paradigm']
        if any(word in text.lower() for word in jargon_words):
            score -= 0.1
        
        return max(0.0, min(1.0, score))
    
    def _determine_tone_type(
        self,
        professionalism: float,
        friendliness: float,
        formality: float
    ) -> ToneType:
        """Determine overall tone type."""
        if formality > 0.7:
            return ToneType.FORMAL
        elif professionalism > 0.7 and friendliness > 0.6:
            return ToneType.FRIENDLY
        elif professionalism > 0.7:
            return ToneType.PROFESSIONAL
        elif friendliness > 0.7:
            return ToneType.CASUAL
        else:
            return ToneType.NEUTRAL
    
    def _find_issues(self, text: str) -> List[str]:
        """Find issues in text."""
        issues = []
        
        if text.isupper():
            issues.append("Text is all caps - appears aggressive")
        
        if "!!!" in text:
            issues.append("Excessive exclamation marks")
        
        if re.search(r'\b(hey|yo)\b', text.lower()):
            issues.append("Overly casual greeting")
        
        if len(text) < 20:
            issues.append("Message is very short - may seem curt")
        
        return issues
    
    def _generate_suggestions(self, text: str, issues: List[str]) -> List[str]:
        """Generate improvement suggestions."""
        suggestions = []
        
        if "Text is all caps" in issues:
            suggestions.append("Use normal capitalization")
        
        if "Excessive exclamation marks" in issues:
            suggestions.append("Limit exclamation marks to one per sentence")
        
        if "Overly casual greeting" in issues:
            suggestions.append("Use 'Hello' or 'Hi' instead of casual greetings")
        
        if "very short" in str(issues):
            suggestions.append("Add more context and detail to the message")
        
        if not suggestions:
            suggestions.append("Communication tone is appropriate")
        
        return suggestions

