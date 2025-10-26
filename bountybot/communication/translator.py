"""
Multi-language translation for communications.
"""

import logging
from typing import Dict, Optional

from .models import Language, TranslationResult

logger = logging.getLogger(__name__)


class MultiLanguageTranslator:
    """
    Translates communications to multiple languages.
    
    Features:
    - Multi-language support
    - Context-aware translation
    - Quality scoring
    - Fallback mechanisms
    
    Example:
        >>> translator = MultiLanguageTranslator()
        >>> result = translator.translate(
        ...     "Thank you for your report",
        ...     Language.ENGLISH,
        ...     Language.SPANISH
        ... )
        >>> print(result.translated_text)
    """
    
    # Simple translation dictionary (in production, use proper translation API)
    TRANSLATIONS = {
        ("Thank you for your report", Language.ENGLISH, Language.SPANISH): "Gracias por su informe",
        ("Thank you for your report", Language.ENGLISH, Language.FRENCH): "Merci pour votre rapport",
        ("Thank you for your report", Language.ENGLISH, Language.GERMAN): "Vielen Dank für Ihren Bericht",
        ("Your report has been accepted", Language.ENGLISH, Language.SPANISH): "Su informe ha sido aceptado",
        ("Your report has been accepted", Language.ENGLISH, Language.FRENCH): "Votre rapport a été accepté",
        ("Your report has been accepted", Language.ENGLISH, Language.GERMAN): "Ihr Bericht wurde akzeptiert",
    }
    
    def __init__(self):
        """Initialize translator."""
        logger.info("MultiLanguageTranslator initialized")
    
    def translate(
        self,
        text: str,
        source_language: Language,
        target_language: Language
    ) -> TranslationResult:
        """
        Translate text from source to target language.
        
        Args:
            text: Text to translate
            source_language: Source language
            target_language: Target language
            
        Returns:
            TranslationResult
        """
        # If same language, return as-is
        if source_language == target_language:
            return TranslationResult(
                original_text=text,
                translated_text=text,
                source_language=source_language,
                target_language=target_language,
                confidence=1.0,
                method="none"
            )
        
        # Try dictionary lookup
        key = (text, source_language, target_language)
        if key in self.TRANSLATIONS:
            return TranslationResult(
                original_text=text,
                translated_text=self.TRANSLATIONS[key],
                source_language=source_language,
                target_language=target_language,
                confidence=0.95,
                method="dictionary"
            )
        
        # Fallback: return original with note
        translated = f"[{target_language.value}] {text}"
        
        return TranslationResult(
            original_text=text,
            translated_text=translated,
            source_language=source_language,
            target_language=target_language,
            confidence=0.5,
            method="fallback"
        )
    
    def detect_language(self, text: str) -> Language:
        """Detect language of text."""
        # Simple detection based on common words
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['gracias', 'informe', 'su']):
            return Language.SPANISH
        elif any(word in text_lower for word in ['merci', 'votre', 'rapport']):
            return Language.FRENCH
        elif any(word in text_lower for word in ['danke', 'ihr', 'bericht']):
            return Language.GERMAN
        else:
            return Language.ENGLISH
    
    def is_supported(self, language: Language) -> bool:
        """Check if language is supported."""
        supported = [
            Language.ENGLISH,
            Language.SPANISH,
            Language.FRENCH,
            Language.GERMAN,
            Language.CHINESE,
            Language.JAPANESE
        ]
        return language in supported

