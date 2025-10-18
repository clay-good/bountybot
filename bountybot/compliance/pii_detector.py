"""
PII Detection Module

Detects Personally Identifiable Information in text using regex patterns.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from .models import PIIType

logger = logging.getLogger(__name__)


@dataclass
class PIIMatch:
    """Detected PII match."""
    pii_type: PIIType
    value: str
    start: int
    end: int
    confidence: float = 1.0  # 0.0 to 1.0
    context: Optional[str] = None


class PIIDetector:
    """Detects PII in text using pattern matching."""
    
    # Regex patterns for different PII types
    PATTERNS = {
        PIIType.EMAIL: r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        PIIType.PHONE: r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
        PIIType.SSN: r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
        PIIType.CREDIT_CARD: r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
        PIIType.IP_ADDRESS: r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        PIIType.PASSPORT: r'\b[A-Z]{1,2}[0-9]{6,9}\b',
        PIIType.DRIVERS_LICENSE: r'\b[A-Z]{1,2}[0-9]{5,8}\b',
    }
    
    # Name patterns (common first/last names)
    COMMON_FIRST_NAMES = {
        'john', 'jane', 'michael', 'sarah', 'david', 'emily', 'james', 'mary',
        'robert', 'patricia', 'william', 'jennifer', 'richard', 'linda'
    }
    
    def __init__(self, enabled_types: Optional[Set[PIIType]] = None):
        """
        Initialize PII detector.
        
        Args:
            enabled_types: Set of PII types to detect. If None, detect all types.
        """
        self.enabled_types = enabled_types or set(PIIType)
        self.compiled_patterns = {}
        
        # Compile regex patterns
        for pii_type, pattern in self.PATTERNS.items():
            if pii_type in self.enabled_types:
                try:
                    self.compiled_patterns[pii_type] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    logger.error(f"Failed to compile pattern for {pii_type}: {e}")
    
    def detect(self, text: str, context_chars: int = 20) -> List[PIIMatch]:
        """
        Detect PII in text.
        
        Args:
            text: Text to scan for PII
            context_chars: Number of characters to include in context
            
        Returns:
            List of PII matches
        """
        matches = []
        
        for pii_type, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(text):
                # Extract context
                start = max(0, match.start() - context_chars)
                end = min(len(text), match.end() + context_chars)
                context = text[start:end]
                
                # Calculate confidence
                confidence = self._calculate_confidence(pii_type, match.group())
                
                matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    context=context
                ))
        
        # Detect names (lower confidence)
        if PIIType.NAME in self.enabled_types:
            name_matches = self._detect_names(text, context_chars)
            matches.extend(name_matches)
        
        # Sort by position
        matches.sort(key=lambda m: m.start)
        
        return matches
    
    def _calculate_confidence(self, pii_type: PIIType, value: str) -> float:
        """Calculate confidence score for a match."""
        if pii_type == PIIType.EMAIL:
            # Higher confidence for common email domains
            if any(domain in value.lower() for domain in ['gmail.com', 'yahoo.com', 'outlook.com']):
                return 0.95
            return 0.85
        
        elif pii_type == PIIType.CREDIT_CARD:
            # Validate using Luhn algorithm
            if self._luhn_check(value.replace('-', '').replace(' ', '')):
                return 0.95
            return 0.7
        
        elif pii_type == PIIType.SSN:
            return 0.9
        
        elif pii_type == PIIType.PHONE:
            return 0.85
        
        elif pii_type == PIIType.IP_ADDRESS:
            # Lower confidence as IPs are common in logs
            return 0.6
        
        return 0.8
    
    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        try:
            digits = [int(d) for d in card_number]
            checksum = 0
            
            # Double every second digit from right
            for i in range(len(digits) - 2, -1, -2):
                digits[i] *= 2
                if digits[i] > 9:
                    digits[i] -= 9
            
            checksum = sum(digits)
            return checksum % 10 == 0
        except (ValueError, IndexError):
            return False
    
    def _detect_names(self, text: str, context_chars: int) -> List[PIIMatch]:
        """Detect potential names in text (lower confidence)."""
        matches = []
        
        # Simple pattern: Capitalized words that might be names
        # This is a basic implementation - production would use NER models
        name_pattern = r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b'
        
        for match in re.finditer(name_pattern, text):
            name = match.group()
            words = name.lower().split()
            
            # Check if first word is a common first name
            confidence = 0.3  # Low default confidence
            if words[0] in self.COMMON_FIRST_NAMES:
                confidence = 0.6
            
            # Extract context
            start = max(0, match.start() - context_chars)
            end = min(len(text), match.end() + context_chars)
            context = text[start:end]
            
            matches.append(PIIMatch(
                pii_type=PIIType.NAME,
                value=name,
                start=match.start(),
                end=match.end(),
                confidence=confidence,
                context=context
            ))
        
        return matches
    
    def has_pii(self, text: str, min_confidence: float = 0.7) -> bool:
        """
        Check if text contains PII above confidence threshold.
        
        Args:
            text: Text to check
            min_confidence: Minimum confidence threshold
            
        Returns:
            True if PII detected above threshold
        """
        matches = self.detect(text)
        return any(m.confidence >= min_confidence for m in matches)
    
    def get_pii_summary(self, text: str) -> Dict[PIIType, int]:
        """
        Get summary of PII types found in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary mapping PII types to count
        """
        matches = self.detect(text)
        summary = {}
        
        for match in matches:
            if match.confidence >= 0.7:  # Only count high-confidence matches
                summary[match.pii_type] = summary.get(match.pii_type, 0) + 1
        
        return summary
    
    def scan_dict(self, data: Dict, path: str = "") -> List[tuple]:
        """
        Recursively scan dictionary for PII.
        
        Args:
            data: Dictionary to scan
            path: Current path in dictionary (for reporting)
            
        Returns:
            List of (path, PIIMatch) tuples
        """
        results = []
        
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            if isinstance(value, str):
                matches = self.detect(value)
                for match in matches:
                    if match.confidence >= 0.7:
                        results.append((current_path, match))
            
            elif isinstance(value, dict):
                results.extend(self.scan_dict(value, current_path))
            
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        matches = self.detect(item)
                        for match in matches:
                            if match.confidence >= 0.7:
                                results.append((f"{current_path}[{i}]", match))
                    elif isinstance(item, dict):
                        results.extend(self.scan_dict(item, f"{current_path}[{i}]"))
        
        return results

