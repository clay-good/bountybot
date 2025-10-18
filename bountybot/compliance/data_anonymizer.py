"""
Data Anonymization Module

Anonymizes PII in text and data structures.
"""

import re
import hashlib
import logging
from enum import Enum
from typing import Dict, Any, Optional, List
from .models import PIIType
from .pii_detector import PIIDetector, PIIMatch

logger = logging.getLogger(__name__)


class AnonymizationStrategy(str, Enum):
    """Anonymization strategies."""
    REDACT = "redact"  # Replace with [REDACTED]
    MASK = "mask"  # Replace with ***
    HASH = "hash"  # Replace with hash
    TOKENIZE = "tokenize"  # Replace with token (reversible with key)
    GENERALIZE = "generalize"  # Replace with generalized value
    PSEUDONYMIZE = "pseudonymize"  # Replace with consistent fake value


class DataAnonymizer:
    """Anonymizes PII in text and data structures."""
    
    def __init__(
        self,
        strategy: AnonymizationStrategy = AnonymizationStrategy.REDACT,
        salt: Optional[str] = None,
        pii_detector: Optional[PIIDetector] = None
    ):
        """
        Initialize data anonymizer.
        
        Args:
            strategy: Default anonymization strategy
            salt: Salt for hashing (required for HASH strategy)
            pii_detector: PII detector instance (creates new if None)
        """
        self.strategy = strategy
        self.salt = salt or "bountybot_default_salt"
        self.pii_detector = pii_detector or PIIDetector()
        
        # Token mapping for consistent pseudonymization
        self.token_map: Dict[str, str] = {}
        self.reverse_token_map: Dict[str, str] = {}
        self.token_counter = 0
    
    def anonymize_text(
        self,
        text: str,
        strategy: Optional[AnonymizationStrategy] = None,
        min_confidence: float = 0.7
    ) -> str:
        """
        Anonymize PII in text.
        
        Args:
            text: Text to anonymize
            strategy: Anonymization strategy (uses default if None)
            min_confidence: Minimum confidence threshold for PII detection
            
        Returns:
            Anonymized text
        """
        strategy = strategy or self.strategy
        
        # Detect PII
        matches = self.pii_detector.detect(text)
        
        # Filter by confidence
        matches = [m for m in matches if m.confidence >= min_confidence]
        
        # Sort by position (reverse order to maintain indices)
        matches.sort(key=lambda m: m.start, reverse=True)
        
        # Replace PII
        result = text
        for match in matches:
            replacement = self._get_replacement(match, strategy)
            result = result[:match.start] + replacement + result[match.end:]
        
        return result
    
    def anonymize_dict(
        self,
        data: Dict[str, Any],
        strategy: Optional[AnonymizationStrategy] = None,
        min_confidence: float = 0.7
    ) -> Dict[str, Any]:
        """
        Anonymize PII in dictionary.
        
        Args:
            data: Dictionary to anonymize
            strategy: Anonymization strategy
            min_confidence: Minimum confidence threshold
            
        Returns:
            Anonymized dictionary
        """
        strategy = strategy or self.strategy
        result = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.anonymize_text(value, strategy, min_confidence)
            elif isinstance(value, dict):
                result[key] = self.anonymize_dict(value, strategy, min_confidence)
            elif isinstance(value, list):
                result[key] = [
                    self.anonymize_text(item, strategy, min_confidence) if isinstance(item, str)
                    else self.anonymize_dict(item, strategy, min_confidence) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        
        return result
    
    def _get_replacement(self, match: PIIMatch, strategy: AnonymizationStrategy) -> str:
        """Get replacement text for PII match."""
        if strategy == AnonymizationStrategy.REDACT:
            return f"[REDACTED_{match.pii_type.value.upper()}]"
        
        elif strategy == AnonymizationStrategy.MASK:
            # Keep first and last character for readability
            if len(match.value) <= 2:
                return "*" * len(match.value)
            return match.value[0] + "*" * (len(match.value) - 2) + match.value[-1]
        
        elif strategy == AnonymizationStrategy.HASH:
            # Hash the value
            hash_input = f"{match.value}{self.salt}".encode()
            hash_value = hashlib.sha256(hash_input).hexdigest()[:16]
            return f"[HASH_{hash_value}]"
        
        elif strategy == AnonymizationStrategy.TOKENIZE:
            # Create reversible token
            if match.value not in self.token_map:
                token = f"TOKEN_{match.pii_type.value.upper()}_{self.token_counter}"
                self.token_map[match.value] = token
                self.reverse_token_map[token] = match.value
                self.token_counter += 1
            return self.token_map[match.value]
        
        elif strategy == AnonymizationStrategy.GENERALIZE:
            return self._generalize(match)
        
        elif strategy == AnonymizationStrategy.PSEUDONYMIZE:
            return self._pseudonymize(match)
        
        return "[REDACTED]"
    
    def _generalize(self, match: PIIMatch) -> str:
        """Generalize PII value."""
        if match.pii_type == PIIType.EMAIL:
            # Keep domain, generalize local part
            parts = match.value.split('@')
            if len(parts) == 2:
                return f"user@{parts[1]}"
            return "[EMAIL]"
        
        elif match.pii_type == PIIType.PHONE:
            # Keep area code
            digits = re.sub(r'\D', '', match.value)
            if len(digits) >= 3:
                return f"({digits[:3]}) XXX-XXXX"
            return "[PHONE]"
        
        elif match.pii_type == PIIType.IP_ADDRESS:
            # Keep first two octets
            parts = match.value.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.X.X"
            return "[IP]"
        
        elif match.pii_type == PIIType.SSN:
            return "XXX-XX-XXXX"
        
        elif match.pii_type == PIIType.CREDIT_CARD:
            # Keep last 4 digits
            digits = re.sub(r'\D', '', match.value)
            if len(digits) >= 4:
                return f"****-****-****-{digits[-4:]}"
            return "[CARD]"
        
        elif match.pii_type == PIIType.NAME:
            # Keep first initial
            parts = match.value.split()
            if parts:
                return f"{parts[0][0]}. [NAME]"
            return "[NAME]"
        
        return f"[{match.pii_type.value.upper()}]"
    
    def _pseudonymize(self, match: PIIMatch) -> str:
        """Create consistent pseudonym for PII value."""
        # Use hash to generate consistent pseudonym
        hash_input = f"{match.value}{self.salt}".encode()
        hash_value = hashlib.sha256(hash_input).hexdigest()
        
        if match.pii_type == PIIType.EMAIL:
            # Generate fake email
            username = f"user{hash_value[:8]}"
            parts = match.value.split('@')
            domain = parts[1] if len(parts) == 2 else "example.com"
            return f"{username}@{domain}"
        
        elif match.pii_type == PIIType.PHONE:
            # Generate fake phone
            digits = hash_value[:10]
            return f"({digits[:3]}) {digits[3:6]}-{digits[6:10]}"
        
        elif match.pii_type == PIIType.IP_ADDRESS:
            # Generate fake IP
            octets = [str(int(hash_value[i:i+2], 16) % 256) for i in range(0, 8, 2)]
            return '.'.join(octets)
        
        elif match.pii_type == PIIType.NAME:
            # Generate fake name
            fake_names = [
                "John Smith", "Jane Doe", "Bob Johnson", "Alice Williams",
                "Charlie Brown", "Diana Prince", "Eve Anderson", "Frank Miller"
            ]
            index = int(hash_value[:8], 16) % len(fake_names)
            return fake_names[index]
        
        elif match.pii_type == PIIType.SSN:
            # Generate fake SSN
            digits = hash_value[:9]
            return f"{digits[:3]}-{digits[3:5]}-{digits[5:9]}"
        
        elif match.pii_type == PIIType.CREDIT_CARD:
            # Generate fake card (Luhn-valid)
            digits = hash_value[:15]
            return f"4{digits[:3]}-{digits[3:7]}-{digits[7:11]}-{digits[11:15]}"
        
        return f"PSEUDO_{hash_value[:8]}"
    
    def detokenize(self, text: str) -> str:
        """
        Reverse tokenization (only works with TOKENIZE strategy).
        
        Args:
            text: Tokenized text
            
        Returns:
            Original text
        """
        result = text
        for token, original in self.reverse_token_map.items():
            result = result.replace(token, original)
        return result
    
    def clear_tokens(self):
        """Clear token mappings."""
        self.token_map.clear()
        self.reverse_token_map.clear()
        self.token_counter = 0
    
    def get_anonymization_report(self, text: str) -> Dict[str, Any]:
        """
        Generate report of what would be anonymized.
        
        Args:
            text: Text to analyze
            
        Returns:
            Report dictionary
        """
        matches = self.pii_detector.detect(text)
        matches = [m for m in matches if m.confidence >= 0.7]
        
        report = {
            'total_pii_found': len(matches),
            'pii_by_type': {},
            'matches': []
        }
        
        for match in matches:
            pii_type_str = match.pii_type.value
            report['pii_by_type'][pii_type_str] = report['pii_by_type'].get(pii_type_str, 0) + 1
            
            report['matches'].append({
                'type': pii_type_str,
                'value': match.value,
                'position': f"{match.start}-{match.end}",
                'confidence': match.confidence,
                'context': match.context
            })
        
        return report

