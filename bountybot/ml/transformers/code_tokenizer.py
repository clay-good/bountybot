"""Code tokenizer for transformer models."""

import re
import logging
from typing import List

from bountybot.ml.transformers.models import ProgrammingLanguage, TransformerConfig

logger = logging.getLogger(__name__)


class CodeTokenizer:
    """Tokenizer for source code."""
    
    def __init__(self, config: TransformerConfig):
        self.config = config
        self.max_length = config.max_sequence_length
    
    def tokenize(self, code: str, language: ProgrammingLanguage) -> List[str]:
        """Tokenize source code."""
        # Simple tokenization (in production, use proper tokenizer like CodeBERT tokenizer)
        tokens = re.findall(r'\b\w+\b|[^\w\s]', code)
        return tokens[:self.max_length]
    
    def encode(self, code: str, language: ProgrammingLanguage) -> List[int]:
        """Encode code to token IDs."""
        tokens = self.tokenize(code, language)
        # Simplified encoding (in production, use proper vocabulary)
        return [hash(token) % 50000 for token in tokens]
    
    def decode(self, token_ids: List[int]) -> str:
        """Decode token IDs to code."""
        # Simplified decoding
        return " ".join(str(tid) for tid in token_ids)

