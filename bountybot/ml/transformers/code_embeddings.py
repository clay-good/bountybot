"""Code embeddings using transformer models."""

import logging
import numpy as np
from typing import List

from bountybot.ml.transformers.models import (
    ProgrammingLanguage,
    CodeEmbedding,
    TransformerConfig
)
from bountybot.ml.transformers.code_tokenizer import CodeTokenizer

logger = logging.getLogger(__name__)


class CodeEmbeddings:
    """Generate code embeddings using transformers."""
    
    def __init__(self, config: TransformerConfig):
        self.config = config
        self.tokenizer = CodeTokenizer(config)
        self.embedding_dim = config.embedding_dim
    
    def generate_embedding(
        self,
        code: str,
        language: ProgrammingLanguage
    ) -> CodeEmbedding:
        """Generate embedding for code."""
        tokens = self.tokenizer.tokenize(code, language)
        
        # Simplified embedding (in production, use CodeBERT/GraphCodeBERT)
        embedding_vector = self._simple_embedding(tokens)
        
        return CodeEmbedding(
            embedding_vector=embedding_vector,
            tokens=tokens,
            model_name=self.config.model_name
        )
    
    def _simple_embedding(self, tokens: List[str]) -> List[float]:
        """Generate simple embedding (placeholder for real transformer)."""
        # In production, use actual transformer model
        embedding = np.random.randn(self.embedding_dim).tolist()
        return embedding
    
    def calculate_similarity(
        self,
        code1: str,
        code2: str,
        language: ProgrammingLanguage
    ) -> float:
        """Calculate cosine similarity between two code snippets."""
        emb1 = self.generate_embedding(code1, language)
        emb2 = self.generate_embedding(code2, language)
        
        # Cosine similarity
        vec1 = np.array(emb1.embedding_vector)
        vec2 = np.array(emb2.embedding_vector)
        
        similarity = np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2))
        return float(similarity)

