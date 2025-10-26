"""
Transformer-based Code Analysis Module

This module provides transformer models for code understanding and vulnerability detection.
Uses pre-trained models like CodeBERT for semantic code analysis.
"""

from bountybot.ml.transformers.models import (
    TransformerConfig,
    CodeAnalysisResult,
    VulnerabilityPattern,
    CodeEmbedding,
    SimilarityScore,
    ProgrammingLanguage,
    VulnerabilityPatternType
)

from bountybot.ml.transformers.code_analyzer import CodeAnalyzer
from bountybot.ml.transformers.code_tokenizer import CodeTokenizer
from bountybot.ml.transformers.vulnerability_detector import VulnerabilityDetector
from bountybot.ml.transformers.code_embeddings import CodeEmbeddings

__all__ = [
    "TransformerConfig",
    "CodeAnalysisResult",
    "VulnerabilityPattern",
    "CodeEmbedding",
    "SimilarityScore",
    "ProgrammingLanguage",
    "VulnerabilityPatternType",
    "CodeAnalyzer",
    "CodeTokenizer",
    "VulnerabilityDetector",
    "CodeEmbeddings",
]

