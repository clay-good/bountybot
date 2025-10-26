"""
Semantic similarity analysis for bug bounty reports.
"""

import logging
import hashlib
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from collections import defaultdict

from .models import SemanticSimilarity, SimilarityAnalysis

logger = logging.getLogger(__name__)


class SemanticSimilarityAnalyzer:
    """
    Analyzes semantic similarity between bug bounty reports.
    
    Uses multiple techniques:
    - Text embeddings (TF-IDF, word2vec-style)
    - Structural similarity
    - Temporal proximity
    - Vulnerability pattern matching
    
    Example:
        >>> analyzer = SemanticSimilarityAnalyzer()
        >>> similarity = analyzer.calculate_similarity(report1, report2)
        >>> print(f"Similarity: {similarity.similarity_score:.2f}")
    """
    
    def __init__(self):
        """Initialize semantic similarity analyzer."""
        self.report_embeddings: Dict[str, np.ndarray] = {}
        self.vocabulary: Dict[str, int] = {}
        self.idf_scores: Dict[str, float] = {}
        logger.info("SemanticSimilarityAnalyzer initialized")
    
    def calculate_similarity(
        self,
        report1: Any,
        report2: Any,
        report1_id: Optional[str] = None,
        report2_id: Optional[str] = None
    ) -> SemanticSimilarity:
        """
        Calculate semantic similarity between two reports.
        
        Args:
            report1: First report
            report2: Second report
            report1_id: Optional ID for first report
            report2_id: Optional ID for second report
            
        Returns:
            SemanticSimilarity object
        """
        # Generate IDs if not provided
        if not report1_id:
            report1_id = self._generate_id(report1)
        if not report2_id:
            report2_id = self._generate_id(report2)
        
        # Generate embeddings
        emb1 = self._get_or_create_embedding(report1, report1_id)
        emb2 = self._get_or_create_embedding(report2, report2_id)
        
        # Calculate cosine similarity
        similarity_score = self._cosine_similarity(emb1, emb2)
        
        # Calculate euclidean distance
        embedding_distance = float(np.linalg.norm(emb1 - emb2))
        
        # Extract semantic features
        semantic_features = self._extract_semantic_features(report1, report2)
        
        # Calculate confidence
        confidence = self._calculate_confidence(similarity_score, semantic_features)
        
        return SemanticSimilarity(
            report1_id=report1_id,
            report2_id=report2_id,
            similarity_score=similarity_score,
            embedding_distance=embedding_distance,
            semantic_features=semantic_features,
            confidence=confidence,
            method="cosine"
        )
    
    def analyze_similarity(
        self,
        report: Any,
        candidate_reports: List[Any],
        report_id: Optional[str] = None,
        threshold: float = 0.7
    ) -> SimilarityAnalysis:
        """
        Analyze similarity of a report against candidates.
        
        Args:
            report: Report to analyze
            candidate_reports: List of candidate reports
            report_id: Optional report ID
            threshold: Similarity threshold
            
        Returns:
            SimilarityAnalysis object
        """
        if not report_id:
            report_id = self._generate_id(report)
        
        # Calculate similarities
        similarities = []
        for candidate in candidate_reports:
            candidate_id = self._generate_id(candidate)
            if candidate_id == report_id:
                continue
            
            sim = self.calculate_similarity(report, candidate, report_id, candidate_id)
            if sim.similarity_score >= threshold:
                similarities.append((candidate_id, sim.similarity_score))
        
        # Sort by similarity
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        # Get best match for detailed analysis
        best_semantic_sim = None
        if similarities:
            best_candidate_id = similarities[0][0]
            best_candidate = next(
                (c for c in candidate_reports if self._generate_id(c) == best_candidate_id),
                None
            )
            if best_candidate:
                best_semantic_sim = self.calculate_similarity(report, best_candidate, report_id, best_candidate_id)
        
        # Calculate component similarities
        text_sim = self._calculate_text_similarity(report, candidate_reports)
        structural_sim = self._calculate_structural_similarity(report, candidate_reports)
        temporal_prox = self._calculate_temporal_proximity(report, candidate_reports)
        
        # Overall similarity (weighted average)
        overall_sim = (
            0.5 * (similarities[0][1] if similarities else 0.0) +
            0.2 * text_sim +
            0.2 * structural_sim +
            0.1 * temporal_prox
        )
        
        # Determine if duplicate or related
        is_duplicate = overall_sim >= 0.9
        is_related = overall_sim >= 0.7
        
        # Generate reasoning
        reasoning = self._generate_reasoning(
            overall_sim, text_sim, structural_sim, temporal_prox, similarities
        )
        
        return SimilarityAnalysis(
            report_id=report_id,
            similar_reports=similarities[:10],  # Top 10
            semantic_similarity=best_semantic_sim,
            text_similarity=text_sim,
            structural_similarity=structural_sim,
            temporal_proximity=temporal_prox,
            overall_similarity=overall_sim,
            is_duplicate=is_duplicate,
            is_related=is_related,
            confidence=0.85,
            reasoning=reasoning
        )
    
    def _get_or_create_embedding(self, report: Any, report_id: str) -> np.ndarray:
        """Get or create embedding for report."""
        if report_id in self.report_embeddings:
            return self.report_embeddings[report_id]
        
        embedding = self._create_embedding(report)
        self.report_embeddings[report_id] = embedding
        return embedding
    
    def _create_embedding(self, report: Any) -> np.ndarray:
        """Create embedding for report using TF-IDF-like approach."""
        # Extract text
        text = self._extract_text(report)
        
        # Tokenize
        tokens = self._tokenize(text)
        
        # Create TF-IDF vector (simplified)
        embedding_dim = 128
        embedding = np.zeros(embedding_dim)
        
        # Hash tokens to embedding dimensions
        for token in tokens:
            idx = hash(token) % embedding_dim
            embedding[idx] += 1.0
        
        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        
        return embedding
    
    def _extract_text(self, report: Any) -> str:
        """Extract text from report."""
        parts = []
        
        if hasattr(report, 'title'):
            parts.append(report.title or "")
        if hasattr(report, 'description'):
            parts.append(report.description or "")
        if hasattr(report, 'vulnerability_type'):
            parts.append(report.vulnerability_type or "")
        if hasattr(report, 'affected_component'):
            parts.append(report.affected_component or "")
        
        return " ".join(parts).lower()
    
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text."""
        # Simple tokenization
        tokens = text.lower().split()
        # Remove short tokens
        tokens = [t for t in tokens if len(t) > 2]
        return tokens
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity."""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return float(dot_product / (norm1 * norm2))
    
    def _extract_semantic_features(self, report1: Any, report2: Any) -> Dict[str, float]:
        """Extract semantic features."""
        features = {}
        
        # Vulnerability type match
        if hasattr(report1, 'vulnerability_type') and hasattr(report2, 'vulnerability_type'):
            features['vuln_type_match'] = 1.0 if report1.vulnerability_type == report2.vulnerability_type else 0.0
        
        # Component match
        if hasattr(report1, 'affected_component') and hasattr(report2, 'affected_component'):
            features['component_match'] = 1.0 if report1.affected_component == report2.affected_component else 0.0
        
        # Severity proximity
        if hasattr(report1, 'severity') and hasattr(report2, 'severity'):
            sev1 = self._severity_to_numeric(report1.severity)
            sev2 = self._severity_to_numeric(report2.severity)
            features['severity_proximity'] = 1.0 - abs(sev1 - sev2) / 4.0
        
        return features
    
    def _severity_to_numeric(self, severity: str) -> float:
        """Convert severity to numeric value."""
        severity_map = {
            'critical': 4.0,
            'high': 3.0,
            'medium': 2.0,
            'low': 1.0,
            'info': 0.0
        }
        return severity_map.get(str(severity).lower(), 2.0)
    
    def _calculate_confidence(self, similarity_score: float, features: Dict[str, float]) -> float:
        """Calculate confidence in similarity score."""
        # Higher confidence if multiple features agree
        feature_agreement = sum(features.values()) / max(len(features), 1)
        confidence = 0.7 * similarity_score + 0.3 * feature_agreement
        return min(1.0, confidence)
    
    def _calculate_text_similarity(self, report: Any, candidates: List[Any]) -> float:
        """Calculate text similarity."""
        if not candidates:
            return 0.0
        
        text1 = self._extract_text(report)
        tokens1 = set(self._tokenize(text1))
        
        max_sim = 0.0
        for candidate in candidates:
            text2 = self._extract_text(candidate)
            tokens2 = set(self._tokenize(text2))
            
            # Jaccard similarity
            intersection = len(tokens1 & tokens2)
            union = len(tokens1 | tokens2)
            sim = intersection / union if union > 0 else 0.0
            max_sim = max(max_sim, sim)
        
        return max_sim
    
    def _calculate_structural_similarity(self, report: Any, candidates: List[Any]) -> float:
        """Calculate structural similarity."""
        # Placeholder - would analyze report structure
        return 0.5
    
    def _calculate_temporal_proximity(self, report: Any, candidates: List[Any]) -> float:
        """Calculate temporal proximity."""
        # Placeholder - would analyze submission times
        return 0.5
    
    def _generate_reasoning(
        self,
        overall_sim: float,
        text_sim: float,
        structural_sim: float,
        temporal_prox: float,
        similarities: List[tuple]
    ) -> List[str]:
        """Generate reasoning for similarity analysis."""
        reasoning = []
        
        if overall_sim >= 0.9:
            reasoning.append("Very high overall similarity - likely duplicate")
        elif overall_sim >= 0.7:
            reasoning.append("High similarity - reports are related")
        
        if text_sim >= 0.8:
            reasoning.append(f"High text similarity ({text_sim:.2f})")
        
        if similarities:
            reasoning.append(f"Found {len(similarities)} similar reports")
        
        return reasoning
    
    def _generate_id(self, report: Any) -> str:
        """Generate ID for report."""
        text = self._extract_text(report)
        return hashlib.md5(text.encode()).hexdigest()[:16]

