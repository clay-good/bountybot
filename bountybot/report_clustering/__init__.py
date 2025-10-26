"""
Advanced Report Similarity & Clustering

Provides semantic similarity analysis and intelligent clustering of bug bounty reports:
- Semantic similarity using embeddings
- Report clustering by vulnerability families
- Relationship tracking between related reports
- Enhanced duplicate detection with ML
- Attack pattern grouping
- Trend identification

Features:
- Deep semantic analysis beyond text matching
- Hierarchical clustering of related reports
- Vulnerability family detection
- Attack campaign identification
- Temporal pattern analysis
- Cross-report relationship graphs

Example:
    >>> from bountybot.report_clustering import ReportClusteringEngine
    >>> 
    >>> engine = ReportClusteringEngine()
    >>> 
    >>> # Analyze semantic similarity
    >>> similarity = engine.calculate_semantic_similarity(report1, report2)
    >>> print(f"Semantic similarity: {similarity:.2f}")
    >>> 
    >>> # Cluster reports
    >>> clusters = engine.cluster_reports(reports)
    >>> print(f"Found {len(clusters)} vulnerability families")
"""

from .models import (
    SemanticSimilarity,
    ReportCluster,
    ClusterMetadata,
    RelationshipType,
    ReportRelationship,
    VulnerabilityFamily,
    ClusteringMethod
)

from .semantic_analyzer import SemanticSimilarityAnalyzer
from .clustering_engine import ReportClusteringEngine
from .relationship_tracker import RelationshipTracker
from .family_detector import VulnerabilityFamilyDetector

__all__ = [
    # Models
    'SemanticSimilarity',
    'ReportCluster',
    'ClusterMetadata',
    'RelationshipType',
    'ReportRelationship',
    'VulnerabilityFamily',
    'ClusteringMethod',
    
    # Core Components
    'SemanticSimilarityAnalyzer',
    'ReportClusteringEngine',
    'RelationshipTracker',
    'VulnerabilityFamilyDetector',
]

