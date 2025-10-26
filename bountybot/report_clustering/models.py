"""
Data models for report clustering and similarity analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from enum import Enum


class ClusteringMethod(Enum):
    """Clustering algorithm method."""
    DBSCAN = "dbscan"
    HIERARCHICAL = "hierarchical"
    KMEANS = "kmeans"
    SEMANTIC = "semantic"


class RelationshipType(Enum):
    """Type of relationship between reports."""
    DUPLICATE = "duplicate"
    SIMILAR = "similar"
    RELATED = "related"
    CHAIN = "chain"  # Part of attack chain
    FAMILY = "family"  # Same vulnerability family
    CAMPAIGN = "campaign"  # Part of coordinated campaign


@dataclass
class SemanticSimilarity:
    """Semantic similarity between two reports."""
    report1_id: str
    report2_id: str
    similarity_score: float  # 0-1
    embedding_distance: float
    semantic_features: Dict[str, float]
    confidence: float
    method: str  # "cosine", "euclidean", "transformer"
    calculated_at: datetime = field(default_factory=datetime.utcnow)
    
    def is_highly_similar(self, threshold: float = 0.85) -> bool:
        """Check if reports are highly similar."""
        return self.similarity_score >= threshold


@dataclass
class ReportRelationship:
    """Relationship between two reports."""
    source_report_id: str
    target_report_id: str
    relationship_type: RelationshipType
    strength: float  # 0-1
    evidence: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ClusterMetadata:
    """Metadata about a report cluster."""
    cluster_id: str
    size: int
    centroid_report_id: Optional[str]
    avg_similarity: float
    vulnerability_types: List[str]
    affected_components: List[str]
    severity_range: tuple  # (min, max)
    date_range: tuple  # (earliest, latest)
    researchers: Set[str]
    tags: List[str] = field(default_factory=list)


@dataclass
class ReportCluster:
    """Cluster of related reports."""
    cluster_id: str
    report_ids: List[str]
    metadata: ClusterMetadata
    method: ClusteringMethod
    similarity_matrix: Dict[tuple, float] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def get_size(self) -> int:
        """Get cluster size."""
        return len(self.report_ids)
    
    def contains_report(self, report_id: str) -> bool:
        """Check if cluster contains report."""
        return report_id in self.report_ids
    
    def get_similarity(self, report1_id: str, report2_id: str) -> Optional[float]:
        """Get similarity between two reports in cluster."""
        key = tuple(sorted([report1_id, report2_id]))
        return self.similarity_matrix.get(key)


@dataclass
class VulnerabilityFamily:
    """Family of related vulnerabilities."""
    family_id: str
    name: str
    description: str
    vulnerability_types: List[str]
    common_patterns: List[str]
    attack_vectors: List[str]
    affected_components: List[str]
    report_ids: List[str]
    severity_distribution: Dict[str, int]  # severity -> count
    first_seen: datetime
    last_seen: datetime
    trend: str  # "increasing", "stable", "decreasing"
    
    def get_report_count(self) -> int:
        """Get number of reports in family."""
        return len(self.report_ids)
    
    def is_active(self, days: int = 30) -> bool:
        """Check if family has recent activity."""
        return (datetime.utcnow() - self.last_seen).days <= days


@dataclass
class ClusteringResult:
    """Result of clustering analysis."""
    clusters: List[ReportCluster]
    families: List[VulnerabilityFamily]
    outliers: List[str]  # Report IDs that don't fit any cluster
    method: ClusteringMethod
    parameters: Dict[str, Any]
    quality_metrics: Dict[str, float]
    execution_time_ms: float
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def get_cluster_count(self) -> int:
        """Get number of clusters."""
        return len(self.clusters)
    
    def get_family_count(self) -> int:
        """Get number of vulnerability families."""
        return len(self.families)
    
    def get_outlier_count(self) -> int:
        """Get number of outliers."""
        return len(self.outliers)


@dataclass
class RelationshipGraph:
    """Graph of relationships between reports."""
    nodes: List[str]  # Report IDs
    edges: List[ReportRelationship]
    communities: List[List[str]]  # Groups of highly connected reports
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_node_count(self) -> int:
        """Get number of nodes."""
        return len(self.nodes)
    
    def get_edge_count(self) -> int:
        """Get number of edges."""
        return len(self.edges)
    
    def get_neighbors(self, report_id: str) -> List[str]:
        """Get neighboring reports."""
        neighbors = []
        for edge in self.edges:
            if edge.source_report_id == report_id:
                neighbors.append(edge.target_report_id)
            elif edge.target_report_id == report_id:
                neighbors.append(edge.source_report_id)
        return list(set(neighbors))
    
    def get_relationships(self, report_id: str) -> List[ReportRelationship]:
        """Get all relationships for a report."""
        return [
            edge for edge in self.edges
            if edge.source_report_id == report_id or edge.target_report_id == report_id
        ]


@dataclass
class SimilarityAnalysis:
    """Comprehensive similarity analysis result."""
    report_id: str
    similar_reports: List[tuple]  # (report_id, similarity_score)
    semantic_similarity: Optional[SemanticSimilarity]
    text_similarity: float
    structural_similarity: float
    temporal_proximity: float
    overall_similarity: float
    is_duplicate: bool
    is_related: bool
    confidence: float
    reasoning: List[str]
    analyzed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TrendAnalysis:
    """Trend analysis for vulnerability families."""
    family_id: str
    time_period_days: int
    report_count: int
    growth_rate: float  # Percentage change
    velocity: float  # Reports per day
    acceleration: float  # Change in velocity
    trend_direction: str  # "up", "down", "stable"
    forecast_next_30_days: int
    confidence: float
    analyzed_at: datetime = field(default_factory=datetime.utcnow)

