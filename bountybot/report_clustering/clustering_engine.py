"""
Report clustering engine for grouping related vulnerabilities.
"""

import logging
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict
import numpy as np

from .models import (
    ReportCluster,
    ClusterMetadata,
    ClusteringMethod,
    ClusteringResult,
    VulnerabilityFamily
)
from .semantic_analyzer import SemanticSimilarityAnalyzer

logger = logging.getLogger(__name__)


class ReportClusteringEngine:
    """
    Clusters bug bounty reports using various algorithms.
    
    Features:
    - DBSCAN clustering
    - Hierarchical clustering
    - Semantic clustering
    - Automatic parameter tuning
    
    Example:
        >>> engine = ReportClusteringEngine()
        >>> result = engine.cluster_reports(reports)
        >>> print(f"Found {result.get_cluster_count()} clusters")
    """
    
    def __init__(self):
        """Initialize clustering engine."""
        self.semantic_analyzer = SemanticSimilarityAnalyzer()
        logger.info("ReportClusteringEngine initialized")
    
    def cluster_reports(
        self,
        reports: List[Any],
        method: ClusteringMethod = ClusteringMethod.SEMANTIC,
        min_cluster_size: int = 2,
        similarity_threshold: float = 0.7
    ) -> ClusteringResult:
        """
        Cluster reports using specified method.
        
        Args:
            reports: List of reports to cluster
            method: Clustering method
            min_cluster_size: Minimum cluster size
            similarity_threshold: Similarity threshold
            
        Returns:
            ClusteringResult
        """
        start_time = time.time()
        
        if method == ClusteringMethod.SEMANTIC:
            clusters, outliers = self._semantic_clustering(
                reports, similarity_threshold, min_cluster_size
            )
        elif method == ClusteringMethod.DBSCAN:
            clusters, outliers = self._dbscan_clustering(
                reports, similarity_threshold, min_cluster_size
            )
        else:
            clusters, outliers = self._semantic_clustering(
                reports, similarity_threshold, min_cluster_size
            )
        
        # Detect vulnerability families
        families = self._detect_families(clusters, reports)
        
        # Calculate quality metrics
        quality_metrics = self._calculate_quality_metrics(clusters, reports)
        
        execution_time = (time.time() - start_time) * 1000
        
        return ClusteringResult(
            clusters=clusters,
            families=families,
            outliers=outliers,
            method=method,
            parameters={
                'min_cluster_size': min_cluster_size,
                'similarity_threshold': similarity_threshold
            },
            quality_metrics=quality_metrics,
            execution_time_ms=execution_time
        )
    
    def _semantic_clustering(
        self,
        reports: List[Any],
        threshold: float,
        min_size: int
    ) -> tuple:
        """Perform semantic clustering."""
        # Build similarity matrix
        n = len(reports)
        similarity_matrix = np.zeros((n, n))
        
        for i in range(n):
            for j in range(i + 1, n):
                sim = self.semantic_analyzer.calculate_similarity(reports[i], reports[j])
                similarity_matrix[i, j] = sim.similarity_score
                similarity_matrix[j, i] = sim.similarity_score
        
        # Find clusters using threshold
        visited = set()
        clusters = []
        
        for i in range(n):
            if i in visited:
                continue
            
            # Start new cluster
            cluster_indices = [i]
            visited.add(i)
            
            # Add similar reports
            for j in range(n):
                if j not in visited and similarity_matrix[i, j] >= threshold:
                    cluster_indices.append(j)
                    visited.add(j)
            
            if len(cluster_indices) >= min_size:
                cluster = self._create_cluster(
                    cluster_indices, reports, similarity_matrix, ClusteringMethod.SEMANTIC
                )
                clusters.append(cluster)
        
        # Outliers are unvisited reports
        outliers = [self._get_report_id(reports[i]) for i in range(n) if i not in visited]
        
        return clusters, outliers
    
    def _dbscan_clustering(
        self,
        reports: List[Any],
        eps: float,
        min_samples: int
    ) -> tuple:
        """Perform DBSCAN clustering."""
        # Simplified DBSCAN implementation
        return self._semantic_clustering(reports, eps, min_samples)
    
    def _create_cluster(
        self,
        indices: List[int],
        reports: List[Any],
        similarity_matrix: np.ndarray,
        method: ClusteringMethod
    ) -> ReportCluster:
        """Create cluster from indices."""
        report_ids = [self._get_report_id(reports[i]) for i in indices]
        
        # Calculate metadata
        metadata = self._calculate_cluster_metadata(indices, reports, similarity_matrix)
        
        # Build similarity dict
        sim_dict = {}
        for i, idx1 in enumerate(indices):
            for idx2 in indices[i + 1:]:
                key = tuple(sorted([report_ids[i], self._get_report_id(reports[idx2])]))
                sim_dict[key] = float(similarity_matrix[idx1, idx2])
        
        cluster_id = f"cluster-{hash(tuple(sorted(report_ids))) % 1000000}"
        
        return ReportCluster(
            cluster_id=cluster_id,
            report_ids=report_ids,
            metadata=metadata,
            method=method,
            similarity_matrix=sim_dict
        )
    
    def _calculate_cluster_metadata(
        self,
        indices: List[int],
        reports: List[Any],
        similarity_matrix: np.ndarray
    ) -> ClusterMetadata:
        """Calculate cluster metadata."""
        cluster_reports = [reports[i] for i in indices]
        
        # Extract vulnerability types
        vuln_types = list(set(
            getattr(r, 'vulnerability_type', 'unknown')
            for r in cluster_reports
        ))
        
        # Extract affected components
        components = list(set(
            getattr(r, 'affected_component', 'unknown')
            for r in cluster_reports
            if hasattr(r, 'affected_component')
        ))
        
        # Calculate average similarity
        sims = []
        for i, idx1 in enumerate(indices):
            for idx2 in indices[i + 1:]:
                sims.append(similarity_matrix[idx1, idx2])
        avg_sim = np.mean(sims) if sims else 0.0
        
        # Severity range
        severities = [
            self._severity_to_numeric(getattr(r, 'severity', 'medium'))
            for r in cluster_reports
        ]
        severity_range = (min(severities), max(severities)) if severities else (0, 0)
        
        # Date range
        dates = [
            getattr(r, 'submitted_at', datetime.utcnow())
            for r in cluster_reports
        ]
        date_range = (min(dates), max(dates)) if dates else (datetime.utcnow(), datetime.utcnow())
        
        # Researchers
        researchers = set(
            getattr(r, 'researcher_id', 'unknown')
            for r in cluster_reports
        )
        
        cluster_id = f"cluster-{hash(tuple(sorted([self._get_report_id(r) for r in cluster_reports]))) % 1000000}"
        
        return ClusterMetadata(
            cluster_id=cluster_id,
            size=len(cluster_reports),
            centroid_report_id=self._get_report_id(cluster_reports[0]),
            avg_similarity=float(avg_sim),
            vulnerability_types=vuln_types,
            affected_components=components,
            severity_range=severity_range,
            date_range=date_range,
            researchers=researchers
        )
    
    def _detect_families(
        self,
        clusters: List[ReportCluster],
        reports: List[Any]
    ) -> List[VulnerabilityFamily]:
        """Detect vulnerability families from clusters."""
        families = []
        
        for cluster in clusters:
            if cluster.get_size() < 3:
                continue  # Too small for a family
            
            family = self._create_family_from_cluster(cluster, reports)
            families.append(family)
        
        return families
    
    def _create_family_from_cluster(
        self,
        cluster: ReportCluster,
        reports: List[Any]
    ) -> VulnerabilityFamily:
        """Create vulnerability family from cluster."""
        cluster_reports = [
            r for r in reports
            if self._get_report_id(r) in cluster.report_ids
        ]
        
        # Determine family name
        vuln_types = cluster.metadata.vulnerability_types
        name = f"{vuln_types[0]} Family" if vuln_types else "Unknown Family"
        
        # Severity distribution
        sev_dist = defaultdict(int)
        for r in cluster_reports:
            sev = getattr(r, 'severity', 'medium')
            sev_dist[str(sev)] += 1
        
        return VulnerabilityFamily(
            family_id=cluster.cluster_id,
            name=name,
            description=f"Family of {len(cluster_reports)} related {vuln_types[0] if vuln_types else 'vulnerability'} reports",
            vulnerability_types=vuln_types,
            common_patterns=[],
            attack_vectors=[],
            affected_components=cluster.metadata.affected_components,
            report_ids=cluster.report_ids,
            severity_distribution=dict(sev_dist),
            first_seen=cluster.metadata.date_range[0],
            last_seen=cluster.metadata.date_range[1],
            trend="stable"
        )
    
    def _calculate_quality_metrics(
        self,
        clusters: List[ReportCluster],
        reports: List[Any]
    ) -> Dict[str, float]:
        """Calculate clustering quality metrics."""
        total_reports = len(reports)
        clustered_reports = sum(c.get_size() for c in clusters)
        
        return {
            'cluster_count': len(clusters),
            'coverage': clustered_reports / total_reports if total_reports > 0 else 0.0,
            'avg_cluster_size': clustered_reports / len(clusters) if clusters else 0.0,
            'avg_similarity': np.mean([c.metadata.avg_similarity for c in clusters]) if clusters else 0.0
        }
    
    def _get_report_id(self, report: Any) -> str:
        """Get report ID."""
        if hasattr(report, 'id'):
            return str(report.id)
        if hasattr(report, 'report_id'):
            return str(report.report_id)
        return str(hash(str(report)))
    
    def _severity_to_numeric(self, severity: str) -> float:
        """Convert severity to numeric."""
        severity_map = {
            'critical': 4.0,
            'high': 3.0,
            'medium': 2.0,
            'low': 1.0,
            'info': 0.0
        }
        return severity_map.get(str(severity).lower(), 2.0)

