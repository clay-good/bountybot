"""
Relationship tracking between bug bounty reports.
"""

import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from collections import defaultdict

from .models import (
    ReportRelationship,
    RelationshipType,
    RelationshipGraph
)

logger = logging.getLogger(__name__)


class RelationshipTracker:
    """
    Tracks relationships between bug bounty reports.
    
    Features:
    - Relationship discovery
    - Graph construction
    - Community detection
    - Attack chain identification
    
    Example:
        >>> tracker = RelationshipTracker()
        >>> tracker.add_relationship(report1_id, report2_id, RelationshipType.SIMILAR)
        >>> graph = tracker.build_graph()
    """
    
    def __init__(self):
        """Initialize relationship tracker."""
        self.relationships: List[ReportRelationship] = []
        logger.info("RelationshipTracker initialized")
    
    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: RelationshipType,
        strength: float = 1.0,
        evidence: Optional[List[str]] = None
    ) -> ReportRelationship:
        """Add a relationship between reports."""
        relationship = ReportRelationship(
            source_report_id=source_id,
            target_report_id=target_id,
            relationship_type=relationship_type,
            strength=strength,
            evidence=evidence or [],
            metadata={}
        )
        
        self.relationships.append(relationship)
        logger.debug(f"Added relationship: {source_id} -> {target_id} ({relationship_type.value})")
        
        return relationship
    
    def get_relationships(
        self,
        report_id: str,
        relationship_type: Optional[RelationshipType] = None
    ) -> List[ReportRelationship]:
        """Get relationships for a report."""
        results = []
        
        for rel in self.relationships:
            if rel.source_report_id == report_id or rel.target_report_id == report_id:
                if relationship_type is None or rel.relationship_type == relationship_type:
                    results.append(rel)
        
        return results
    
    def build_graph(self) -> RelationshipGraph:
        """Build relationship graph."""
        # Extract all nodes
        nodes = set()
        for rel in self.relationships:
            nodes.add(rel.source_report_id)
            nodes.add(rel.target_report_id)
        
        # Detect communities (simple connected components)
        communities = self._detect_communities(list(nodes))
        
        return RelationshipGraph(
            nodes=list(nodes),
            edges=self.relationships,
            communities=communities,
            metadata={
                'node_count': len(nodes),
                'edge_count': len(self.relationships)
            }
        )
    
    def _detect_communities(self, nodes: List[str]) -> List[List[str]]:
        """Detect communities using connected components."""
        # Build adjacency list
        adj = defaultdict(set)
        for rel in self.relationships:
            adj[rel.source_report_id].add(rel.target_report_id)
            adj[rel.target_report_id].add(rel.source_report_id)
        
        # Find connected components
        visited = set()
        communities = []
        
        for node in nodes:
            if node in visited:
                continue
            
            # BFS to find component
            component = []
            queue = [node]
            visited.add(node)
            
            while queue:
                current = queue.pop(0)
                component.append(current)
                
                for neighbor in adj[current]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
            
            if len(component) > 1:
                communities.append(component)
        
        return communities
    
    def find_attack_chains(self) -> List[List[str]]:
        """Find attack chains (sequences of related vulnerabilities)."""
        chains = []
        
        # Find CHAIN relationships
        chain_rels = [
            r for r in self.relationships
            if r.relationship_type == RelationshipType.CHAIN
        ]
        
        if not chain_rels:
            return chains
        
        # Build chains
        visited = set()
        for rel in chain_rels:
            if rel.source_report_id in visited:
                continue
            
            chain = self._build_chain(rel.source_report_id, chain_rels)
            if len(chain) > 1:
                chains.append(chain)
                visited.update(chain)
        
        return chains
    
    def _build_chain(self, start_id: str, chain_rels: List[ReportRelationship]) -> List[str]:
        """Build chain starting from a report."""
        chain = [start_id]
        current = start_id
        
        while True:
            # Find next in chain
            next_rel = next(
                (r for r in chain_rels if r.source_report_id == current),
                None
            )
            
            if not next_rel:
                break
            
            chain.append(next_rel.target_report_id)
            current = next_rel.target_report_id
        
        return chain

