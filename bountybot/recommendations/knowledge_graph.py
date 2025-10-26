"""
Knowledge Graph - Graph database for vulnerability relationships and patterns.
"""

import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

from bountybot.recommendations.models import (
    KnowledgeNode,
    KnowledgeEdge,
    EdgeType,
)


logger = logging.getLogger(__name__)


@dataclass
class GraphQuery:
    """A query for the knowledge graph."""
    node_type: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    edge_types: List[EdgeType] = field(default_factory=list)
    max_depth: int = 2
    limit: int = 10
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'node_type': self.node_type,
            'properties': self.properties,
            'edge_types': [et.value for et in self.edge_types],
            'max_depth': self.max_depth,
            'limit': self.limit,
        }


class KnowledgeGraph:
    """
    Knowledge graph for storing and querying vulnerability relationships,
    remediation patterns, and security knowledge.
    """
    
    def __init__(self):
        """Initialize knowledge graph."""
        # Graph storage
        self.nodes: Dict[str, KnowledgeNode] = {}
        self.edges: Dict[str, KnowledgeEdge] = {}
        
        # Indexes for fast lookup
        self.node_type_index: Dict[str, Set[str]] = {}
        self.edge_type_index: Dict[EdgeType, Set[str]] = {}
        self.outgoing_edges: Dict[str, Set[str]] = {}  # node_id -> edge_ids
        self.incoming_edges: Dict[str, Set[str]] = {}  # node_id -> edge_ids
        
        # Statistics
        self.stats = {
            'total_nodes': 0,
            'total_edges': 0,
            'node_types': set(),
            'edge_types': set(),
        }
    
    def add_node(self, node: KnowledgeNode) -> str:
        """
        Add a node to the graph.
        
        Args:
            node: Node to add
            
        Returns:
            Node ID
        """
        self.nodes[node.node_id] = node
        
        # Update indexes
        if node.node_type not in self.node_type_index:
            self.node_type_index[node.node_type] = set()
        self.node_type_index[node.node_type].add(node.node_id)
        
        # Update statistics
        self.stats['total_nodes'] += 1
        self.stats['node_types'].add(node.node_type)
        
        logger.debug(f"Added node: {node.name} ({node.node_type})")
        return node.node_id
    
    def add_edge(self, edge: KnowledgeEdge) -> str:
        """
        Add an edge to the graph.
        
        Args:
            edge: Edge to add
            
        Returns:
            Edge ID
        """
        # Validate nodes exist
        if edge.source_node_id not in self.nodes:
            raise ValueError(f"Source node {edge.source_node_id} not found")
        if edge.target_node_id not in self.nodes:
            raise ValueError(f"Target node {edge.target_node_id} not found")
        
        self.edges[edge.edge_id] = edge
        
        # Update indexes
        if edge.edge_type not in self.edge_type_index:
            self.edge_type_index[edge.edge_type] = set()
        self.edge_type_index[edge.edge_type].add(edge.edge_id)
        
        # Update adjacency lists
        if edge.source_node_id not in self.outgoing_edges:
            self.outgoing_edges[edge.source_node_id] = set()
        self.outgoing_edges[edge.source_node_id].add(edge.edge_id)
        
        if edge.target_node_id not in self.incoming_edges:
            self.incoming_edges[edge.target_node_id] = set()
        self.incoming_edges[edge.target_node_id].add(edge.edge_id)
        
        # Update statistics
        self.stats['total_edges'] += 1
        self.stats['edge_types'].add(edge.edge_type.value)
        
        logger.debug(f"Added edge: {edge.edge_type.value} from {edge.source_node_id} to {edge.target_node_id}")
        return edge.edge_id
    
    def get_node(self, node_id: str) -> Optional[KnowledgeNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def get_edge(self, edge_id: str) -> Optional[KnowledgeEdge]:
        """Get an edge by ID."""
        return self.edges.get(edge_id)
    
    def find_nodes(
        self,
        node_type: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        tags: Optional[Set[str]] = None,
        limit: int = 100,
    ) -> List[KnowledgeNode]:
        """
        Find nodes matching criteria.
        
        Args:
            node_type: Filter by node type
            properties: Filter by properties
            tags: Filter by tags
            limit: Maximum results
            
        Returns:
            List of matching nodes
        """
        # Start with all nodes or filtered by type
        if node_type:
            candidate_ids = self.node_type_index.get(node_type, set())
            candidates = [self.nodes[nid] for nid in candidate_ids]
        else:
            candidates = list(self.nodes.values())
        
        # Filter by properties
        if properties:
            candidates = [
                node for node in candidates
                if all(node.properties.get(k) == v for k, v in properties.items())
            ]
        
        # Filter by tags
        if tags:
            candidates = [
                node for node in candidates
                if tags.issubset(node.tags)
            ]
        
        return candidates[:limit]
    
    def find_similar_vulnerabilities(
        self,
        vulnerability_type: str,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Find similar vulnerabilities.
        
        Args:
            vulnerability_type: Type of vulnerability
            limit: Maximum results
            
        Returns:
            List of similar vulnerabilities with metadata
        """
        # Find vulnerability nodes
        vuln_nodes = self.find_nodes(
            node_type='vulnerability',
            properties={'type': vulnerability_type},
            limit=limit,
        )
        
        results = []
        for node in vuln_nodes:
            # Get related information
            related_fixes = self.get_related_nodes(node.node_id, EdgeType.FIXES)
            related_exploits = self.get_related_nodes(node.node_id, EdgeType.EXPLOITS)
            
            results.append({
                'node_id': node.node_id,
                'name': node.name,
                'description': node.description,
                'properties': node.properties,
                'related_fixes': len(related_fixes),
                'related_exploits': len(related_exploits),
            })
        
        return results
    
    def get_related_nodes(
        self,
        node_id: str,
        edge_type: Optional[EdgeType] = None,
        direction: str = 'outgoing',
    ) -> List[KnowledgeNode]:
        """
        Get nodes related to a given node.
        
        Args:
            node_id: Source node ID
            edge_type: Filter by edge type
            direction: 'outgoing', 'incoming', or 'both'
            
        Returns:
            List of related nodes
        """
        related_node_ids = set()
        
        # Get outgoing edges
        if direction in ['outgoing', 'both']:
            edge_ids = self.outgoing_edges.get(node_id, set())
            for edge_id in edge_ids:
                edge = self.edges[edge_id]
                if edge_type is None or edge.edge_type == edge_type:
                    related_node_ids.add(edge.target_node_id)
        
        # Get incoming edges
        if direction in ['incoming', 'both']:
            edge_ids = self.incoming_edges.get(node_id, set())
            for edge_id in edge_ids:
                edge = self.edges[edge_id]
                if edge_type is None or edge.edge_type == edge_type:
                    related_node_ids.add(edge.source_node_id)
        
        return [self.nodes[nid] for nid in related_node_ids if nid in self.nodes]
    
    def find_path(
        self,
        start_node_id: str,
        end_node_id: str,
        max_depth: int = 5,
    ) -> Optional[List[str]]:
        """
        Find shortest path between two nodes.
        
        Args:
            start_node_id: Start node ID
            end_node_id: End node ID
            max_depth: Maximum path length
            
        Returns:
            List of node IDs forming the path, or None if no path found
        """
        if start_node_id not in self.nodes or end_node_id not in self.nodes:
            return None
        
        # BFS to find shortest path
        queue = [(start_node_id, [start_node_id])]
        visited = {start_node_id}
        
        while queue:
            current_id, path = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            if current_id == end_node_id:
                return path
            
            # Get neighbors
            neighbors = self.get_related_nodes(current_id, direction='outgoing')
            
            for neighbor in neighbors:
                if neighbor.node_id not in visited:
                    visited.add(neighbor.node_id)
                    queue.append((neighbor.node_id, path + [neighbor.node_id]))
        
        return None
    
    def query(self, query: GraphQuery) -> List[KnowledgeNode]:
        """
        Execute a graph query.
        
        Args:
            query: Query to execute
            
        Returns:
            List of matching nodes
        """
        return self.find_nodes(
            node_type=query.node_type,
            properties=query.properties,
            limit=query.limit,
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge graph statistics."""
        return {
            'total_nodes': self.stats['total_nodes'],
            'total_edges': self.stats['total_edges'],
            'node_types': list(self.stats['node_types']),
            'edge_types': list(self.stats['edge_types']),
            'avg_edges_per_node': (
                self.stats['total_edges'] / self.stats['total_nodes']
                if self.stats['total_nodes'] > 0 else 0
            ),
        }
    
    def export_graph(self) -> Dict[str, Any]:
        """Export graph to dictionary format."""
        return {
            'nodes': [node.to_dict() for node in self.nodes.values()],
            'edges': [edge.to_dict() for edge in self.edges.values()],
            'stats': self.get_stats(),
        }
    
    def import_graph(self, data: Dict[str, Any]) -> None:
        """Import graph from dictionary format."""
        # Import nodes
        for node_data in data.get('nodes', []):
            node = KnowledgeNode(
                node_id=node_data['node_id'],
                node_type=node_data['node_type'],
                name=node_data['name'],
                description=node_data['description'],
                properties=node_data['properties'],
                tags=set(node_data.get('tags', [])),
            )
            self.add_node(node)
        
        # Import edges
        for edge_data in data.get('edges', []):
            edge = KnowledgeEdge(
                edge_id=edge_data['edge_id'],
                edge_type=EdgeType(edge_data['edge_type']),
                source_node_id=edge_data['source_node_id'],
                target_node_id=edge_data['target_node_id'],
                weight=edge_data.get('weight', 1.0),
                properties=edge_data.get('properties', {}),
                confidence=edge_data.get('confidence', 1.0),
            )
            self.add_edge(edge)
        
        logger.info(f"Imported graph with {len(data.get('nodes', []))} nodes and {len(data.get('edges', []))} edges")

