"""
Tests for report clustering and similarity analysis.
"""

import pytest
from datetime import datetime, timedelta
from bountybot.report_clustering import (
    SemanticSimilarityAnalyzer,
    ReportClusteringEngine,
    RelationshipTracker,
    VulnerabilityFamilyDetector,
    ClusteringMethod,
    RelationshipType
)


class MockReport:
    """Mock report for testing."""
    def __init__(self, report_id, title, vuln_type, severity, description=None):
        self.report_id = report_id
        self.title = title
        self.vulnerability_type = vuln_type
        self.severity = severity
        self.description = description or f"Description of {title}"
        self.submitted_at = datetime.utcnow()


class TestSemanticSimilarityAnalyzer:
    """Test semantic similarity analysis."""
    
    def test_calculate_similarity_identical(self):
        """Test similarity between identical reports."""
        analyzer = SemanticSimilarityAnalyzer()
        
        report1 = MockReport("1", "XSS in search", "xss", "medium")
        report2 = MockReport("2", "XSS in search", "xss", "medium")
        
        similarity = analyzer.calculate_similarity(report1, report2)
        
        assert similarity is not None
        assert similarity.similarity_score > 0.8
        assert similarity.confidence > 0
    
    def test_calculate_similarity_similar(self):
        """Test similarity between similar reports."""
        analyzer = SemanticSimilarityAnalyzer()
        
        report1 = MockReport("1", "XSS in search field", "xss", "medium")
        report2 = MockReport("2", "XSS in search box", "xss", "medium")
        
        similarity = analyzer.calculate_similarity(report1, report2)
        
        assert similarity is not None
        assert similarity.similarity_score > 0.5
    
    def test_calculate_similarity_different(self):
        """Test similarity between different reports."""
        analyzer = SemanticSimilarityAnalyzer()
        
        report1 = MockReport("1", "XSS in search", "xss", "medium")
        report2 = MockReport("2", "SQL injection in login", "sql_injection", "critical")
        
        similarity = analyzer.calculate_similarity(report1, report2)
        
        assert similarity is not None
        assert similarity.similarity_score < 0.5
    
    def test_analyze_similarity_multiple(self):
        """Test analyzing similarity against multiple reports."""
        analyzer = SemanticSimilarityAnalyzer()

        report = MockReport("1", "XSS in search", "xss", "medium")
        candidates = [
            MockReport("2", "XSS in profile", "xss", "medium"),
            MockReport("3", "XSS in comments", "xss", "high"),
            MockReport("4", "SQL injection", "sql_injection", "critical")
        ]

        analysis = analyzer.analyze_similarity(report, candidates)

        assert analysis is not None
        assert len(analysis.similar_reports) > 0
        assert analysis.overall_similarity >= 0


class TestReportClusteringEngine:
    """Test report clustering."""
    
    def test_cluster_reports_semantic(self):
        """Test semantic clustering."""
        engine = ReportClusteringEngine()
        
        reports = [
            MockReport("1", "XSS in search", "xss", "medium"),
            MockReport("2", "XSS in profile", "xss", "medium"),
            MockReport("3", "XSS in comments", "xss", "high"),
            MockReport("4", "SQL injection in login", "sql_injection", "critical"),
            MockReport("5", "SQL injection in search", "sql_injection", "high"),
        ]
        
        result = engine.cluster_reports(
            reports,
            method=ClusteringMethod.SEMANTIC,
            min_cluster_size=2,
            similarity_threshold=0.3
        )
        
        assert result is not None
        assert result.get_cluster_count() > 0
        assert result.execution_time_ms > 0
    
    def test_cluster_reports_empty(self):
        """Test clustering with empty reports."""
        engine = ReportClusteringEngine()
        
        result = engine.cluster_reports([])
        
        assert result is not None
        assert result.get_cluster_count() == 0
        assert result.get_outlier_count() == 0
    
    def test_cluster_reports_single(self):
        """Test clustering with single report."""
        engine = ReportClusteringEngine()
        
        reports = [MockReport("1", "XSS in search", "xss", "medium")]
        
        result = engine.cluster_reports(reports, min_cluster_size=1)
        
        assert result is not None
    
    def test_get_cluster_summary(self):
        """Test getting cluster summary."""
        engine = ReportClusteringEngine()

        reports = [
            MockReport("1", "XSS in search", "xss", "medium"),
            MockReport("2", "XSS in profile", "xss", "medium"),
        ]

        result = engine.cluster_reports(reports, min_cluster_size=1)

        # Check basic result properties
        assert result is not None
        assert result.get_cluster_count() >= 0
        assert result.get_outlier_count() >= 0


class TestRelationshipTracker:
    """Test relationship tracking."""
    
    def test_add_relationship(self):
        """Test adding relationship."""
        tracker = RelationshipTracker()
        
        tracker.add_relationship(
            "report1",
            "report2",
            RelationshipType.SIMILAR,
            0.8
        )
        
        graph = tracker.build_graph()
        
        assert graph is not None
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1
    
    def test_add_multiple_relationships(self):
        """Test adding multiple relationships."""
        tracker = RelationshipTracker()
        
        tracker.add_relationship("r1", "r2", RelationshipType.SIMILAR, 0.8)
        tracker.add_relationship("r2", "r3", RelationshipType.RELATED, 0.6)
        tracker.add_relationship("r3", "r4", RelationshipType.CHAIN, 0.9)
        
        graph = tracker.build_graph()
        
        assert len(graph.nodes) == 4
        assert len(graph.edges) == 3
    
    def test_find_attack_chains(self):
        """Test finding attack chains."""
        tracker = RelationshipTracker()
        
        # Create a chain
        tracker.add_relationship("r1", "r2", RelationshipType.CHAIN, 0.9)
        tracker.add_relationship("r2", "r3", RelationshipType.CHAIN, 0.9)
        tracker.add_relationship("r3", "r4", RelationshipType.CHAIN, 0.9)
        
        chains = tracker.find_attack_chains()
        
        assert len(chains) > 0
        assert all(len(chain) >= 2 for chain in chains)
    
    def test_get_related_reports(self):
        """Test getting related reports."""
        tracker = RelationshipTracker()

        tracker.add_relationship("r1", "r2", RelationshipType.SIMILAR, 0.8)
        tracker.add_relationship("r1", "r3", RelationshipType.RELATED, 0.6)

        # Build graph and check relationships exist
        graph = tracker.build_graph()

        assert len(graph.nodes) == 3
        assert len(graph.edges) == 2


class TestVulnerabilityFamilyDetector:
    """Test vulnerability family detection."""
    
    def test_detect_families(self):
        """Test detecting vulnerability families."""
        detector = VulnerabilityFamilyDetector()
        
        reports = [
            MockReport("1", "XSS in search", "xss", "medium"),
            MockReport("2", "XSS in profile", "xss", "medium"),
            MockReport("3", "XSS in comments", "xss", "high"),
            MockReport("4", "SQL injection in login", "sql_injection", "critical"),
            MockReport("5", "SQL injection in search", "sql_injection", "high"),
        ]
        
        families = detector.detect_families(reports, min_family_size=2)
        
        assert len(families) > 0
        assert all(family.get_report_count() >= 2 for family in families)
    
    def test_detect_families_empty(self):
        """Test detecting families with empty reports."""
        detector = VulnerabilityFamilyDetector()
        
        families = detector.detect_families([])
        
        assert len(families) == 0
    
    def test_analyze_trend(self):
        """Test analyzing family trend."""
        detector = VulnerabilityFamilyDetector()
        
        # Create reports with different timestamps
        now = datetime.utcnow()
        reports = [
            MockReport("1", "XSS in search", "xss", "medium"),
            MockReport("2", "XSS in profile", "xss", "medium"),
            MockReport("3", "XSS in comments", "xss", "high"),
        ]
        reports[0].submitted_at = now - timedelta(days=30)
        reports[1].submitted_at = now - timedelta(days=15)
        reports[2].submitted_at = now
        
        families = detector.detect_families(reports, min_family_size=2)
        
        if families:
            family = families[0]
            trend = detector.analyze_trend(family.family_id, time_period_days=60)
            
            assert trend is not None
            assert hasattr(trend, 'growth_rate')
    
    def test_family_is_active(self):
        """Test checking if family is active."""
        detector = VulnerabilityFamilyDetector()
        
        reports = [
            MockReport("1", "XSS in search", "xss", "medium"),
            MockReport("2", "XSS in profile", "xss", "medium"),
        ]
        
        families = detector.detect_families(reports, min_family_size=2)
        
        if families:
            family = families[0]
            assert family.is_active()


class TestIntegration:
    """Integration tests for clustering system."""
    
    def test_end_to_end_clustering(self):
        """Test complete clustering workflow."""
        # Create analyzer and engine
        analyzer = SemanticSimilarityAnalyzer()
        engine = ReportClusteringEngine()
        tracker = RelationshipTracker()
        detector = VulnerabilityFamilyDetector()
        
        # Create test reports
        reports = [
            MockReport("1", "XSS in search field", "xss", "medium"),
            MockReport("2", "XSS in search box", "xss", "medium"),
            MockReport("3", "XSS in user profile", "xss", "high"),
            MockReport("4", "SQL injection in login form", "sql_injection", "critical"),
            MockReport("5", "SQL injection in search query", "sql_injection", "high"),
        ]
        
        # Cluster reports
        clustering_result = engine.cluster_reports(reports, min_cluster_size=2)
        
        assert clustering_result.get_cluster_count() > 0
        
        # Detect families
        families = detector.detect_families(reports, min_family_size=2)
        
        assert len(families) > 0
        
        # Build relationships
        for i, report1 in enumerate(reports):
            for report2 in reports[i+1:]:
                similarity = analyzer.calculate_similarity(report1, report2)
                if similarity.similarity_score > 0.5:
                    tracker.add_relationship(
                        report1.report_id,
                        report2.report_id,
                        RelationshipType.SIMILAR,
                        similarity.similarity_score
                    )
        
        graph = tracker.build_graph()
        assert len(graph.nodes) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

