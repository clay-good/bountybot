"""
Tests for the recommendation system.
"""

import pytest
from datetime import datetime, timedelta

from bountybot.recommendations import (
    Recommendation,
    RecommendationType,
    RecommendationContext,
    RecommendationFeedback,
    FeedbackType,
    LearningPattern,
    PatternType,
    KnowledgeNode,
    KnowledgeEdge,
    EdgeType,
    RecommendationEngine,
    AdaptiveLearningSystem,
    LearningMetrics,
    SuggestionEngine,
    ContextualSuggestion,
    KnowledgeGraph,
    GraphQuery,
    SmartAutomation,
    AutomationRule,
)
from bountybot.recommendations.suggestion_engine import SuggestionTrigger
from bountybot.recommendations.smart_automation import AutomationTrigger, AutomationAction


class TestRecommendationModels:
    """Test recommendation data models."""
    
    def test_recommendation_creation(self):
        """Test creating a recommendation."""
        rec = Recommendation(
            type=RecommendationType.VALIDATION_STRATEGY,
            title="Test Recommendation",
            description="Test description",
            confidence=0.9,
        )
        
        assert rec.type == RecommendationType.VALIDATION_STRATEGY
        assert rec.title == "Test Recommendation"
        assert rec.confidence == 0.9
        assert rec.applied is False
    
    def test_recommendation_to_dict(self):
        """Test converting recommendation to dict."""
        rec = Recommendation(
            type=RecommendationType.CODE_FIX,
            title="Fix SQL Injection",
            confidence=0.95,
        )
        
        data = rec.to_dict()
        assert data['type'] == 'code_fix'
        assert data['title'] == "Fix SQL Injection"
        assert data['confidence'] == 0.95
    
    def test_recommendation_feedback(self):
        """Test recommendation feedback."""
        feedback = RecommendationFeedback(
            recommendation_id="rec-123",
            feedback_type=FeedbackType.ACCEPTED,
            user_id="user-1",
            effectiveness_score=0.9,
        )
        
        assert feedback.feedback_type == FeedbackType.ACCEPTED
        assert feedback.effectiveness_score == 0.9
    
    def test_learning_pattern(self):
        """Test learning pattern."""
        pattern = LearningPattern(
            type=PatternType.VULNERABILITY_PATTERN,
            name="XSS Pattern",
            occurrence_count=10,
            success_rate=0.85,
        )
        
        assert pattern.type == PatternType.VULNERABILITY_PATTERN
        assert pattern.occurrence_count == 10
        assert pattern.success_rate == 0.85


class TestRecommendationEngine:
    """Test recommendation engine."""
    
    def test_engine_initialization(self):
        """Test initializing recommendation engine."""
        engine = RecommendationEngine()
        
        assert engine.recommendations_history == []
        assert engine.stats['total_recommendations'] == 0
    
    def test_generate_xss_recommendations(self):
        """Test generating XSS recommendations."""
        engine = RecommendationEngine()
        
        context = RecommendationContext(
            vulnerability_type="XSS",
            severity="high",
            language="javascript",
        )
        
        recommendations = engine.generate_recommendations(context)
        
        assert len(recommendations) > 0
        assert any(r.type == RecommendationType.VALIDATION_STRATEGY for r in recommendations)
        assert engine.stats['total_recommendations'] > 0
    
    def test_generate_sqli_recommendations(self):
        """Test generating SQL injection recommendations."""
        engine = RecommendationEngine()
        
        context = RecommendationContext(
            vulnerability_type="SQL Injection",
            severity="critical",
            language="python",
        )
        
        recommendations = engine.generate_recommendations(context)
        
        assert len(recommendations) > 0
        # Should have validation and remediation recommendations
        types = {r.type for r in recommendations}
        assert RecommendationType.VALIDATION_STRATEGY in types or RecommendationType.REMEDIATION_APPROACH in types
    
    def test_record_feedback(self):
        """Test recording feedback."""
        engine = RecommendationEngine()
        
        # Generate recommendation
        context = RecommendationContext(
            vulnerability_type="XSS",
            severity="high",
        )
        recommendations = engine.generate_recommendations(context, max_recommendations=1)
        
        # Record feedback
        feedback = RecommendationFeedback(
            recommendation_id=recommendations[0].recommendation_id,
            feedback_type=FeedbackType.ACCEPTED,
            user_id="user-1",
        )
        engine.record_feedback(feedback)
        
        assert engine.stats['accepted_recommendations'] == 1
        assert recommendations[0].applied is True
    
    def test_get_stats(self):
        """Test getting engine statistics."""
        engine = RecommendationEngine()
        
        context = RecommendationContext(
            vulnerability_type="XSS",
            severity="high",
        )
        engine.generate_recommendations(context)
        
        stats = engine.get_stats()
        assert 'total_recommendations' in stats
        assert 'acceptance_rate' in stats
        assert stats['total_recommendations'] > 0


class TestAdaptiveLearningSystem:
    """Test adaptive learning system."""
    
    def test_learning_system_initialization(self):
        """Test initializing learning system."""
        system = AdaptiveLearningSystem()
        
        assert system.patterns == {}
        assert system.metrics.total_patterns == 0
    
    def test_process_positive_feedback(self):
        """Test processing positive feedback."""
        system = AdaptiveLearningSystem()
        
        feedback = RecommendationFeedback(
            recommendation_id="rec-123",
            feedback_type=FeedbackType.ACCEPTED,
            user_id="user-1",
        )
        
        system.process_feedback(feedback)
        
        assert system.metrics.total_feedback_processed == 1
        assert len(system.patterns) > 0
    
    def test_process_negative_feedback(self):
        """Test processing negative feedback."""
        system = AdaptiveLearningSystem()
        
        feedback = RecommendationFeedback(
            recommendation_id="rec-456",
            feedback_type=FeedbackType.REJECTED,
            user_id="user-1",
        )
        
        system.process_feedback(feedback)
        
        assert system.metrics.total_feedback_processed == 1
    
    def test_add_pattern(self):
        """Test adding a learning pattern."""
        system = AdaptiveLearningSystem()
        
        pattern = LearningPattern(
            type=PatternType.VULNERABILITY_PATTERN,
            name="Test Pattern",
            confidence=0.8,
        )
        
        system.add_pattern(pattern)
        
        assert system.metrics.total_patterns == 1
        assert pattern.pattern_id in system.patterns
    
    def test_get_recommendations_for_context(self):
        """Test getting recommendations from patterns."""
        system = AdaptiveLearningSystem()
        
        # Add a pattern
        pattern = LearningPattern(
            type=PatternType.VULNERABILITY_PATTERN,
            name="XSS Pattern",
            confidence=0.9,
            occurrence_count=5,
            success_rate=0.85,
            conditions={'vulnerability_type': 'XSS'},
        )
        system.add_pattern(pattern)
        
        # Get recommendations
        context = RecommendationContext(
            vulnerability_type="XSS",
            severity="high",
        )
        recommendations = system.get_recommendations_for_context(context)
        
        assert len(recommendations) > 0
        assert recommendations[0].source == "learning_system"
    
    def test_train_model(self):
        """Test training the model."""
        system = AdaptiveLearningSystem()
        
        # Add some feedback
        feedback = RecommendationFeedback(
            recommendation_id="rec-123",
            feedback_type=FeedbackType.ACCEPTED,
            user_id="user-1",
        )
        system.process_feedback(feedback)
        
        # Train model
        system.train_model()
        
        assert system.metrics.last_training is not None
        assert system.metrics.model_accuracy > 0
    
    def test_prune_patterns(self):
        """Test pruning old patterns."""
        system = AdaptiveLearningSystem()
        
        # Add old pattern
        pattern = LearningPattern(
            type=PatternType.VULNERABILITY_PATTERN,
            name="Old Pattern",
            confidence=0.2,
            last_seen=datetime.utcnow() - timedelta(days=100),
        )
        system.add_pattern(pattern)
        
        # Prune
        pruned = system.prune_patterns(max_age_days=90, min_confidence=0.3)
        
        assert pruned == 1
        assert system.metrics.total_patterns == 0


class TestSuggestionEngine:
    """Test suggestion engine."""
    
    def test_suggestion_engine_initialization(self):
        """Test initializing suggestion engine."""
        engine = SuggestionEngine()
        
        assert engine.suggestions_history == []
        assert engine.stats['total_suggestions'] == 0
    
    def test_get_quality_suggestions(self):
        """Test getting quality assessment suggestions."""
        engine = SuggestionEngine()
        
        context = RecommendationContext(
            vulnerability_type="XSS",
            severity="high",
        )
        
        results = {
            'completeness_score': 0.5,
            'missing_fields': ['steps_to_reproduce'],
        }
        
        suggestions = engine.get_suggestions_for_stage(
            "quality_assessment",
            context,
            results,
        )
        
        assert len(suggestions) > 0
        assert suggestions[0].trigger == SuggestionTrigger.LOW_CONFIDENCE
    
    def test_get_plausibility_suggestions(self):
        """Test getting plausibility suggestions."""
        engine = SuggestionEngine()
        
        context = RecommendationContext(
            vulnerability_type="XSS",
            severity="high",
        )
        
        suggestions = engine.get_suggestions_for_stage(
            "plausibility_analysis",
            context,
        )
        
        assert len(suggestions) > 0
        assert any(s.trigger == SuggestionTrigger.PATTERN_MATCH for s in suggestions)
    
    def test_record_suggestion_action(self):
        """Test recording suggestion actions."""
        engine = SuggestionEngine()
        
        engine.record_suggestion_action("sug-123", "accepted")
        
        assert engine.stats['accepted_suggestions'] == 1
    
    def test_get_stats(self):
        """Test getting suggestion statistics."""
        engine = SuggestionEngine()
        
        context = RecommendationContext(
            vulnerability_type="XSS",
            severity="high",
        )
        
        engine.get_suggestions_for_stage("quality_assessment", context)
        
        stats = engine.get_stats()
        assert 'total_suggestions' in stats
        assert stats['total_suggestions'] >= 0


class TestKnowledgeGraph:
    """Test knowledge graph."""
    
    def test_graph_initialization(self):
        """Test initializing knowledge graph."""
        graph = KnowledgeGraph()
        
        assert graph.nodes == {}
        assert graph.edges == {}
        assert graph.stats['total_nodes'] == 0
    
    def test_add_node(self):
        """Test adding a node."""
        graph = KnowledgeGraph()
        
        node = KnowledgeNode(
            node_type="vulnerability",
            name="XSS Vulnerability",
            description="Cross-site scripting",
        )
        
        node_id = graph.add_node(node)
        
        assert node_id == node.node_id
        assert graph.stats['total_nodes'] == 1
    
    def test_add_edge(self):
        """Test adding an edge."""
        graph = KnowledgeGraph()
        
        # Add nodes
        node1 = KnowledgeNode(node_type="vulnerability", name="XSS")
        node2 = KnowledgeNode(node_type="fix", name="Input Sanitization")
        
        graph.add_node(node1)
        graph.add_node(node2)
        
        # Add edge
        edge = KnowledgeEdge(
            edge_type=EdgeType.FIXES,
            source_node_id=node2.node_id,
            target_node_id=node1.node_id,
        )
        
        edge_id = graph.add_edge(edge)
        
        assert edge_id == edge.edge_id
        assert graph.stats['total_edges'] == 1
    
    def test_find_nodes(self):
        """Test finding nodes."""
        graph = KnowledgeGraph()
        
        # Add nodes
        node1 = KnowledgeNode(node_type="vulnerability", name="XSS")
        node2 = KnowledgeNode(node_type="vulnerability", name="SQLi")
        
        graph.add_node(node1)
        graph.add_node(node2)
        
        # Find vulnerability nodes
        nodes = graph.find_nodes(node_type="vulnerability")
        
        assert len(nodes) == 2
    
    def test_get_related_nodes(self):
        """Test getting related nodes."""
        graph = KnowledgeGraph()
        
        # Add nodes
        vuln = KnowledgeNode(node_type="vulnerability", name="XSS")
        fix = KnowledgeNode(node_type="fix", name="Sanitization")
        
        graph.add_node(vuln)
        graph.add_node(fix)
        
        # Add edge
        edge = KnowledgeEdge(
            edge_type=EdgeType.FIXES,
            source_node_id=fix.node_id,
            target_node_id=vuln.node_id,
        )
        graph.add_edge(edge)
        
        # Get related nodes
        related = graph.get_related_nodes(fix.node_id, direction='outgoing')
        
        assert len(related) == 1
        assert related[0].node_id == vuln.node_id
    
    def test_find_path(self):
        """Test finding path between nodes."""
        graph = KnowledgeGraph()
        
        # Add nodes
        node1 = KnowledgeNode(node_type="vulnerability", name="Node1")
        node2 = KnowledgeNode(node_type="fix", name="Node2")
        node3 = KnowledgeNode(node_type="control", name="Node3")
        
        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_node(node3)
        
        # Add edges
        edge1 = KnowledgeEdge(
            edge_type=EdgeType.FIXES,
            source_node_id=node1.node_id,
            target_node_id=node2.node_id,
        )
        edge2 = KnowledgeEdge(
            edge_type=EdgeType.RELATED_TO,
            source_node_id=node2.node_id,
            target_node_id=node3.node_id,
        )
        
        graph.add_edge(edge1)
        graph.add_edge(edge2)
        
        # Find path
        path = graph.find_path(node1.node_id, node3.node_id)
        
        assert path is not None
        assert len(path) == 3
        assert path[0] == node1.node_id
        assert path[-1] == node3.node_id


class TestSmartAutomation:
    """Test smart automation."""
    
    def test_automation_initialization(self):
        """Test initializing smart automation."""
        automation = SmartAutomation()
        
        assert automation.rules == {}
        assert automation.stats['total_executions'] == 0
    
    def test_add_rule(self):
        """Test adding an automation rule."""
        automation = SmartAutomation()
        
        rule = AutomationRule(
            rule_id="rule-1",
            name="Auto-apply XSS validation",
            description="Automatically apply XSS validation strategy",
            trigger=AutomationTrigger.HIGH_CONFIDENCE_PATTERN,
            action=AutomationAction.APPLY_VALIDATION_STRATEGY,
        )
        
        rule_id = automation.add_rule(rule)
        
        assert rule_id == "rule-1"
        assert "rule-1" in automation.rules
    
    def test_enable_disable_rule(self):
        """Test enabling and disabling rules."""
        automation = SmartAutomation()
        
        rule = AutomationRule(
            rule_id="rule-1",
            name="Test Rule",
            description="Test",
            trigger=AutomationTrigger.VALIDATION_START,
            action=AutomationAction.ADD_TAGS,
        )
        
        automation.add_rule(rule)
        
        # Disable
        assert automation.disable_rule("rule-1") is True
        assert automation.rules["rule-1"].enabled is False
        
        # Enable
        assert automation.enable_rule("rule-1") is True
        assert automation.rules["rule-1"].enabled is True
    
    def test_evaluate_rules(self):
        """Test evaluating automation rules."""
        automation = SmartAutomation()
        
        rule = AutomationRule(
            rule_id="rule-1",
            name="XSS Rule",
            description="Auto-apply for XSS",
            trigger=AutomationTrigger.VALIDATION_START,
            action=AutomationAction.APPLY_VALIDATION_STRATEGY,
            conditions={'vulnerability_type': 'XSS'},
        )
        
        automation.add_rule(rule)
        
        context = RecommendationContext(
            vulnerability_type="XSS",
            severity="high",
        )
        
        actions = automation.evaluate_rules(
            AutomationTrigger.VALIDATION_START,
            context,
        )
        
        assert len(actions) > 0
        assert actions[0]['rule_id'] == "rule-1"
    
    def test_execute_action(self):
        """Test executing an automation action."""
        automation = SmartAutomation()
        
        rule = AutomationRule(
            rule_id="rule-1",
            name="Test Rule",
            description="Test",
            trigger=AutomationTrigger.VALIDATION_START,
            action=AutomationAction.ADD_TAGS,
            action_params={'tags': ['automated', 'xss']},
        )
        
        automation.add_rule(rule)
        
        context = RecommendationContext(
            vulnerability_type="XSS",
            severity="high",
        )
        
        action = {
            'rule_id': "rule-1",
            'action': AutomationAction.ADD_TAGS,
            'action_params': {'tags': ['automated', 'xss']},
        }
        
        result = automation.execute_action(action, context)
        
        assert result['success'] is True
        assert automation.stats['successful_executions'] == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

