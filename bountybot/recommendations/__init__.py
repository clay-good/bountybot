"""
BountyBot Recommendations Module

This module provides AI-powered smart recommendations and learning capabilities:
- Intelligent recommendation engine with pattern matching
- Adaptive learning system that improves over time
- Context-aware suggestions during validation
- Knowledge graph for vulnerability relationships
- Smart automation with learned patterns
"""

from bountybot.recommendations.models import (
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
)

from bountybot.recommendations.recommendation_engine import (
    RecommendationEngine,
)

from bountybot.recommendations.learning_system import (
    AdaptiveLearningSystem,
    LearningMetrics,
)

from bountybot.recommendations.suggestion_engine import (
    SuggestionEngine,
    ContextualSuggestion,
)

from bountybot.recommendations.knowledge_graph import (
    KnowledgeGraph,
    GraphQuery,
)

from bountybot.recommendations.smart_automation import (
    SmartAutomation,
    AutomationRule,
)


__all__ = [
    # Models
    'Recommendation',
    'RecommendationType',
    'RecommendationContext',
    'RecommendationFeedback',
    'FeedbackType',
    'LearningPattern',
    'PatternType',
    'KnowledgeNode',
    'KnowledgeEdge',
    'EdgeType',
    
    # Engines
    'RecommendationEngine',
    'AdaptiveLearningSystem',
    'LearningMetrics',
    'SuggestionEngine',
    'ContextualSuggestion',
    'KnowledgeGraph',
    'GraphQuery',
    'SmartAutomation',
    'AutomationRule',
]

