"""
Adaptive Learning System - Learns from validation outcomes to improve recommendations.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
import math

from bountybot.recommendations.models import (
    Recommendation,
    RecommendationType,
    RecommendationContext,
    RecommendationFeedback,
    FeedbackType,
    LearningPattern,
    PatternType,
)


logger = logging.getLogger(__name__)


@dataclass
class LearningMetrics:
    """Metrics for the learning system."""
    total_patterns: int = 0
    active_patterns: int = 0
    average_success_rate: float = 0.0
    total_feedback_processed: int = 0
    model_accuracy: float = 0.0
    last_training: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_patterns': self.total_patterns,
            'active_patterns': self.active_patterns,
            'average_success_rate': round(self.average_success_rate, 2),
            'total_feedback_processed': self.total_feedback_processed,
            'model_accuracy': round(self.model_accuracy, 2),
            'last_training': self.last_training.isoformat() if self.last_training else None,
        }


class AdaptiveLearningSystem:
    """
    Adaptive learning system that learns from validation outcomes
    and improves recommendations over time.
    """
    
    def __init__(self, min_pattern_occurrences: int = 3, confidence_threshold: float = 0.7):
        """
        Initialize adaptive learning system.
        
        Args:
            min_pattern_occurrences: Minimum occurrences before pattern is considered
            confidence_threshold: Minimum confidence for pattern recommendations
        """
        self.min_pattern_occurrences = min_pattern_occurrences
        self.confidence_threshold = confidence_threshold
        
        # Learned patterns
        self.patterns: Dict[str, LearningPattern] = {}
        
        # Feedback data
        self.feedback_data: List[RecommendationFeedback] = []
        
        # Metrics
        self.metrics = LearningMetrics()
    
    def process_feedback(self, feedback: RecommendationFeedback) -> None:
        """
        Process feedback and update learning patterns.
        
        Args:
            feedback: Feedback to process
        """
        self.feedback_data.append(feedback)
        self.metrics.total_feedback_processed += 1
        
        # Extract patterns from feedback
        self._extract_patterns_from_feedback(feedback)
        
        # Update pattern statistics
        self._update_pattern_statistics()
        
        logger.info(f"Processed feedback: {feedback.feedback_type.value}")
    
    def _extract_patterns_from_feedback(self, feedback: RecommendationFeedback) -> None:
        """Extract learning patterns from feedback."""
        # This is a simplified pattern extraction
        # In production, this would use ML models
        
        if feedback.feedback_type in [FeedbackType.ACCEPTED, FeedbackType.HELPFUL]:
            # Positive feedback - reinforce pattern
            pattern_key = f"positive_{feedback.recommendation_id[:8]}"
            
            if pattern_key in self.patterns:
                pattern = self.patterns[pattern_key]
                pattern.occurrence_count += 1
                pattern.success_rate = min(1.0, pattern.success_rate + 0.1)
                pattern.last_seen = datetime.utcnow()
            else:
                # Create new pattern
                pattern = LearningPattern(
                    type=PatternType.VULNERABILITY_PATTERN,
                    name=f"Pattern from {feedback.recommendation_id[:8]}",
                    description="Learned from positive feedback",
                    pattern_data={'feedback_id': feedback.feedback_id},
                    occurrence_count=1,
                    success_rate=0.8,
                    confidence=0.7,
                )
                self.patterns[pattern_key] = pattern
        
        elif feedback.feedback_type in [FeedbackType.REJECTED, FeedbackType.NOT_HELPFUL]:
            # Negative feedback - reduce pattern confidence
            pattern_key = f"negative_{feedback.recommendation_id[:8]}"
            
            if pattern_key in self.patterns:
                pattern = self.patterns[pattern_key]
                pattern.success_rate = max(0.0, pattern.success_rate - 0.1)
                pattern.confidence = max(0.0, pattern.confidence - 0.1)
    
    def _update_pattern_statistics(self) -> None:
        """Update pattern statistics."""
        # Always update total count
        self.metrics.total_patterns = len(self.patterns)

        if not self.patterns:
            self.metrics.active_patterns = 0
            self.metrics.average_success_rate = 0.0
            return

        # Count active patterns (high confidence, recent)
        active_count = 0
        total_success = 0.0

        for pattern in self.patterns.values():
            if pattern.confidence >= self.confidence_threshold:
                active_count += 1
            total_success += pattern.success_rate

        self.metrics.active_patterns = active_count
        self.metrics.average_success_rate = total_success / len(self.patterns)
    
    def get_recommendations_for_context(
        self,
        context: RecommendationContext,
    ) -> List[Recommendation]:
        """
        Get recommendations based on learned patterns.
        
        Args:
            context: Context for recommendations
            
        Returns:
            List of pattern-based recommendations
        """
        recommendations = []
        
        # Find matching patterns
        matching_patterns = self._find_matching_patterns(context)
        
        for pattern in matching_patterns:
            if pattern.confidence < self.confidence_threshold:
                continue
            
            if pattern.occurrence_count < self.min_pattern_occurrences:
                continue
            
            # Create recommendation from pattern
            rec = Recommendation(
                type=RecommendationType.VALIDATION_STRATEGY,
                title=f"Learned Strategy: {pattern.name}",
                description=pattern.description,
                confidence=pattern.confidence,
                reasoning=f"This pattern has been successful {pattern.occurrence_count} times "
                          f"with {pattern.success_rate*100:.0f}% success rate",
                content=pattern.pattern_data,
                source="learning_system",
                tags=['learned', 'pattern'],
                priority=8,
            )
            recommendations.append(rec)
        
        return recommendations
    
    def _find_matching_patterns(
        self,
        context: RecommendationContext,
    ) -> List[LearningPattern]:
        """Find patterns matching the context."""
        matching = []
        
        for pattern in self.patterns.values():
            # Simple matching based on conditions
            # In production, this would use ML similarity matching
            
            if not pattern.conditions:
                continue
            
            match_score = 0
            total_conditions = len(pattern.conditions)
            
            # Check vulnerability type
            if 'vulnerability_type' in pattern.conditions:
                if pattern.conditions['vulnerability_type'] == context.vulnerability_type:
                    match_score += 1
            
            # Check severity
            if 'severity' in pattern.conditions:
                if pattern.conditions['severity'] == context.severity:
                    match_score += 1
            
            # Check language
            if 'language' in pattern.conditions and context.language:
                if pattern.conditions['language'] == context.language:
                    match_score += 1
            
            # If at least 50% of conditions match
            if total_conditions > 0 and match_score / total_conditions >= 0.5:
                matching.append(pattern)
        
        # Sort by confidence and success rate
        matching.sort(key=lambda p: (p.confidence, p.success_rate), reverse=True)
        
        return matching
    
    def train_model(self) -> None:
        """
        Train/retrain the learning model.
        
        In production, this would train ML models on historical data.
        For now, it updates pattern statistics.
        """
        logger.info("Training learning model...")
        
        # Update all pattern statistics
        self._update_pattern_statistics()
        
        # Calculate model accuracy based on feedback
        if self.feedback_data:
            positive_feedback = sum(
                1 for f in self.feedback_data
                if f.feedback_type in [FeedbackType.ACCEPTED, FeedbackType.HELPFUL]
            )
            self.metrics.model_accuracy = positive_feedback / len(self.feedback_data)
        
        self.metrics.last_training = datetime.utcnow()
        
        logger.info(f"Model training complete. Accuracy: {self.metrics.model_accuracy:.2%}")
    
    def add_pattern(self, pattern: LearningPattern) -> None:
        """
        Manually add a learning pattern.
        
        Args:
            pattern: Pattern to add
        """
        self.patterns[pattern.pattern_id] = pattern
        self.metrics.total_patterns += 1
        
        if pattern.confidence >= self.confidence_threshold:
            self.metrics.active_patterns += 1
        
        logger.info(f"Added pattern: {pattern.name}")
    
    def get_pattern(self, pattern_id: str) -> Optional[LearningPattern]:
        """Get a pattern by ID."""
        return self.patterns.get(pattern_id)
    
    def get_all_patterns(
        self,
        pattern_type: Optional[PatternType] = None,
        min_confidence: float = 0.0,
    ) -> List[LearningPattern]:
        """
        Get all patterns, optionally filtered.
        
        Args:
            pattern_type: Filter by pattern type
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of patterns
        """
        patterns = list(self.patterns.values())
        
        if pattern_type:
            patterns = [p for p in patterns if p.type == pattern_type]
        
        if min_confidence > 0:
            patterns = [p for p in patterns if p.confidence >= min_confidence]
        
        return patterns
    
    def get_metrics(self) -> LearningMetrics:
        """Get learning system metrics."""
        return self.metrics
    
    def get_stats(self) -> Dict[str, Any]:
        """Get learning system statistics."""
        return self.metrics.to_dict()
    
    def prune_patterns(self, max_age_days: int = 90, min_confidence: float = 0.3) -> int:
        """
        Prune old or low-confidence patterns.
        
        Args:
            max_age_days: Maximum age in days
            min_confidence: Minimum confidence to keep
            
        Returns:
            Number of patterns pruned
        """
        cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
        
        patterns_to_remove = []
        for pattern_id, pattern in self.patterns.items():
            # Remove if too old and low confidence
            if pattern.last_seen < cutoff_date and pattern.confidence < min_confidence:
                patterns_to_remove.append(pattern_id)
        
        for pattern_id in patterns_to_remove:
            del self.patterns[pattern_id]
        
        # Update metrics
        self._update_pattern_statistics()
        
        logger.info(f"Pruned {len(patterns_to_remove)} patterns")
        return len(patterns_to_remove)

