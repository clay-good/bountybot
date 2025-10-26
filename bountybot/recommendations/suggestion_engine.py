"""
Suggestion Engine - Provides real-time context-aware suggestions during validation.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from bountybot.recommendations.models import (
    RecommendationContext,
)


logger = logging.getLogger(__name__)


class SuggestionTrigger(Enum):
    """Triggers for suggestions."""
    VALIDATION_START = "validation_start"
    STAGE_COMPLETE = "stage_complete"
    ERROR_DETECTED = "error_detected"
    LOW_CONFIDENCE = "low_confidence"
    PATTERN_MATCH = "pattern_match"
    USER_REQUEST = "user_request"


@dataclass
class ContextualSuggestion:
    """A contextual suggestion provided during validation."""
    suggestion_id: str
    trigger: SuggestionTrigger
    title: str
    message: str
    action: Optional[str] = None
    action_params: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.8
    priority: int = 5
    dismissible: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'suggestion_id': self.suggestion_id,
            'trigger': self.trigger.value,
            'title': self.title,
            'message': self.message,
            'action': self.action,
            'action_params': self.action_params,
            'confidence': self.confidence,
            'priority': self.priority,
            'dismissible': self.dismissible,
            'created_at': self.created_at.isoformat(),
        }


class SuggestionEngine:
    """
    Provides real-time context-aware suggestions during validation.
    """
    
    def __init__(self, recommendation_engine=None, learning_system=None):
        """
        Initialize suggestion engine.
        
        Args:
            recommendation_engine: Optional recommendation engine
            learning_system: Optional learning system
        """
        self.recommendation_engine = recommendation_engine
        self.learning_system = learning_system
        
        # Suggestion history
        self.suggestions_history: List[ContextualSuggestion] = []
        
        # Statistics
        self.stats = {
            'total_suggestions': 0,
            'accepted_suggestions': 0,
            'dismissed_suggestions': 0,
        }
    
    def get_suggestions_for_stage(
        self,
        stage: str,
        context: RecommendationContext,
        current_results: Optional[Dict[str, Any]] = None,
    ) -> List[ContextualSuggestion]:
        """
        Get suggestions for a specific validation stage.
        
        Args:
            stage: Current validation stage
            context: Validation context
            current_results: Current validation results
            
        Returns:
            List of contextual suggestions
        """
        suggestions = []
        
        if stage == "quality_assessment":
            suggestions.extend(self._get_quality_suggestions(context, current_results))
        
        elif stage == "plausibility_analysis":
            suggestions.extend(self._get_plausibility_suggestions(context, current_results))
        
        elif stage == "code_analysis":
            suggestions.extend(self._get_code_analysis_suggestions(context, current_results))
        
        elif stage == "dynamic_scanning":
            suggestions.extend(self._get_scanning_suggestions(context, current_results))
        
        elif stage == "final_verdict":
            suggestions.extend(self._get_verdict_suggestions(context, current_results))
        
        # Sort by priority
        suggestions.sort(key=lambda s: s.priority, reverse=True)
        
        # Update statistics
        self.stats['total_suggestions'] += len(suggestions)
        self.suggestions_history.extend(suggestions)
        
        return suggestions
    
    def _get_quality_suggestions(
        self,
        context: RecommendationContext,
        results: Optional[Dict[str, Any]],
    ) -> List[ContextualSuggestion]:
        """Get suggestions for quality assessment stage."""
        suggestions = []
        
        if results and results.get('completeness_score', 1.0) < 0.7:
            suggestion = ContextualSuggestion(
                suggestion_id=f"quality_{datetime.utcnow().timestamp()}",
                trigger=SuggestionTrigger.LOW_CONFIDENCE,
                title="Report Quality Issue Detected",
                message="The report appears incomplete. Consider requesting more details from the researcher.",
                action="request_clarification",
                action_params={
                    'missing_fields': results.get('missing_fields', []),
                },
                confidence=0.85,
                priority=8,
            )
            suggestions.append(suggestion)
        
        return suggestions
    
    def _get_plausibility_suggestions(
        self,
        context: RecommendationContext,
        results: Optional[Dict[str, Any]],
    ) -> List[ContextualSuggestion]:
        """Get suggestions for plausibility analysis stage."""
        suggestions = []
        
        # Suggest additional checks based on vulnerability type
        if context.vulnerability_type.lower() == 'xss':
            suggestion = ContextualSuggestion(
                suggestion_id=f"plausibility_{datetime.utcnow().timestamp()}",
                trigger=SuggestionTrigger.PATTERN_MATCH,
                title="XSS Context Analysis Recommended",
                message="For XSS vulnerabilities, analyze the injection context (HTML, JS, URL, CSS) for accurate assessment.",
                action="analyze_xss_context",
                confidence=0.9,
                priority=7,
            )
            suggestions.append(suggestion)
        
        elif context.vulnerability_type.lower() == 'sql injection':
            suggestion = ContextualSuggestion(
                suggestion_id=f"plausibility_{datetime.utcnow().timestamp()}",
                trigger=SuggestionTrigger.PATTERN_MATCH,
                title="SQL Injection Technique Check",
                message="Test multiple SQL injection techniques (union, boolean, time-based) for comprehensive validation.",
                action="test_sqli_techniques",
                action_params={
                    'techniques': ['union', 'boolean', 'time', 'error'],
                },
                confidence=0.9,
                priority=7,
            )
            suggestions.append(suggestion)
        
        return suggestions
    
    def _get_code_analysis_suggestions(
        self,
        context: RecommendationContext,
        results: Optional[Dict[str, Any]],
    ) -> List[ContextualSuggestion]:
        """Get suggestions for code analysis stage."""
        suggestions = []
        
        if results and results.get('vulnerable_code_found'):
            suggestion = ContextualSuggestion(
                suggestion_id=f"code_{datetime.utcnow().timestamp()}",
                trigger=SuggestionTrigger.PATTERN_MATCH,
                title="Vulnerable Code Pattern Detected",
                message="Similar vulnerable patterns found in codebase. Consider checking related files.",
                action="scan_related_files",
                action_params={
                    'pattern': results.get('pattern_type'),
                    'related_files': results.get('related_files', []),
                },
                confidence=0.8,
                priority=7,
            )
            suggestions.append(suggestion)
        
        # Language-specific suggestions
        if context.language == 'python':
            suggestion = ContextualSuggestion(
                suggestion_id=f"code_{datetime.utcnow().timestamp()}",
                trigger=SuggestionTrigger.STAGE_COMPLETE,
                title="Python Security Best Practices",
                message="Consider using Bandit for additional Python security analysis.",
                action="run_bandit_scan",
                confidence=0.75,
                priority=5,
            )
            suggestions.append(suggestion)
        
        return suggestions
    
    def _get_scanning_suggestions(
        self,
        context: RecommendationContext,
        results: Optional[Dict[str, Any]],
    ) -> List[ContextualSuggestion]:
        """Get suggestions for dynamic scanning stage."""
        suggestions = []
        
        if results and results.get('scan_errors'):
            suggestion = ContextualSuggestion(
                suggestion_id=f"scan_{datetime.utcnow().timestamp()}",
                trigger=SuggestionTrigger.ERROR_DETECTED,
                title="Scanning Errors Detected",
                message="Some scans failed. Consider adjusting scan parameters or retrying.",
                action="retry_scans",
                action_params={
                    'failed_scans': results.get('scan_errors', []),
                },
                confidence=0.7,
                priority=6,
            )
            suggestions.append(suggestion)
        
        return suggestions
    
    def _get_verdict_suggestions(
        self,
        context: RecommendationContext,
        results: Optional[Dict[str, Any]],
    ) -> List[ContextualSuggestion]:
        """Get suggestions for final verdict stage."""
        suggestions = []
        
        if results and results.get('confidence', 1.0) < 0.7:
            suggestion = ContextualSuggestion(
                suggestion_id=f"verdict_{datetime.utcnow().timestamp()}",
                trigger=SuggestionTrigger.LOW_CONFIDENCE,
                title="Low Confidence Verdict",
                message="Confidence is below 70%. Consider manual review or additional validation.",
                action="request_manual_review",
                confidence=0.9,
                priority=9,
            )
            suggestions.append(suggestion)
        
        # Check for similar cases
        if self.recommendation_engine and self.recommendation_engine.knowledge_graph:
            similar_count = len(
                self.recommendation_engine.knowledge_graph.find_similar_vulnerabilities(
                    context.vulnerability_type,
                    limit=5,
                )
            )
            
            if similar_count > 0:
                suggestion = ContextualSuggestion(
                    suggestion_id=f"verdict_{datetime.utcnow().timestamp()}",
                    trigger=SuggestionTrigger.PATTERN_MATCH,
                    title=f"{similar_count} Similar Cases Found",
                    message="Review similar cases for validation insights and remediation approaches.",
                    action="view_similar_cases",
                    action_params={
                        'count': similar_count,
                        'vulnerability_type': context.vulnerability_type,
                    },
                    confidence=0.8,
                    priority=6,
                )
                suggestions.append(suggestion)
        
        return suggestions
    
    def record_suggestion_action(
        self,
        suggestion_id: str,
        action: str,
    ) -> None:
        """
        Record that a suggestion action was taken.
        
        Args:
            suggestion_id: ID of the suggestion
            action: Action taken ('accepted' or 'dismissed')
        """
        if action == 'accepted':
            self.stats['accepted_suggestions'] += 1
        elif action == 'dismissed':
            self.stats['dismissed_suggestions'] += 1
        
        logger.info(f"Suggestion {suggestion_id} {action}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get suggestion engine statistics."""
        total = self.stats['total_suggestions']
        accepted = self.stats['accepted_suggestions']
        dismissed = self.stats['dismissed_suggestions']
        
        acceptance_rate = (accepted / total * 100) if total > 0 else 0
        dismissal_rate = (dismissed / total * 100) if total > 0 else 0
        
        return {
            'total_suggestions': total,
            'accepted_suggestions': accepted,
            'dismissed_suggestions': dismissed,
            'acceptance_rate': round(acceptance_rate, 2),
            'dismissal_rate': round(dismissal_rate, 2),
        }

