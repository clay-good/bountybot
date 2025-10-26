"""
Recommendation Engine - Core recommendation generation system.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import math

from bountybot.recommendations.models import (
    Recommendation,
    RecommendationType,
    RecommendationContext,
    RecommendationFeedback,
    FeedbackType,
)


logger = logging.getLogger(__name__)


class RecommendationEngine:
    """
    Core recommendation engine that generates intelligent recommendations
    based on context, historical data, and learned patterns.
    """
    
    def __init__(self, knowledge_graph=None, learning_system=None):
        """
        Initialize recommendation engine.
        
        Args:
            knowledge_graph: Optional knowledge graph for relationship queries
            learning_system: Optional learning system for pattern-based recommendations
        """
        self.knowledge_graph = knowledge_graph
        self.learning_system = learning_system
        
        # Historical data
        self.recommendations_history: List[Recommendation] = []
        self.feedback_history: List[RecommendationFeedback] = []
        
        # Statistics
        self.stats = {
            'total_recommendations': 0,
            'accepted_recommendations': 0,
            'rejected_recommendations': 0,
            'average_confidence': 0.0,
        }
    
    def generate_recommendations(
        self,
        context: RecommendationContext,
        max_recommendations: int = 5,
        min_confidence: float = 0.5,
    ) -> List[Recommendation]:
        """
        Generate recommendations based on context.
        
        Args:
            context: Context for generating recommendations
            max_recommendations: Maximum number of recommendations to return
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of recommendations sorted by priority and confidence
        """
        logger.info(f"Generating recommendations for {context.vulnerability_type}")
        
        recommendations = []
        
        # Generate different types of recommendations
        recommendations.extend(self._generate_validation_recommendations(context))
        recommendations.extend(self._generate_remediation_recommendations(context))
        recommendations.extend(self._generate_security_recommendations(context))
        recommendations.extend(self._generate_similar_case_recommendations(context))
        
        # Filter by confidence
        recommendations = [r for r in recommendations if r.confidence >= min_confidence]
        
        # Sort by priority and confidence
        recommendations.sort(key=lambda r: (r.priority, r.confidence), reverse=True)
        
        # Limit results
        recommendations = recommendations[:max_recommendations]
        
        # Update statistics
        self.stats['total_recommendations'] += len(recommendations)
        self.recommendations_history.extend(recommendations)
        
        logger.info(f"Generated {len(recommendations)} recommendations")
        return recommendations
    
    def _generate_validation_recommendations(
        self,
        context: RecommendationContext,
    ) -> List[Recommendation]:
        """Generate validation strategy recommendations."""
        recommendations = []
        
        # Recommend validation approach based on vulnerability type
        if context.vulnerability_type.lower() in ['xss', 'cross-site scripting']:
            rec = Recommendation(
                type=RecommendationType.VALIDATION_STRATEGY,
                title="Use Context-Aware XSS Validation",
                description="Validate XSS in the specific context (HTML, JavaScript, URL, CSS) where it occurs",
                confidence=0.9,
                reasoning="XSS validation accuracy improves by 40% when context-specific checks are used",
                content={
                    'strategy': 'context_aware_validation',
                    'contexts': ['html', 'javascript', 'url', 'css'],
                    'tools': ['browser_automation', 'dom_analysis'],
                },
                references=[
                    'OWASP XSS Prevention Cheat Sheet',
                    'PortSwigger XSS Contexts',
                ],
                priority=10,
            )
            recommendations.append(rec)
        
        elif context.vulnerability_type.lower() in ['sql injection', 'sqli']:
            rec = Recommendation(
                type=RecommendationType.VALIDATION_STRATEGY,
                title="Test Multiple SQL Injection Techniques",
                description="Test union-based, boolean-based, time-based, and error-based SQL injection",
                confidence=0.85,
                reasoning="Comprehensive SQL injection testing catches 95% of variants",
                content={
                    'strategy': 'multi_technique_sqli',
                    'techniques': ['union', 'boolean', 'time', 'error', 'stacked'],
                    'payloads': ['UNION SELECT', "' OR '1'='1", 'SLEEP(5)', 'CAST(0x AS INT)'],
                },
                references=[
                    'OWASP SQL Injection',
                    'SQLMap Documentation',
                ],
                priority=10,
            )
            recommendations.append(rec)
        
        # Check learning system for patterns
        if self.learning_system:
            learned_recs = self.learning_system.get_recommendations_for_context(context)
            recommendations.extend(learned_recs)
        
        return recommendations
    
    def _generate_remediation_recommendations(
        self,
        context: RecommendationContext,
    ) -> List[Recommendation]:
        """Generate remediation approach recommendations."""
        recommendations = []
        
        # Language-specific recommendations
        if context.language:
            if context.language.lower() == 'python':
                rec = Recommendation(
                    type=RecommendationType.REMEDIATION_APPROACH,
                    title="Use Parameterized Queries with SQLAlchemy",
                    description="Replace string concatenation with parameterized queries to prevent SQL injection",
                    confidence=0.95,
                    reasoning="Parameterized queries eliminate 99.9% of SQL injection vulnerabilities",
                    code_snippet="""
# Bad
query = f"SELECT * FROM users WHERE id = {user_id}"

# Good
query = session.query(User).filter(User.id == user_id)
""",
                    content={
                        'approach': 'parameterized_queries',
                        'library': 'sqlalchemy',
                        'pattern': 'orm',
                    },
                    references=[
                        'SQLAlchemy Documentation',
                        'OWASP Query Parameterization',
                    ],
                    priority=9,
                )
                recommendations.append(rec)
            
            elif context.language.lower() == 'javascript':
                rec = Recommendation(
                    type=RecommendationType.REMEDIATION_APPROACH,
                    title="Use DOMPurify for XSS Prevention",
                    description="Sanitize user input with DOMPurify before inserting into DOM",
                    confidence=0.9,
                    reasoning="DOMPurify is the industry standard for XSS prevention in JavaScript",
                    code_snippet="""
// Bad
element.innerHTML = userInput;

// Good
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
""",
                    content={
                        'approach': 'input_sanitization',
                        'library': 'dompurify',
                        'pattern': 'sanitize_before_render',
                    },
                    references=[
                        'DOMPurify GitHub',
                        'OWASP XSS Prevention',
                    ],
                    priority=9,
                )
                recommendations.append(rec)
        
        return recommendations
    
    def _generate_security_recommendations(
        self,
        context: RecommendationContext,
    ) -> List[Recommendation]:
        """Generate security best practice recommendations."""
        recommendations = []
        
        # Framework-specific recommendations
        if context.framework:
            if 'django' in context.framework.lower():
                rec = Recommendation(
                    type=RecommendationType.SECURITY_BEST_PRACTICE,
                    title="Enable Django Security Middleware",
                    description="Ensure all Django security middleware is enabled for defense in depth",
                    confidence=0.85,
                    reasoning="Django security middleware provides multiple layers of protection",
                    content={
                        'middleware': [
                            'SecurityMiddleware',
                            'CsrfViewMiddleware',
                            'XFrameOptionsMiddleware',
                        ],
                        'settings': {
                            'SECURE_SSL_REDIRECT': True,
                            'SECURE_HSTS_SECONDS': 31536000,
                            'SECURE_CONTENT_TYPE_NOSNIFF': True,
                        },
                    },
                    references=[
                        'Django Security Documentation',
                        'OWASP Django Security',
                    ],
                    priority=7,
                )
                recommendations.append(rec)
        
        return recommendations
    
    def _generate_similar_case_recommendations(
        self,
        context: RecommendationContext,
    ) -> List[Recommendation]:
        """Generate recommendations based on similar cases."""
        recommendations = []
        
        # Query knowledge graph for similar vulnerabilities
        if self.knowledge_graph:
            similar_vulns = self.knowledge_graph.find_similar_vulnerabilities(
                context.vulnerability_type,
                limit=3,
            )
            
            if similar_vulns:
                rec = Recommendation(
                    type=RecommendationType.SIMILAR_VULNERABILITY,
                    title=f"Similar Cases Found: {len(similar_vulns)} related vulnerabilities",
                    description="Review these similar cases for validation and remediation insights",
                    confidence=0.75,
                    reasoning="Learning from similar cases improves validation accuracy by 30%",
                    content={
                        'similar_cases': similar_vulns,
                    },
                    similar_cases=[v['node_id'] for v in similar_vulns],
                    priority=6,
                )
                recommendations.append(rec)
        
        return recommendations
    
    def record_feedback(self, feedback: RecommendationFeedback) -> None:
        """
        Record feedback on a recommendation.
        
        Args:
            feedback: Feedback to record
        """
        self.feedback_history.append(feedback)
        
        # Update statistics
        if feedback.feedback_type == FeedbackType.ACCEPTED:
            self.stats['accepted_recommendations'] += 1
        elif feedback.feedback_type == FeedbackType.REJECTED:
            self.stats['rejected_recommendations'] += 1
        
        # Update recommendation
        for rec in self.recommendations_history:
            if rec.recommendation_id == feedback.recommendation_id:
                rec.feedback = feedback
                if feedback.feedback_type == FeedbackType.ACCEPTED:
                    rec.applied = True
                break
        
        # Send feedback to learning system
        if self.learning_system:
            self.learning_system.process_feedback(feedback)
        
        logger.info(f"Recorded feedback: {feedback.feedback_type.value} for {feedback.recommendation_id}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get recommendation engine statistics."""
        total = self.stats['total_recommendations']
        accepted = self.stats['accepted_recommendations']
        rejected = self.stats['rejected_recommendations']
        
        acceptance_rate = (accepted / total * 100) if total > 0 else 0
        rejection_rate = (rejected / total * 100) if total > 0 else 0
        
        # Calculate average confidence
        if self.recommendations_history:
            avg_confidence = sum(r.confidence for r in self.recommendations_history) / len(self.recommendations_history)
        else:
            avg_confidence = 0.0
        
        return {
            'total_recommendations': total,
            'accepted_recommendations': accepted,
            'rejected_recommendations': rejected,
            'acceptance_rate': round(acceptance_rate, 2),
            'rejection_rate': round(rejection_rate, 2),
            'average_confidence': round(avg_confidence, 2),
            'total_feedback': len(self.feedback_history),
        }

