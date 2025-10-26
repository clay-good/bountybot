"""
Smart Automation - Automatically apply learned patterns and recommendations.
"""

import logging
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from bountybot.recommendations.models import (
    Recommendation,
    RecommendationType,
    RecommendationContext,
)


logger = logging.getLogger(__name__)


class AutomationTrigger(Enum):
    """Triggers for automation rules."""
    VALIDATION_START = "validation_start"
    HIGH_CONFIDENCE_PATTERN = "high_confidence_pattern"
    SIMILAR_CASE_FOUND = "similar_case_found"
    THRESHOLD_MET = "threshold_met"
    MANUAL_TRIGGER = "manual_trigger"


class AutomationAction(Enum):
    """Actions that can be automated."""
    APPLY_VALIDATION_STRATEGY = "apply_validation_strategy"
    APPLY_REMEDIATION = "apply_remediation"
    ADJUST_PRIORITY = "adjust_priority"
    SKIP_STAGE = "skip_stage"
    ADD_TAGS = "add_tags"
    NOTIFY_TEAM = "notify_team"


@dataclass
class AutomationRule:
    """A rule for smart automation."""
    rule_id: str
    name: str
    description: str
    
    # Trigger conditions
    trigger: AutomationTrigger
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Action
    action: AutomationAction = AutomationAction.APPLY_VALIDATION_STRATEGY
    action_params: Dict[str, Any] = field(default_factory=dict)
    
    # Configuration
    enabled: bool = True
    confidence_threshold: float = 0.8
    require_approval: bool = False
    
    # Statistics
    execution_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_executed: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'trigger': self.trigger.value,
            'conditions': self.conditions,
            'action': self.action.value,
            'action_params': self.action_params,
            'enabled': self.enabled,
            'confidence_threshold': self.confidence_threshold,
            'require_approval': self.require_approval,
            'execution_count': self.execution_count,
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'created_at': self.created_at.isoformat(),
            'last_executed': self.last_executed.isoformat() if self.last_executed else None,
        }


class SmartAutomation:
    """
    Smart automation system that automatically applies learned patterns
    and recommendations based on rules.
    """
    
    def __init__(
        self,
        recommendation_engine=None,
        learning_system=None,
        approval_callback: Optional[Callable] = None,
    ):
        """
        Initialize smart automation.
        
        Args:
            recommendation_engine: Optional recommendation engine
            learning_system: Optional learning system
            approval_callback: Optional callback for approval requests
        """
        self.recommendation_engine = recommendation_engine
        self.learning_system = learning_system
        self.approval_callback = approval_callback
        
        # Automation rules
        self.rules: Dict[str, AutomationRule] = {}
        
        # Execution history
        self.execution_history: List[Dict[str, Any]] = []
        
        # Statistics
        self.stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'pending_approvals': 0,
        }
    
    def add_rule(self, rule: AutomationRule) -> str:
        """
        Add an automation rule.
        
        Args:
            rule: Rule to add
            
        Returns:
            Rule ID
        """
        self.rules[rule.rule_id] = rule
        logger.info(f"Added automation rule: {rule.name}")
        return rule.rule_id
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove an automation rule.
        
        Args:
            rule_id: ID of rule to remove
            
        Returns:
            True if removed, False if not found
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Removed automation rule: {rule_id}")
            return True
        return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            return True
        return False
    
    def evaluate_rules(
        self,
        trigger: AutomationTrigger,
        context: RecommendationContext,
        recommendations: Optional[List[Recommendation]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Evaluate automation rules for a given trigger and context.
        
        Args:
            trigger: Trigger event
            context: Validation context
            recommendations: Optional list of recommendations
            
        Returns:
            List of actions to execute
        """
        actions = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            if rule.trigger != trigger:
                continue
            
            # Check conditions
            if not self._check_conditions(rule, context, recommendations):
                continue
            
            # Check if approval is required
            if rule.require_approval:
                if self.approval_callback:
                    approved = self.approval_callback(rule, context)
                    if not approved:
                        self.stats['pending_approvals'] += 1
                        continue
                else:
                    # Skip if approval required but no callback
                    continue
            
            # Add action to execute
            actions.append({
                'rule_id': rule.rule_id,
                'action': rule.action,
                'action_params': rule.action_params,
                'confidence': self._calculate_action_confidence(rule, recommendations),
            })
        
        return actions
    
    def _check_conditions(
        self,
        rule: AutomationRule,
        context: RecommendationContext,
        recommendations: Optional[List[Recommendation]],
    ) -> bool:
        """Check if rule conditions are met."""
        conditions = rule.conditions
        
        # Check vulnerability type
        if 'vulnerability_type' in conditions:
            if context.vulnerability_type != conditions['vulnerability_type']:
                return False
        
        # Check severity
        if 'severity' in conditions:
            if context.severity != conditions['severity']:
                return False
        
        # Check language
        if 'language' in conditions:
            if context.language != conditions['language']:
                return False
        
        # Check recommendation confidence
        if recommendations and 'min_recommendation_confidence' in conditions:
            min_conf = conditions['min_recommendation_confidence']
            if not any(r.confidence >= min_conf for r in recommendations):
                return False
        
        return True
    
    def _calculate_action_confidence(
        self,
        rule: AutomationRule,
        recommendations: Optional[List[Recommendation]],
    ) -> float:
        """Calculate confidence for executing the action."""
        # Base confidence from rule
        confidence = rule.confidence_threshold
        
        # Adjust based on rule success rate
        if rule.execution_count > 0:
            success_rate = rule.success_count / rule.execution_count
            confidence = (confidence + success_rate) / 2
        
        # Adjust based on recommendations
        if recommendations:
            avg_rec_confidence = sum(r.confidence for r in recommendations) / len(recommendations)
            confidence = (confidence + avg_rec_confidence) / 2
        
        return min(1.0, confidence)
    
    def execute_action(
        self,
        action: Dict[str, Any],
        context: RecommendationContext,
    ) -> Dict[str, Any]:
        """
        Execute an automation action.
        
        Args:
            action: Action to execute
            context: Validation context
            
        Returns:
            Execution result
        """
        rule_id = action['rule_id']
        rule = self.rules.get(rule_id)
        
        if not rule:
            return {
                'success': False,
                'error': f"Rule {rule_id} not found",
            }
        
        try:
            # Execute action based on type
            action_type = action['action']
            action_params = action['action_params']
            
            if action_type == AutomationAction.APPLY_VALIDATION_STRATEGY:
                result = self._apply_validation_strategy(action_params, context)
            
            elif action_type == AutomationAction.APPLY_REMEDIATION:
                result = self._apply_remediation(action_params, context)
            
            elif action_type == AutomationAction.ADJUST_PRIORITY:
                result = self._adjust_priority(action_params, context)
            
            elif action_type == AutomationAction.ADD_TAGS:
                result = self._add_tags(action_params, context)
            
            else:
                result = {
                    'success': False,
                    'error': f"Unknown action type: {action_type}",
                }
            
            # Update rule statistics
            rule.execution_count += 1
            rule.last_executed = datetime.utcnow()
            
            if result.get('success'):
                rule.success_count += 1
                self.stats['successful_executions'] += 1
            else:
                rule.failure_count += 1
                self.stats['failed_executions'] += 1
            
            self.stats['total_executions'] += 1
            
            # Record execution
            self.execution_history.append({
                'rule_id': rule_id,
                'action': action_type.value if isinstance(action_type, AutomationAction) else action_type,
                'context': context.vulnerability_type,
                'result': result,
                'timestamp': datetime.utcnow().isoformat(),
            })
            
            return result
        
        except Exception as e:
            logger.error(f"Error executing action: {e}")
            rule.failure_count += 1
            self.stats['failed_executions'] += 1
            
            return {
                'success': False,
                'error': str(e),
            }
    
    def _apply_validation_strategy(
        self,
        params: Dict[str, Any],
        context: RecommendationContext,
    ) -> Dict[str, Any]:
        """Apply a validation strategy."""
        strategy = params.get('strategy')
        logger.info(f"Applying validation strategy: {strategy}")
        
        return {
            'success': True,
            'strategy_applied': strategy,
            'message': f"Applied {strategy} validation strategy",
        }
    
    def _apply_remediation(
        self,
        params: Dict[str, Any],
        context: RecommendationContext,
    ) -> Dict[str, Any]:
        """Apply a remediation."""
        approach = params.get('approach')
        logger.info(f"Applying remediation: {approach}")
        
        return {
            'success': True,
            'remediation_applied': approach,
            'message': f"Applied {approach} remediation",
        }
    
    def _adjust_priority(
        self,
        params: Dict[str, Any],
        context: RecommendationContext,
    ) -> Dict[str, Any]:
        """Adjust priority."""
        adjustment = params.get('adjustment', 0)
        logger.info(f"Adjusting priority by {adjustment}")
        
        return {
            'success': True,
            'priority_adjustment': adjustment,
            'message': f"Adjusted priority by {adjustment}",
        }
    
    def _add_tags(
        self,
        params: Dict[str, Any],
        context: RecommendationContext,
    ) -> Dict[str, Any]:
        """Add tags."""
        tags = params.get('tags', [])
        logger.info(f"Adding tags: {tags}")
        
        return {
            'success': True,
            'tags_added': tags,
            'message': f"Added {len(tags)} tags",
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get automation statistics."""
        return {
            **self.stats,
            'total_rules': len(self.rules),
            'enabled_rules': sum(1 for r in self.rules.values() if r.enabled),
            'success_rate': (
                self.stats['successful_executions'] / self.stats['total_executions'] * 100
                if self.stats['total_executions'] > 0 else 0
            ),
        }

