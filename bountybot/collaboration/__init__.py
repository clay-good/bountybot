"""
BountyBot Collaborative Workflow & Team Coordination System.

This module provides comprehensive team collaboration features including:
- Workflow orchestration with state machines
- Task assignments and approval chains
- Real-time comments and @mentions
- Activity feeds and notifications
- SLA tracking and automated escalation

Example:
    >>> from bountybot.collaboration import WorkflowEngine, CollaborationManager, SLAManager
    >>> 
    >>> # Create workflow
    >>> engine = WorkflowEngine()
    >>> workflow = engine.create_workflow("security_review", report_id="report-123")
    >>> 
    >>> # Assign task
    >>> task = engine.assign_task(workflow.workflow_id, "analyst@acme.com", "Review vulnerability")
    >>> 
    >>> # Add comment
    >>> manager = CollaborationManager()
    >>> comment = manager.add_comment(report_id="report-123", user_id="analyst@acme.com", 
    ...                                content="This looks like a critical SQL injection")
    >>> 
    >>> # Track SLA
    >>> sla_manager = SLAManager()
    >>> sla = sla_manager.create_sla(report_id="report-123", target_hours=24)
"""

from bountybot.collaboration.models import (
    # Workflow models
    WorkflowState,
    WorkflowTransition,
    WorkflowDefinition,
    WorkflowInstance,
    WorkflowTask,
    TaskStatus,
    TaskPriority,
    ApprovalStatus,
    
    # Collaboration models
    Comment,
    Mention,
    ActivityType,
    Activity,
    Notification,
    NotificationType,
    NotificationStatus,
    
    # SLA models
    SLA,
    SLAStatus,
    SLABreach,
    EscalationLevel,
    EscalationRule,
)

from bountybot.collaboration.workflow_engine import (
    WorkflowEngine,
    WorkflowExecutor,
    StateTransitionError,
)

from bountybot.collaboration.collaboration_manager import (
    CollaborationManager,
    MentionParser,
)

from bountybot.collaboration.activity_feed import (
    ActivityFeedManager,
    ActivityFilter,
)

from bountybot.collaboration.sla_manager import (
    SLAManager,
    SLAMonitor,
    EscalationEngine,
)

__all__ = [
    # Workflow models
    'WorkflowState',
    'WorkflowTransition',
    'WorkflowDefinition',
    'WorkflowInstance',
    'WorkflowTask',
    'TaskStatus',
    'TaskPriority',
    'ApprovalStatus',
    
    # Collaboration models
    'Comment',
    'Mention',
    'ActivityType',
    'Activity',
    'Notification',
    'NotificationType',
    'NotificationStatus',
    
    # SLA models
    'SLA',
    'SLAStatus',
    'SLABreach',
    'EscalationLevel',
    'EscalationRule',
    
    # Workflow engine
    'WorkflowEngine',
    'WorkflowExecutor',
    'StateTransitionError',
    
    # Collaboration
    'CollaborationManager',
    'MentionParser',
    
    # Activity feed
    'ActivityFeedManager',
    'ActivityFilter',
    
    # SLA management
    'SLAManager',
    'SLAMonitor',
    'EscalationEngine',
]

__version__ = '2.13.0'

